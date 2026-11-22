/*
 * res_ext.c - KernelEx-NG: resources of files loaded with LOAD_LIBRARY_AS_DATAFILE / AS_IMAGE_RESOURCE.
 *
 * Build 85. Build 84 log: Chromium's icon reader (utility process "chrome.mojom.UtilReadIcon", run for every
 * download to show its icon) crashed inside Windows 98's KERNEL32 (KERNEL32.DLL+e1e1, reading ffffffff) - twice,
 * both times called from CHROME.DLL+6f01853 = EnumResourceNamesW(module, RT_GROUP_ICON, ...) on a module handle
 * b5423001 (a file loaded "as data": base address + 1). Its next call is LoadImageW(that module, name, IMAGE_ICON).
 * Windows 98's own resource code does not handle such a module safely, so for module handles with the low bits
 * set (data-file handles) the resource directory is read here, straight from the PE file:
 *   EnumResourceNamesW/A, FindResourceW/A, FindResourceExW/A, LoadResource, SizeofResource, LockResource,
 *   and LoadImageW/A for IMAGE_ICON / IMAGE_CURSOR (gdiguard_ext.c calls kex_res_load_image).
 * Every other module handle goes to the previous implementation unchanged.
 * The mapping may be the raw file (NT's layout for data files) or laid out like a loaded image; both are tried
 * and the one whose resource directory is consistent is used (noted once per module in KEXCRASH).
 */
#include "kexnt_common.h"

FARPROC kex_prev_impl(const char *dll, const char *name);   /* gdiguard_ext.c */
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

typedef struct {
    BYTE *base; DWORD span;          /* mapping start and readable size */
    DWORD rva, rsize;                /* resource directory */
    IMAGE_SECTION_HEADER *sec; int nsec; DWORD hdrsize;
    int flat;                        /* 1 raw file layout, 0 image layout */
    BYTE *root;
} RES;

/* data-file spans seen (for LockResource) */
static struct { BYTE *base; DWORD span; } g_known[32];
static volatile LONG g_nknown;

static BOOL is_datafile(HMODULE h) { return ((ULONG_PTR)h & 3) != 0 && (ULONG_PTR)h > 0x10000; }

static DWORD span_of(BYTE *b)
{
    MEMORY_BASIC_INFORMATION m; BYTE *p = b; DWORD n = 0;
    while (VirtualQuery(p, &m, sizeof(m)) >= sizeof(m) && m.AllocationBase == (PVOID)b && m.State == MEM_COMMIT && m.RegionSize) {
        n += (DWORD)m.RegionSize; p = (BYTE *)m.BaseAddress + m.RegionSize;
        if (n > 0x7FF00000UL) break;
    }
    if (!n && VirtualQuery(b, &m, sizeof(m)) >= sizeof(m) && m.State == MEM_COMMIT) n = (DWORD)((BYTE *)m.BaseAddress + m.RegionSize - b);
    return n;
}

static BYTE *at(const RES *r, DWORD rva, DWORD n)
{
    DWORD off = rva; int i;
    if (r->flat && rva >= r->hdrsize) {
        off = 0xFFFFFFFF;
        for (i = 0; i < r->nsec; i++) {
            DWORD va = r->sec[i].VirtualAddress, sz = r->sec[i].SizeOfRawData;
            if (r->sec[i].Misc.VirtualSize > sz) sz = r->sec[i].Misc.VirtualSize;
            if (rva >= va && rva < va + sz) { off = rva - va + r->sec[i].PointerToRawData; break; }
        }
    }
    if (off == 0xFFFFFFFF || off > r->span || n > r->span - off) return NULL;
    return r->base + off;
}

/* a resource directory at d (offset within the resource section) looks right */
static BOOL dir_ok(const RES *r, DWORD d)
{
    IMAGE_RESOURCE_DIRECTORY *dir; DWORD cnt;
    if (d > r->rsize || r->rsize - d < sizeof(*dir)) return FALSE;
    dir = (IMAGE_RESOURCE_DIRECTORY *)(r->root + d);
    cnt = (DWORD)dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    if (cnt > 4096 || (r->rsize - d - sizeof(*dir)) / sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) < cnt) return FALSE;
    return TRUE;
}

static BOOL try_layout(RES *r, int flat)
{
    IMAGE_RESOURCE_DIRECTORY *dir; IMAGE_RESOURCE_DIRECTORY_ENTRY *e; DWORD i, cnt;
    r->flat = flat;
    if (!(r->root = at(r, r->rva, r->rsize))) {
        DWORD avail;                         /* the last section may be shorter in the file than rsize says */
        BYTE *p = at(r, r->rva, 16);
        if (!p) return FALSE;
        avail = (DWORD)(r->base + r->span - p);
        r->rsize = avail; r->root = p;
    }
    if (!dir_ok(r, 0)) return FALSE;
    dir = (IMAGE_RESOURCE_DIRECTORY *)r->root;
    cnt = (DWORD)dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    e = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    for (i = 0; i < cnt; i++) {                    /* the type level: every entry is a sub-directory */
        if (!(e[i].OffsetToData & 0x80000000UL) || !dir_ok(r, e[i].OffsetToData & 0x7FFFFFFFUL)) return FALSE;
    }
    return TRUE;
}

static BOOL res_open(HMODULE h, RES *r)
{
    IMAGE_DOS_HEADER *dos; IMAGE_NT_HEADERS32 *nt; BYTE *opt; WORD magic; DWORD ndir, lfa; IMAGE_DATA_DIRECTORY *dd;
    ZeroMemory(r, sizeof(*r));
    r->base = (BYTE *)((ULONG_PTR)h & ~(ULONG_PTR)3);
    if (!(r->span = span_of(r->base)) || r->span < 0x200) return FALSE;
    dos = (IMAGE_DOS_HEADER *)r->base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    lfa = (DWORD)dos->e_lfanew;
    if (lfa > r->span - sizeof(IMAGE_NT_HEADERS32)) return FALSE;
    nt = (IMAGE_NT_HEADERS32 *)(r->base + lfa);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    opt = (BYTE *)&nt->OptionalHeader;
    magic = *(WORD *)opt;
    if (magic == 0x10B) { ndir = *(DWORD *)(opt + 92); dd = (IMAGE_DATA_DIRECTORY *)(opt + 96); r->hdrsize = *(DWORD *)(opt + 60); }
    else if (magic == 0x20B) { ndir = *(DWORD *)(opt + 108); dd = (IMAGE_DATA_DIRECTORY *)(opt + 112); r->hdrsize = *(DWORD *)(opt + 60); }
    else return FALSE;
    if (ndir <= IMAGE_DIRECTORY_ENTRY_RESOURCE) return FALSE;
    r->rva = dd[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
    r->rsize = dd[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
    if (!r->rva || !r->rsize) return FALSE;
    r->sec = (IMAGE_SECTION_HEADER *)(opt + nt->FileHeader.SizeOfOptionalHeader);
    r->nsec = nt->FileHeader.NumberOfSections;
    if ((BYTE *)(r->sec + r->nsec) > r->base + r->span || r->nsec > 96) return FALSE;
    {
        DWORD keep = r->rsize;
        if (!try_layout(r, 1)) { r->rsize = keep; if (!try_layout(r, 0)) return FALSE; }
    }
    {   int i, n = g_nknown, seen = 0;
        for (i = 0; i < n && i < 32; i++) if (g_known[i].base == r->base) { g_known[i].span = r->span; seen = 1; break; }
        if (!seen) {
            i = InterlockedIncrement(&g_nknown) - 1;
            if (i < 32) { g_known[i].span = r->span; g_known[i].base = r->base; }
            else { InterlockedDecrement(&g_nknown); i = (int)((ULONG_PTR)r->base >> 16) & 31; g_known[i].span = r->span; g_known[i].base = r->base; }
            kex_crashnote("resources of a data-file module read by kexnt (handle, layout 1 file / 0 image, mapped size, resource size)",
                          (DWORD)(ULONG_PTR)h, (DWORD)r->flat, r->span, r->rsize);
        }
    }
    return TRUE;
}

static WCHAR up(WCHAR c) { return (c >= 'a' && c <= 'z') ? (WCHAR)(c - 32) : c; }

/* id: integer resource, "#123", or a name; returns the entry or NULL */
static IMAGE_RESOURCE_DIRECTORY_ENTRY *dir_find(const RES *r, DWORD d, LPCWSTR id)
{
    IMAGE_RESOURCE_DIRECTORY *dir = (IMAGE_RESOURCE_DIRECTORY *)(r->root + d);
    IMAGE_RESOURCE_DIRECTORY_ENTRY *e = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    DWORD i, nn = dir->NumberOfNamedEntries, cnt = nn + dir->NumberOfIdEntries, num = 0;
    BOOL isnum = IS_INTRESOURCE(id);
    if (isnum) num = (DWORD)(ULONG_PTR)id;
    else if (id[0] == '#') {
        LPCWSTR p = id + 1; isnum = TRUE;
        while (*p >= '0' && *p <= '9') num = num * 10 + (DWORD)(*p++ - '0');
        if (*p) return NULL;
    }
    for (i = 0; i < cnt; i++) {
        if (isnum) { if (!(e[i].Name & 0x80000000UL) && (e[i].Name & 0xFFFF) == num) return &e[i]; }
        else if (e[i].Name & 0x80000000UL) {
            DWORD so = e[i].Name & 0x7FFFFFFFUL; WORD len; const WCHAR *s; DWORD k;
            if (so > r->rsize - 2) continue;
            len = *(WORD *)(r->root + so); s = (const WCHAR *)(r->root + so + 2);
            if (so + 2 + (DWORD)len * 2 > r->rsize) continue;
            for (k = 0; k < len && id[k] && up(id[k]) == up(s[k]); k++) ;
            if (k == len && !id[k]) return &e[i];
        }
    }
    return NULL;
}

static IMAGE_RESOURCE_DATA_ENTRY *find_w(const RES *r, LPCWSTR type, LPCWSTR name, WORD lang)
{
    IMAGE_RESOURCE_DIRECTORY_ENTRY *t, *n, *l = NULL; IMAGE_RESOURCE_DIRECTORY *ld; DWORD i, cnt, off;
    if (!(t = dir_find(r, 0, type)) || !(t->OffsetToData & 0x80000000UL)) { SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND); return NULL; }
    if (!(n = dir_find(r, t->OffsetToData & 0x7FFFFFFFUL, name)) || !(n->OffsetToData & 0x80000000UL) ||
        !dir_ok(r, n->OffsetToData & 0x7FFFFFFFUL)) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return NULL; }
    ld = (IMAGE_RESOURCE_DIRECTORY *)(r->root + (n->OffsetToData & 0x7FFFFFFFUL));
    cnt = (DWORD)ld->NumberOfNamedEntries + ld->NumberOfIdEntries;
    if (!cnt) { SetLastError(ERROR_RESOURCE_LANG_NOT_FOUND); return NULL; }
    {   IMAGE_RESOURCE_DIRECTORY_ENTRY *e = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(ld + 1);
        for (i = 0; i < cnt && !l; i++) if ((e[i].Name & 0xFFFF) == lang) l = &e[i];
        for (i = 0; i < cnt && !l; i++) if (PRIMARYLANGID(e[i].Name & 0xFFFF) == PRIMARYLANGID(lang)) l = &e[i];
        for (i = 0; i < cnt && !l; i++) if ((e[i].Name & 0xFFFF) == 0x409) l = &e[i];
        if (!l) l = &e[0];
    }
    off = l->OffsetToData;
    if (off & 0x80000000UL || off > r->rsize - sizeof(IMAGE_RESOURCE_DATA_ENTRY)) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return NULL; }
    return (IMAGE_RESOURCE_DATA_ENTRY *)(r->root + off);
}

/* A-string (or integer) id -> W; "buf" holds the converted text */
static LPCWSTR a2w(LPCSTR s, WCHAR *buf, int n)
{
    if (IS_INTRESOURCE(s)) return (LPCWSTR)s;
    if (!MultiByteToWideChar(CP_ACP, 0, s, -1, buf, n)) buf[0] = 0;
    return buf;
}

static BYTE *entry_data(const RES *r, IMAGE_RESOURCE_DATA_ENTRY *d) { return at(r, d->OffsetToData, d->Size); }

/* ---------------- exports ---------------- */
typedef HRSRC (WINAPI *T_FRXW)(HMODULE, LPCWSTR, LPCWSTR, WORD);
typedef HRSRC (WINAPI *T_FRXA)(HMODULE, LPCSTR, LPCSTR, WORD);
typedef HRSRC (WINAPI *T_FRW)(HMODULE, LPCWSTR, LPCWSTR);
typedef HRSRC (WINAPI *T_FRA)(HMODULE, LPCSTR, LPCSTR);

HRSRC KEXAPI kex_FindResourceExW(HMODULE h, LPCWSTR type, LPCWSTR name, WORD lang)
{
    static T_FRXW prev; RES r;
    if (is_datafile(h) && res_open(h, &r)) return (HRSRC)find_w(&r, type, name, lang);
    if (!prev) prev = (T_FRXW)(void *)kex_prev_impl("KERNEL32.DLL", "FindResourceExW");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return prev(h, type, name, lang);
}
HRSRC KEXAPI kex_FindResourceW(HMODULE h, LPCWSTR name, LPCWSTR type)
{
    static T_FRW prev; RES r;
    if (is_datafile(h) && res_open(h, &r)) return (HRSRC)find_w(&r, type, name, 0);
    if (!prev) prev = (T_FRW)(void *)kex_prev_impl("KERNEL32.DLL", "FindResourceW");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return prev(h, name, type);
}
HRSRC KEXAPI kex_FindResourceExA(HMODULE h, LPCSTR type, LPCSTR name, WORD lang)
{
    static T_FRXA prev; RES r;
    if (is_datafile(h) && res_open(h, &r)) { WCHAR tb[128], nb[128]; return (HRSRC)find_w(&r, a2w(type, tb, 128), a2w(name, nb, 128), lang); }
    if (!prev) prev = (T_FRXA)(void *)kex_prev_impl("KERNEL32.DLL", "FindResourceExA");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return prev(h, type, name, lang);
}
HRSRC KEXAPI kex_FindResourceA(HMODULE h, LPCSTR name, LPCSTR type)
{
    static T_FRA prev; RES r;
    if (is_datafile(h) && res_open(h, &r)) { WCHAR tb[128], nb[128]; return (HRSRC)find_w(&r, a2w(type, tb, 128), a2w(name, nb, 128), 0); }
    if (!prev) prev = (T_FRA)(void *)kex_prev_impl("KERNEL32.DLL", "FindResourceA");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return prev(h, name, type);
}

static BOOL rsrc_in(const RES *r, HRSRC x)
{
    return (BYTE *)x >= r->root && (BYTE *)x + sizeof(IMAGE_RESOURCE_DATA_ENTRY) <= r->root + r->rsize;
}

typedef HGLOBAL (WINAPI *T_LR)(HMODULE, HRSRC);
HGLOBAL KEXAPI kex_LoadResource(HMODULE h, HRSRC x)
{
    static T_LR prev; RES r;
    if (is_datafile(h) && res_open(h, &r)) {
        if (!x || !rsrc_in(&r, x)) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return NULL; }
        return (HGLOBAL)entry_data(&r, (IMAGE_RESOURCE_DATA_ENTRY *)x);
    }
    if (!prev) prev = (T_LR)(void *)kex_prev_impl("KERNEL32.DLL", "LoadResource");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return prev(h, x);
}
typedef DWORD (WINAPI *T_SR)(HMODULE, HRSRC);
DWORD KEXAPI kex_SizeofResource(HMODULE h, HRSRC x)
{
    static T_SR prev; RES r;
    if (is_datafile(h) && res_open(h, &r)) {
        if (!x || !rsrc_in(&r, x)) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return 0; }
        return ((IMAGE_RESOURCE_DATA_ENTRY *)x)->Size;
    }
    if (!prev) prev = (T_SR)(void *)kex_prev_impl("KERNEL32.DLL", "SizeofResource");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    return prev(h, x);
}
typedef LPVOID (WINAPI *T_LKR)(HGLOBAL);
LPVOID KEXAPI kex_LockResource(HGLOBAL g)
{
    static T_LKR prev; int i, n = g_nknown;
    for (i = 0; i < n && i < 32; i++)
        if (g_known[i].base && (BYTE *)g >= g_known[i].base && (BYTE *)g < g_known[i].base + g_known[i].span) return (LPVOID)g;
    if (!prev) prev = (T_LKR)(void *)kex_prev_impl("KERNEL32.DLL", "LockResource");
    if (!prev) return (LPVOID)g;
    return prev(g);
}

typedef BOOL (CALLBACK *ENW)(HMODULE, LPCWSTR, LPWSTR, LONG_PTR);
typedef BOOL (CALLBACK *ENA)(HMODULE, LPCSTR, LPSTR, LONG_PTR);
static BOOL enum_names(HMODULE h, const RES *r, LPCWSTR type, void *cb, LONG_PTR lp, BOOL wide)
{
    IMAGE_RESOURCE_DIRECTORY_ENTRY *t, *e; IMAGE_RESOURCE_DIRECTORY *nd; DWORD i, cnt, d;
    if (!cb) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!(t = dir_find(r, 0, type)) || !(t->OffsetToData & 0x80000000UL)) { SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND); return FALSE; }
    d = t->OffsetToData & 0x7FFFFFFFUL;
    nd = (IMAGE_RESOURCE_DIRECTORY *)(r->root + d);
    cnt = (DWORD)nd->NumberOfNamedEntries + nd->NumberOfIdEntries;
    e = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(nd + 1);
    for (i = 0; i < cnt; i++) {
        WCHAR wn[260]; char an[520]; LPWSTR nw; LPSTR na; char at_[128]; LPCSTR ta = (LPCSTR)type;
        if (e[i].Name & 0x80000000UL) {
            DWORD so = e[i].Name & 0x7FFFFFFFUL; WORD len; DWORD k;
            if (so > r->rsize - 2) continue;
            len = *(WORD *)(r->root + so);
            if (so + 2 + (DWORD)len * 2 > r->rsize) continue;
            if (len > 259) len = 259;
            for (k = 0; k < len; k++) wn[k] = ((const WCHAR *)(r->root + so + 2))[k];
            wn[len] = 0; nw = wn;
        } else nw = (LPWSTR)(ULONG_PTR)(e[i].Name & 0xFFFF);
        if (wide) { if (!((ENW)cb)(h, type, nw, lp)) return TRUE; }
        else {
            if (IS_INTRESOURCE(nw)) na = (LPSTR)nw;
            else { if (!WideCharToMultiByte(CP_ACP, 0, nw, -1, an, sizeof(an), NULL, NULL)) an[0] = 0; na = an; }
            if (!IS_INTRESOURCE(type)) { if (!WideCharToMultiByte(CP_ACP, 0, type, -1, at_, sizeof(at_), NULL, NULL)) at_[0] = 0; ta = at_; }
            if (!((ENA)cb)(h, ta, na, lp)) return TRUE;
        }
    }
    return TRUE;
}

typedef BOOL (WINAPI *T_ERNW)(HMODULE, LPCWSTR, ENW, LONG_PTR);
typedef BOOL (WINAPI *T_ERNA)(HMODULE, LPCSTR, ENA, LONG_PTR);
BOOL KEXAPI kex_EnumResourceNamesW(HMODULE h, LPCWSTR type, ENW cb, LONG_PTR lp)
{
    static T_ERNW prev; RES r;
    if (is_datafile(h)) {
        if (!res_open(h, &r)) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return FALSE; }
        return enum_names(h, &r, type, (void *)cb, lp, TRUE);
    }
    if (!prev) prev = (T_ERNW)(void *)kex_prev_impl("KERNEL32.DLL", "EnumResourceNamesW");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return prev(h, type, cb, lp);
}
BOOL KEXAPI kex_EnumResourceNamesA(HMODULE h, LPCSTR type, ENA cb, LONG_PTR lp)
{
    static T_ERNA prev; RES r;
    if (is_datafile(h)) {
        WCHAR tb[128];
        if (!res_open(h, &r)) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return FALSE; }
        return enum_names(h, &r, a2w(type, tb, 128), (void *)cb, lp, FALSE);
    }
    if (!prev) prev = (T_ERNA)(void *)kex_prev_impl("KERNEL32.DLL", "EnumResourceNamesA");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return prev(h, type, cb, lp);
}

/* LoadImageW/A(datafile module, name, IMAGE_ICON / IMAGE_CURSOR, cx, cy, flags), from gdiguard_ext.c.
 * Returns 1 and *out when it handled the call, 0 when the guard should pass it on. */
int kex_res_load_image(const DWORD *args, BOOL wide, DWORD *out)
{
    typedef int (WINAPI *T_LID)(PBYTE, BOOL, int, int, UINT);
    typedef HICON (WINAPI *T_CIR)(PBYTE, DWORD, BOOL, DWORD, int, int, UINT);
    typedef int (WINAPI *T_GSM)(int);
    HMODULE h = (HMODULE)(ULONG_PTR)args[0]; UINT type = args[2], fl = args[5]; int cx = (int)args[3], cy = (int)args[4];
    RES r; WCHAR nb[128]; LPCWSTR name; IMAGE_RESOURCE_DATA_ENTRY *g, *one; BYTE *gb, *ib; int id; BOOL icon = type == IMAGE_ICON;
    T_LID lid; T_CIR cir;
    if (!is_datafile(h) || (type != IMAGE_ICON && type != IMAGE_CURSOR)) return 0;
    *out = 0;
    if (!res_open(h, &r)) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return 1; }
    name = wide ? (LPCWSTR)(ULONG_PTR)args[1] : a2w((LPCSTR)(ULONG_PTR)args[1], nb, 128);
    if (!name) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return 1; }
    lid = (T_LID)(void *)kex_sysproc("USER32.DLL", "LookupIconIdFromDirectoryEx");
    cir = (T_CIR)(void *)kex_sysproc("USER32.DLL", "CreateIconFromResourceEx");
    if (!lid || !cir) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 1; }
    if ((!cx || !cy) && (fl & LR_DEFAULTSIZE)) {
        T_GSM gsm = (T_GSM)(void *)kex_sysproc("USER32.DLL", "GetSystemMetrics");
        if (gsm) { if (!cx) cx = gsm(icon ? SM_CXICON : SM_CXCURSOR); if (!cy) cy = gsm(icon ? SM_CYICON : SM_CYCURSOR); }
    }
    if (!(g = find_w(&r, icon ? (LPCWSTR)RT_GROUP_ICON : (LPCWSTR)RT_GROUP_CURSOR, name, 0)) || !(gb = entry_data(&r, g))) return 1;
    id = lid(gb, icon, cx, cy, fl & LR_MONOCHROME);
    if (!id) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return 1; }
    if (!(one = find_w(&r, icon ? (LPCWSTR)RT_ICON : (LPCWSTR)RT_CURSOR, (LPCWSTR)(ULONG_PTR)(WORD)id, 0)) || !(ib = entry_data(&r, one))) return 1;
    *out = (DWORD)(ULONG_PTR)cir(ib, one->Size, icon, 0x00030000, cx, cy, fl & (LR_MONOCHROME | LR_DEFAULTCOLOR));
    {   static LONG n; if (InterlockedIncrement(&n) <= 10)
            kex_crashnote("LoadImage from a data-file module by kexnt (handle, icon id, size cx|cy<<16, result)",
                          (DWORD)(ULONG_PTR)h, (DWORD)id, (DWORD)(cx & 0xFFFF) | ((DWORD)cy << 16), *out); }
    return 1;
}
