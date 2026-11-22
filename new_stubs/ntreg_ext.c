/*
 * ntreg_ext.c - NT native registry API on Windows 98 SE (KernelEx-NG).
 *
 * Chromium's chrome_elf.dll (and chrome.dll) talk to the registry through the native
 * NT calls: NtCreateKey / NtOpenKeyEx / NtQueryValueKey / NtSetValueKey / NtDeleteKey /
 * NtClose with object paths such as  \Registry\Machine\SOFTWARE\...  and
 * \Registry\User\<sid>\...  (prefix from RtlFormatCurrentUserKeyPath).
 *
 * Win98 has no object manager, so we translate:
 *   \Registry\Machine\...        -> HKEY_LOCAL_MACHINE\...
 *   \Registry\User\<KEX_CU_SID>  -> HKEY_CURRENT_USER   (the SID we hand out ourselves)
 *   \Registry\User\<other>\...   -> HKEY_USERS\<other>\...
 *   RootDirectory = key handle   -> relative to that key
 * and call Win98's own ANSI registry functions (RegOpenKeyExA ...), converting UTF-16 names
 * and REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ data with the ANSI code page.
 *
 * Key handles are the real Win98 HKEYs (so Reg*W on them keeps working). Every handle we
 * return is remembered in a small table together with its root and path: NtClose uses it to
 * tell keys from kernel objects, and NtDeleteKey needs the path because Win98 deletes by name.
 * Behaviour follows the documented NT semantics (MSDN / WDK headers): NtDeleteKey refuses a
 * key that still has subkeys (Win98's RegDeleteKeyA would delete the whole tree).
 */
#include "kexnt_common.h"
#include <string.h>

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } KUSTR;
typedef struct {                               /* OBJECT_ATTRIBUTES, x86 = 24 bytes */
    ULONG Length; HANDLE RootDirectory; KUSTR *ObjectName; ULONG Attributes;
    PVOID SecurityDescriptor, SecurityQualityOfService;
} KOBJATTR;

#define STATUS_BUFFER_OVERFLOW_K       ((NTSTATUS)0x80000005L)
#define STATUS_OBJECT_NAME_INVALID_K   ((NTSTATUS)0xC0000033L)
#define STATUS_OBJECT_NAME_NOT_FOUND_K ((NTSTATUS)0xC0000034L)
#define STATUS_OBJECT_PATH_NOT_FOUND_K ((NTSTATUS)0xC000003AL)
#define STATUS_ACCESS_DENIED_K2        ((NTSTATUS)0xC0000022L)
#define STATUS_CANNOT_DELETE_K         ((NTSTATUS)0xC0000121L)
#define STATUS_KEY_DELETED_K           ((NTSTATUS)0xC000017CL)
#define STATUS_UNSUCCESSFUL_K          ((NTSTATUS)0xC0000001L)

/* The "SID" our RtlFormatCurrentUserKeyPath reports for the current user (Win98 has none). */
static const WCHAR KEX_CU_SID[] = L"S-1-5-21-0-0-0-1000";

NTSTATUS kex_status_from_win32(DWORD e);       /* chrome_ext.c */

static void *xalloc(SIZE_T n) { return HeapAlloc(GetProcessHeap(), 0, n ? n : 1); }
static void  xfree(void *p)   { if (p) HeapFree(GetProcessHeap(), 0, p); }

/* ---------------------------------------------------------------- handle table */
typedef struct { HKEY h; HKEY root; char *path; BOOL deleted; } KEYENT;   /* path relative to root */
static KEYENT *g_keys;
static LONG    g_nkeys, g_capkeys;
static volatile LONG g_lock;

static void lock(void)   { kex_spin_acquire((volatile LONG *)&g_lock); }
static void unlock(void) { InterlockedExchange((LONG *)&g_lock, 0); }

static BOOL is_predef(HKEY h) { return ((ULONG_PTR)h & 0xFFFFFFF0UL) == 0x80000000UL; }

/* caller holds the lock */
static KEYENT *find_key(HKEY h)
{
    LONG i;
    for (i = 0; i < g_nkeys; i++) if (g_keys[i].h == h) return &g_keys[i];
    return NULL;
}

static BOOL add_key(HKEY h, HKEY root, const char *path)
{
    char *p; size_t n = strlen(path) + 1;
    if (!(p = xalloc(n))) return FALSE;
    memcpy(p, path, n);
    lock();
    if (g_nkeys == g_capkeys) {
        LONG nc = g_capkeys ? g_capkeys * 2 : 32;
        KEYENT *nk = g_keys ? HeapReAlloc(GetProcessHeap(), 0, g_keys, nc * sizeof(KEYENT))
                            : HeapAlloc(GetProcessHeap(), 0, nc * sizeof(KEYENT));
        if (!nk) { unlock(); xfree(p); return FALSE; }
        g_keys = nk; g_capkeys = nc;
    }
    g_keys[g_nkeys].h = h; g_keys[g_nkeys].root = root; g_keys[g_nkeys].path = p; g_keys[g_nkeys].deleted = FALSE;
    g_nkeys++;
    unlock();
    return TRUE;
}

/* Remove h from the table; returns TRUE if it was ours. */
static BOOL remove_key(HKEY h)
{
    KEYENT *e; char *p = NULL;
    lock();
    if ((e = find_key(h)) != NULL) { p = e->path; *e = g_keys[--g_nkeys]; }
    unlock();
    if (!e) return FALSE;
    xfree(p);
    return TRUE;
}

/* Copy of the root/path of a tracked key (path allocated). */
static BOOL key_info(HKEY h, HKEY *root, char **path, BOOL *deleted)
{
    KEYENT *e; BOOL ok = FALSE;
    lock();
    if ((e = find_key(h)) != NULL) {
        size_t n = strlen(e->path) + 1;
        if ((*path = xalloc(n)) != NULL) {
            memcpy(*path, e->path, n); *root = e->root; if (deleted) *deleted = e->deleted; ok = TRUE;
        }
    }
    unlock();
    return ok;
}

static void mark_deleted(HKEY h)
{
    KEYENT *e;
    lock();
    if ((e = find_key(h)) != NULL) e->deleted = TRUE;
    unlock();
}

/* ---------------------------------------------------------------- strings */
static int wlen_ci_prefix(const WCHAR *s, int n, const char *pre)
{
    /* length of pre if s[0..n) starts with pre (ASCII, case-insensitive) followed by '\' or end */
    int i;
    for (i = 0; pre[i]; i++) {
        WCHAR c;
        if (i >= n) return -1;
        c = s[i]; if (c >= 'a' && c <= 'z') c -= 32;
        if (c != (WCHAR)(pre[i] >= 'a' && pre[i] <= 'z' ? pre[i] - 32 : pre[i])) return -1;
    }
    if (i < n && s[i] != '\\') return -1;
    return i;
}

static BOOL wsame_ci(const WCHAR *a, int n, const WCHAR *b)
{
    int i;
    for (i = 0; i < n; i++) {
        WCHAR x = a[i], y = b[i];
        if (!y) return FALSE;
        if (x >= 'a' && x <= 'z') x -= 32;
        if (y >= 'a' && y <= 'z') y -= 32;
        if (x != y) return FALSE;
    }
    return b[n] == 0;
}

/* UTF-16 (counted) -> ANSI, allocated, NUL terminated. */
static char *w2a(const WCHAR *w, int n)
{
    int m; char *a;
    if (n <= 0) { a = xalloc(1); if (a) a[0] = 0; return a; }
    m = WideCharToMultiByte(CP_ACP, 0, w, n, NULL, 0, NULL, NULL);
    if (m <= 0 || !(a = xalloc(m + 1))) return NULL;
    WideCharToMultiByte(CP_ACP, 0, w, n, a, m, NULL, NULL);
    a[m] = 0;
    return a;
}

static char *join_path(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    char *p = xalloc(la + lb + 2);
    if (!p) return NULL;
    memcpy(p, a, la);
    if (la && lb) p[la++] = '\\';
    memcpy(p + la, b, lb + 1);
    return p;
}

/* Strip leading/trailing/doubled backslashes in place. */
static void tidy_path(char *p)
{
    char *s = p, *d = p;
    while (*s == '\\') s++;
    while (*s) {
        if (*s == '\\' && (s[1] == '\\' || s[1] == 0)) { s++; continue; }
        *d++ = *s++;
    }
    *d = 0;
}

/*
 * Resolve OBJECT_ATTRIBUTES to (root predefined key, path relative to it).
 * Returns STATUS_SUCCESS and an allocated *path.
 */
static NTSTATUS resolve(const KOBJATTR *oa, HKEY *root, char **path)
{
    const WCHAR *w; int n; char *rel, *full;
    if (!oa) return STATUS_INVALID_PARAMETER;
    if (oa->ObjectName && oa->ObjectName->Buffer) { w = oa->ObjectName->Buffer; n = oa->ObjectName->Length / 2; }
    else { w = L""; n = 0; }

    if (oa->RootDirectory) {
        HKEY base = (HKEY)oa->RootDirectory; char *bpath; BOOL del = FALSE;
        if (n && w[0] == '\\') return STATUS_OBJECT_PATH_NOT_FOUND_K;      /* NT: must be relative */
        if (is_predef(base)) { *root = base; bpath = NULL; }
        else if (!key_info(base, root, &bpath, &del)) return STATUS_INVALID_HANDLE_K;
        if (del) { xfree(bpath); return STATUS_KEY_DELETED_K; }
        if (!(rel = w2a(w, n))) { xfree(bpath); return STATUS_NO_MEMORY_K; }
        full = join_path(bpath ? bpath : "", rel);
        xfree(bpath); xfree(rel);
        if (!full) return STATUS_NO_MEMORY_K;
        tidy_path(full);
        *path = full;
        return STATUS_SUCCESS;
    }

    {
        int k = wlen_ci_prefix(w, n, "\\REGISTRY");
        if (k < 0) return STATUS_OBJECT_PATH_NOT_FOUND_K;
        w += k; n -= k; if (n && *w == '\\') { w++; n--; }
        if ((k = wlen_ci_prefix(w, n, "MACHINE")) >= 0) {
            *root = HKEY_LOCAL_MACHINE;
        } else if ((k = wlen_ci_prefix(w, n, "USER")) >= 0) {
            int j;
            *root = HKEY_USERS;
            w += k; n -= k; if (n && *w == '\\') { w++; n--; }
            for (j = 0; j < n && w[j] != '\\'; j++) ;
            if (j && wsame_ci(w, j, KEX_CU_SID)) { *root = HKEY_CURRENT_USER; k = j; }
            else k = 0;                                   /* keep "<sid>\..." below HKEY_USERS */
        } else return STATUS_OBJECT_PATH_NOT_FOUND_K;
        w += k; n -= k;
    }
    if (!(full = w2a(w, n))) return STATUS_NO_MEMORY_K;
    tidy_path(full);
    *path = full;
    return STATUS_SUCCESS;
}

static NTSTATUS reg_status(LONG e)
{
    switch (e) {
    case ERROR_SUCCESS: return STATUS_SUCCESS;
    case ERROR_FILE_NOT_FOUND: case ERROR_BADKEY: return STATUS_OBJECT_NAME_NOT_FOUND_K;
    case ERROR_PATH_NOT_FOUND: return STATUS_OBJECT_PATH_NOT_FOUND_K;
    case ERROR_ACCESS_DENIED: return STATUS_ACCESS_DENIED_K2;
    case ERROR_INVALID_HANDLE: return STATUS_INVALID_HANDLE_K;
    case ERROR_KEY_DELETED: return STATUS_KEY_DELETED_K;
    case ERROR_MORE_DATA: return STATUS_BUFFER_OVERFLOW_K;
    case ERROR_OUTOFMEMORY: case ERROR_NOT_ENOUGH_MEMORY: return STATUS_NO_MEMORY_K;
    default: return kex_status_from_win32((DWORD)e);
    }
}

static REGSAM clean_sam(ACCESS_MASK a)
{
    a &= ~(KEY_WOW64_32KEY | KEY_WOW64_64KEY);
    if (a & (MAXIMUM_ALLOWED | GENERIC_ALL)) return KEY_ALL_ACCESS;
    return a ? a : KEY_READ;
}

/* ---------------------------------------------------------------- keys */
NTSTATUS KEXAPI kex_NtOpenKeyEx(PHANDLE out, ACCESS_MASK access, KOBJATTR *oa, ULONG options)
{
    HKEY root, h; char *path; NTSTATUS s; LONG e;
    if (!out) return STATUS_INVALID_PARAMETER;
    *out = NULL;
    if ((s = resolve(oa, &root, &path)) != STATUS_SUCCESS) return s;
    e = RegOpenKeyExA(root, path, 0, clean_sam(access), &h);
    if (e == ERROR_SUCCESS) {
        if (!add_key(h, root, path)) { RegCloseKey(h); xfree(path); return STATUS_NO_MEMORY_K; }
        *out = (HANDLE)h;
    }
    xfree(path);
    return reg_status(e);
}

NTSTATUS KEXAPI kex_NtOpenKey(PHANDLE out, ACCESS_MASK access, KOBJATTR *oa)
{
    return kex_NtOpenKeyEx(out, access, oa, 0);
}

NTSTATUS KEXAPI kex_NtCreateKey(PHANDLE out, ACCESS_MASK access, KOBJATTR *oa, ULONG title,
                                KUSTR *cls, ULONG options, PULONG disposition)
{
    HKEY root, h; char *path; NTSTATUS s; LONG e; DWORD disp = REG_OPENED_EXISTING_KEY;
    if (!out) return STATUS_INVALID_PARAMETER;
    *out = NULL;
    if ((s = resolve(oa, &root, &path)) != STATUS_SUCCESS) return s;
    if (!path[0]) e = RegOpenKeyExA(root, NULL, 0, clean_sam(access), &h);   /* the root itself */
    else {
        e = RegOpenKeyExA(root, path, 0, clean_sam(access), &h);
        if (e != ERROR_SUCCESS) {
            /* NT creates only the last component: the parent must already exist. */
            char *slash = strrchr(path, '\\');
            if (slash) {
                HKEY ph; LONG pe;
                *slash = 0; pe = RegOpenKeyExA(root, path, 0, KEY_READ, &ph); *slash = '\\';
                if (pe != ERROR_SUCCESS) { xfree(path); return STATUS_OBJECT_NAME_NOT_FOUND_K; }
                RegCloseKey(ph);
            }
            e = RegCreateKeyExA(root, path, 0, NULL, REG_OPTION_NON_VOLATILE, clean_sam(access), NULL, &h, &disp);
            if (e == ERROR_SUCCESS) disp = REG_CREATED_NEW_KEY;
        }
    }
    if (e == ERROR_SUCCESS) {
        if (!add_key(h, root, path)) { RegCloseKey(h); xfree(path); return STATUS_NO_MEMORY_K; }
        *out = (HANDLE)h;
        if (disposition) *disposition = disp;
    }
    xfree(path);
    return reg_status(e);
}

NTSTATUS KEXAPI kex_NtDeleteKey(HANDLE key)
{
    HKEY root; char *path; BOOL del; DWORD nsub = 0; LONG e;
    if (!key_info((HKEY)key, &root, &path, &del)) return STATUS_INVALID_HANDLE_K;
    if (del) { xfree(path); return STATUS_KEY_DELETED_K; }
    if (!path[0]) { xfree(path); return STATUS_CANNOT_DELETE_K; }               /* a hive root */
    e = RegQueryInfoKeyA((HKEY)key, NULL, NULL, NULL, &nsub, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (e == ERROR_SUCCESS && nsub) { xfree(path); return STATUS_CANNOT_DELETE_K; }  /* NT: no subkeys allowed */
    e = RegDeleteKeyA(root, path);
    xfree(path);
    if (e == ERROR_SUCCESS) mark_deleted((HKEY)key);
    return reg_status(e);
}

NTSTATUS KEXAPI kex_NtFlushKey(HANDLE key)
{
    return reg_status(RegFlushKey((HKEY)key));
}

/* ---------------------------------------------------------------- values */
static BOOL is_str_type(DWORD t) { return t == REG_SZ || t == REG_EXPAND_SZ || t == REG_MULTI_SZ; }

/* Value name -> ANSI ("" = default value). */
static char *value_name(const KUSTR *n)
{
    return w2a(n && n->Buffer ? n->Buffer : L"", n && n->Buffer ? n->Length / 2 : 0);
}

/*
 * Read a value; for string types returns UTF-16 data (always terminated: one NUL for SZ,
 * two for MULTI_SZ, as NT stores them when written by Win32 callers).
 */
static NTSTATUS read_value(HKEY h, const char *name, DWORD *type, BYTE **data, DWORD *len)
{
    DWORD t = 0, sz = 0; BYTE *a; LONG e;
    e = RegQueryValueExA(h, name, NULL, &t, NULL, &sz);
    if (e != ERROR_SUCCESS && e != ERROR_MORE_DATA) return reg_status(e);
    if (!(a = xalloc(sz + 2))) return STATUS_NO_MEMORY_K;
    e = RegQueryValueExA(h, name, NULL, &t, a, &sz);
    if (e != ERROR_SUCCESS) { xfree(a); return reg_status(e); }
    if (is_str_type(t)) {
        int n = (int)sz, wn; WCHAR *w; int need = (t == REG_MULTI_SZ) ? 2 : 1;
        while (n > 0 && a[n - 1] == 0) n--;                           /* strip terminators, re-add below */
        wn = n ? MultiByteToWideChar(CP_ACP, 0, (char *)a, n, NULL, 0) : 0;
        if (n && wn <= 0) { xfree(a); return STATUS_UNSUCCESSFUL_K; }
        if (!(w = xalloc((wn + need) * sizeof(WCHAR)))) { xfree(a); return STATUS_NO_MEMORY_K; }
        if (wn) MultiByteToWideChar(CP_ACP, 0, (char *)a, n, w, wn);
        w[wn] = 0; if (need == 2) w[wn + 1] = 0;
        if (t == REG_MULTI_SZ && wn == 0) need = 1;                   /* empty multi-sz = one NUL */
        xfree(a);
        *data = (BYTE *)w; *len = (wn + need) * sizeof(WCHAR);
    } else { *data = a; *len = sz; }
    *type = t;
    return STATUS_SUCCESS;
}

/* KEY_VALUE_INFORMATION_CLASS */
#define KVBasic   0
#define KVFull    1
#define KVPartial 2
#define KVFullA64 3
#define KVPartA64 4

NTSTATUS KEXAPI kex_NtQueryValueKey(HANDLE key, KUSTR *vname, ULONG cls, PVOID buf, ULONG len, PULONG retlen)
{
    char *name; DWORD type = 0, dlen = 0; BYTE *data = NULL; NTSTATUS s;
    ULONG nbytes = (vname && vname->Buffer) ? vname->Length : 0;
    ULONG fixed, need, doff = 0;
    BOOL del = FALSE; HKEY r; char *p;

    if (retlen) *retlen = 0;
    if (cls > KVPartA64) return STATUS_INVALID_INFO_CLASS;
    if (key_info((HKEY)key, &r, &p, &del)) { xfree(p); if (del) return STATUS_KEY_DELETED_K; }
    if (!(name = value_name(vname))) return STATUS_NO_MEMORY_K;
    s = read_value((HKEY)key, name, &type, &data, &dlen);
    xfree(name);
    if (s != STATUS_SUCCESS) return s;

    switch (cls) {
    case KVBasic:   fixed = 12; need = fixed + nbytes; break;                 /* TitleIndex Type NameLength Name[] */
    case KVFull: case KVFullA64:                                              /* + DataOffset DataLength */
        fixed = 20;
        doff = fixed + nbytes;
        doff = (cls == KVFullA64) ? ((doff + 7) & ~7UL) : ((doff + 3) & ~3UL);
        need = doff + dlen; break;
    case KVPartA64: fixed = 8;  need = fixed + dlen; break;                    /* Type DataLength Data[] (8-aligned) */
    default:        fixed = 12; need = fixed + dlen; break;                    /* TitleIndex Type DataLength Data[] */
    }
    if (retlen) *retlen = need;
    if (len < fixed || !buf) { xfree(data); return STATUS_BUFFER_TOO_SMALL; }

    {
        ULONG *u = (ULONG *)buf; BYTE *b = (BYTE *)buf;
        switch (cls) {
        case KVBasic:
            u[0] = 0; u[1] = type; u[2] = nbytes;
            if (len < need) { xfree(data); return STATUS_BUFFER_OVERFLOW_K; }
            if (nbytes) memcpy(b + 12, vname->Buffer, nbytes);
            break;
        case KVFull: case KVFullA64:
            u[0] = 0; u[1] = type; u[2] = doff; u[3] = dlen; u[4] = nbytes;
            if (len < need) { xfree(data); return STATUS_BUFFER_OVERFLOW_K; }
            if (nbytes) memcpy(b + 20, vname->Buffer, nbytes);
            if (doff > fixed + nbytes) memset(b + fixed + nbytes, 0, doff - fixed - nbytes);
            if (dlen) memcpy(b + doff, data, dlen);
            break;
        case KVPartA64:
            u[0] = type; u[1] = dlen;
            if (len < need) { xfree(data); return STATUS_BUFFER_OVERFLOW_K; }
            if (dlen) memcpy(b + 8, data, dlen);
            break;
        default:
            u[0] = 0; u[1] = type; u[2] = dlen;
            if (len < need) { xfree(data); return STATUS_BUFFER_OVERFLOW_K; }
            if (dlen) memcpy(b + 12, data, dlen);
            break;
        }
    }
    xfree(data);
    return STATUS_SUCCESS;
}

NTSTATUS KEXAPI kex_NtSetValueKey(HANDLE key, KUSTR *vname, ULONG title, ULONG type, PVOID data, ULONG size)
{
    char *name, *a = NULL; const BYTE *src = data; DWORD n = size; LONG e;
    BOOL del = FALSE; HKEY r; char *p;
    if (key_info((HKEY)key, &r, &p, &del)) { xfree(p); if (del) return STATUS_KEY_DELETED_K; }
    if (!(name = value_name(vname))) return STATUS_NO_MEMORY_K;
    if (is_str_type(type) && data) {
        int wn = (int)(size / 2), m;
        const WCHAR *w = (const WCHAR *)data;
        while (wn > 0 && w[wn - 1] == 0) wn--;                       /* re-terminate in ANSI */
        m = wn ? WideCharToMultiByte(CP_ACP, 0, w, wn, NULL, 0, NULL, NULL) : 0;
        if (wn && m <= 0) { xfree(name); return STATUS_INVALID_PARAMETER; }
        if (!(a = xalloc(m + 2))) { xfree(name); return STATUS_NO_MEMORY_K; }
        if (m) WideCharToMultiByte(CP_ACP, 0, w, wn, a, m, NULL, NULL);
        a[m] = 0; a[m + 1] = 0;
        n = m + ((type == REG_MULTI_SZ && m) ? 2 : 1);
        src = (const BYTE *)a;
    }
    e = RegSetValueExA((HKEY)key, name, 0, type, src, n);
    xfree(a); xfree(name);
    return reg_status(e);
}

NTSTATUS KEXAPI kex_NtDeleteValueKey(HANDLE key, KUSTR *vname)
{
    char *name; LONG e;
    if (!(name = value_name(vname))) return STATUS_NO_MEMORY_K;
    e = RegDeleteValueA((HKEY)key, name);
    xfree(name);
    return reg_status(e);
}

/* ---------------------------------------------------------------- handles */
NTSTATUS KEXAPI kex_NtClose(HANDLE h)
{
    void kex_section_forget(HANDLE h);
    if (h == (HANDLE)(ULONG_PTR)0xCAFE) return STATUS_SUCCESS;   /* token placeholder (sec_ext.c, nttoken_ext.c) */
    kex_section_forget(h);                                        /* shm_ext.c */
    if (remove_key((HKEY)h)) return reg_status(RegCloseKey((HKEY)h));
    if (is_predef((HKEY)h)) return STATUS_SUCCESS;
    if (CloseHandle(h)) return STATUS_SUCCESS;
    return STATUS_INVALID_HANDLE_K;
}

/* \REGISTRY\USER\<sid> for the current user; free with RtlFreeUnicodeString (process heap). */
NTSTATUS KEXAPI kex_RtlFormatCurrentUserKeyPath(KUSTR *out)
{
    static const WCHAR pre[] = L"\\REGISTRY\\USER\\";
    size_t a = sizeof(pre) / 2 - 1, b = sizeof(KEX_CU_SID) / 2 - 1;
    WCHAR *w;
    if (!out) return STATUS_INVALID_PARAMETER;
    if (!(w = xalloc((a + b + 1) * sizeof(WCHAR)))) return STATUS_NO_MEMORY_K;
    memcpy(w, pre, a * 2); memcpy(w + a, KEX_CU_SID, (b + 1) * 2);
    out->Buffer = w; out->Length = (USHORT)((a + b) * 2); out->MaximumLength = (USHORT)((a + b + 1) * 2);
    return STATUS_SUCCESS;
}

/* RtlOpenCurrentUser: a handle to HKEY_CURRENT_USER usable with the calls above. */
NTSTATUS KEXAPI kex_RtlOpenCurrentUser(ACCESS_MASK access, PHANDLE out)
{
    HKEY h; LONG e;
    if (!out) return STATUS_INVALID_PARAMETER;
    *out = NULL;
    e = RegOpenKeyExA(HKEY_CURRENT_USER, NULL, 0, clean_sam(access), &h);
    if (e == ERROR_SUCCESS) {
        if (!add_key(h, HKEY_CURRENT_USER, "")) { RegCloseKey(h); return STATUS_NO_MEMORY_K; }
        *out = (HANDLE)h;
    }
    return reg_status(e);
}
