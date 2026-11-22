/*
 * ntfacade_ext.c - KernelEx-NG build 131: what a modern program finds when it reads NTDLL's export table itself.
 *
 * Windows 98's NTDLL.DLL (shared arena, the same for every process) exports almost nothing; kexnt's NTDLL functions
 * reach programs through KernelEx's GetProcAddress (gate thunks). Code that parses NTDLL's export directory itself
 * never sees them: Chromium's sandbox (Firefox 115's content processes) resolves the functions it patches in a child
 * with base::win::PEImage(GetModuleHandle(L"ntdll.dll")).GetProcAddress (resolver.cc ResolveInterceptor) and gave up
 * (SBOX_ERROR_CANNOT_SETUP_INTERCEPTION_THUNK, STATUS_PROCEDURE_NOT_FOUND).
 *
 * In a modern program (kex_peb_active) GetModuleHandle("ntdll.dll") answers with a FACADE: a private block shaped like
 * a PE image whose export directory ("ntdll.dll") lists every function kexnt publishes under NTDLL, each pointing at
 * its gate (gen_apitable.py; the sandbox's targets have NT service-stub gates). Every API given the facade handle
 * works on the real NTDLL (GetProcAddress, GetModuleFileName, FreeLibrary). Windows 98 programs are untouched (the
 * gates send them to the previous implementation), and NTDLL itself is not changed.
 */
#include "kexnt_common.h"

typedef struct { const char *name; unsigned long addr; } k_named;
typedef struct { const char *lib; const k_named *named; int nnamed; const void *unnamed; int nunnamed; } k_table;
const k_table *get_api_table(void);
FARPROC kex_prev_impl(const char *dll, const char *name);
BOOL kex_peb_active(void);
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

static BYTE *g_fac;                 /* the facade (64 KB aligned, private) */
static HMODULE g_real;              /* Windows 98's NTDLL.DLL */
static volatile LONG g_fac_lock;

static int ord_cmp(const char *a, const char *b) { while (*a && *a == *b) a++, b++; return (BYTE)*a - (BYTE)*b; }

static BYTE *build(void)
{
    const k_table *t; const k_named *v = NULL; int n = 0, i, j; DWORD strs = 0, size, o_exp, o_fn, o_nm, o_or, o_str;
    const k_named **s; BYTE *b; IMAGE_NT_HEADERS32 *nt; IMAGE_EXPORT_DIRECTORY *e; char *p;
    k_named *own = NULL; int nown = 0;
    for (t = get_api_table(); t && t->lib; t++) if (!lstrcmpiA(t->lib, "NTDLL.DLL")) { v = t->named; n = t->nnamed; break; }
    if (!v || n <= 0) return NULL;
    {   /* Windows 98's own NTDLL exports that kexnt does not replace (kexnt's entry wins for a name both have) */
        BYTE *rb = (BYTE *)g_real; IMAGE_NT_HEADERS32 *rh; IMAGE_EXPORT_DIRECTORY *re; DWORD rva, rsz, k;
        if (rb && *(WORD *)rb == IMAGE_DOS_SIGNATURE) {
            rh = (IMAGE_NT_HEADERS32 *)(rb + ((IMAGE_DOS_HEADER *)rb)->e_lfanew);
            rva = rh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            rsz = rh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            re = (IMAGE_EXPORT_DIRECTORY *)(rb + rva);
            if (rva && re->NumberOfNames && (own = (k_named *)HeapAlloc(GetProcessHeap(), 0, re->NumberOfNames * sizeof(*own)))) {
                for (k = 0; k < re->NumberOfNames; k++) {
                    const char *nm = (const char *)(rb + ((DWORD *)(rb + re->AddressOfNames))[k]);
                    DWORD f = ((DWORD *)(rb + re->AddressOfFunctions))[((WORD *)(rb + re->AddressOfNameOrdinals))[k]];
                    int dup = 0;
                    if (!f || (f >= rva && f < rva + rsz)) continue;           /* none / a forwarder */
                    for (j = 0; j < n && !dup; j++) dup = !ord_cmp(v[j].name, nm);
                    if (!dup) { own[nown].name = nm; own[nown].addr = (unsigned long)(rb + f); nown++; }
                }
            }
        }
    }
    if (!(s = (const k_named **)HeapAlloc(GetProcessHeap(), 0, (n + nown) * sizeof(*s)))) return NULL;
    for (i = 0; i < n; i++) { s[i] = &v[i]; strs += lstrlenA(v[i].name) + 1; }
    for (i = 0; i < nown; i++) { s[n + i] = &own[i]; strs += lstrlenA(own[i].name) + 1; }
    n += nown;   /* (own stays allocated: the facade's names point at it only while building - copied below) */
    for (i = 1; i < n; i++) { const k_named *x = s[i]; for (j = i; j > 0 && ord_cmp(s[j - 1]->name, x->name) > 0; j--) s[j] = s[j - 1]; s[j] = x; }
    o_exp = 0x200; o_fn = o_exp + sizeof(IMAGE_EXPORT_DIRECTORY); o_nm = o_fn + 4 * n; o_or = o_nm + 4 * n;
    o_str = (o_or + 2 * n + 3) & ~3UL; size = (o_str + strs + 16 + 0xFFFF) & ~0xFFFFUL;
    if (!(b = (BYTE *)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) { HeapFree(GetProcessHeap(), 0, s); return NULL; }
    ((IMAGE_DOS_HEADER *)b)->e_magic = IMAGE_DOS_SIGNATURE; ((IMAGE_DOS_HEADER *)b)->e_lfanew = 0x40;
    nt = (IMAGE_NT_HEADERS32 *)(b + 0x40);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386; nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_DLL;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC; nt->OptionalHeader.ImageBase = (DWORD)(ULONG_PTR)b;
    nt->OptionalHeader.SectionAlignment = 0x1000; nt->OptionalHeader.FileAlignment = 0x200;
    nt->OptionalHeader.MajorOperatingSystemVersion = 4; nt->OptionalHeader.MajorSubsystemVersion = 4;
    nt->OptionalHeader.SizeOfImage = size; nt->OptionalHeader.SizeOfHeaders = 0x200;
    nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI; nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = o_exp;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = o_str + strs + 16 - o_exp;
    e = (IMAGE_EXPORT_DIRECTORY *)(b + o_exp);
    e->Base = 1; e->NumberOfFunctions = n; e->NumberOfNames = n;
    e->AddressOfFunctions = o_fn; e->AddressOfNames = o_nm; e->AddressOfNameOrdinals = o_or;
    p = (char *)(b + o_str);
    lstrcpyA(p, "ntdll.dll"); e->Name = (DWORD)(p - (char *)b); p += 10;
    for (i = 0; i < n; i++) {
        ((DWORD *)(b + o_fn))[i] = (DWORD)(s[i]->addr - (DWORD)(ULONG_PTR)b);   /* RVA of the gate (wraps: it lies below) */
        ((DWORD *)(b + o_nm))[i] = (DWORD)(p - (char *)b);
        ((WORD *)(b + o_or))[i] = (WORD)i;
        lstrcpyA(p, s[i]->name); p += lstrlenA(s[i]->name) + 1;
    }
    HeapFree(GetProcessHeap(), 0, s);
    kex_trace("ntdll facade built (base, functions)", (DWORD)(ULONG_PTR)b, (DWORD)n, 0, 0);
    return b;
}

static HMODULE facade(void)
{
    if (g_fac) return (HMODULE)g_fac;
    kex_spin_acquire(&g_fac_lock);
    if (!g_fac) { g_real = GetModuleHandleA("NTDLL.DLL"); if (g_real) g_fac = build(); }
    InterlockedExchange(&g_fac_lock, 0);
    return (HMODULE)g_fac;
}
/* knowndll_ext.c kex_GetProcAddress and the wrappers below: the facade stands for the real NTDLL */
HMODULE kex_ntdll_real(HMODULE h) { return (g_fac && h == (HMODULE)g_fac) ? g_real : h; }

static BOOL ntdll_name(const char *n)          /* "ntdll" / "ntdll.dll", with or without a path */
{
    const char *b = n, *p; char x[16]; int k = 0;
    for (p = n; *p; p++) if (*p == '\\' || *p == '/') b = p + 1;
    for (p = b; *p && k < 15; p++) x[k++] = (*p >= 'A' && *p <= 'Z') ? (char)(*p + 32) : *p;
    x[k] = 0;
    return !*p && (!lstrcmpA(x, "ntdll") || !lstrcmpA(x, "ntdll.dll"));
}
static BOOL ntdll_name_w(LPCWSTR n)
{
    char a[MAX_PATH]; int k;
    for (k = 0; n[k] && k < MAX_PATH - 1; k++) { if (n[k] > 0x7F) return FALSE; a[k] = (char)n[k]; }
    a[k] = 0;
    return !n[k] && ntdll_name(a);
}

typedef HMODULE (WINAPI *T_GMHA)(LPCSTR);
typedef HMODULE (WINAPI *T_GMHW)(LPCWSTR);
typedef BOOL (WINAPI *T_GMHXA)(DWORD, LPCSTR, HMODULE *);
typedef BOOL (WINAPI *T_GMHXW)(DWORD, LPCWSTR, HMODULE *);
typedef DWORD (WINAPI *T_GMFA)(HMODULE, LPSTR, DWORD);
typedef DWORD (WINAPI *T_GMFW)(HMODULE, LPWSTR, DWORD);
typedef BOOL (WINAPI *T_FL)(HMODULE);
#define PREV(T, v, name) static T v; if (!v) v = (T)(void *)kex_prev_impl("KERNEL32.DLL", name)

HMODULE KEXAPI kex_GetModuleHandleA(LPCSTR n)
{
    PREV(T_GMHA, p, "GetModuleHandleA");
    if (n && kex_peb_active() && ntdll_name(n) && facade()) return (HMODULE)g_fac;
    return p ? p(n) : NULL;
}
HMODULE KEXAPI kex_GetModuleHandleW(LPCWSTR n)
{
    PREV(T_GMHW, p, "GetModuleHandleW");
    if (n && kex_peb_active() && ntdll_name_w(n) && facade()) return (HMODULE)g_fac;
    if (!p) { SetLastError(ERROR_PROC_NOT_FOUND); return NULL; }
    return p(n);
}
BOOL KEXAPI kex_GetModuleHandleExA(DWORD f, LPCSTR n, HMODULE *out)
{
    PREV(T_GMHXA, p, "GetModuleHandleExA");
    if (out && n && !(f & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) && kex_peb_active() && ntdll_name(n) && facade()) { *out = (HMODULE)g_fac; return TRUE; }
    if (!p) { SetLastError(ERROR_PROC_NOT_FOUND); return FALSE; }
    return p(f, n, out);
}
BOOL KEXAPI kex_GetModuleHandleExW(DWORD f, LPCWSTR n, HMODULE *out)
{
    PREV(T_GMHXW, p, "GetModuleHandleExW");
    if (out && n && !(f & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) && kex_peb_active() && ntdll_name_w(n) && facade()) { *out = (HMODULE)g_fac; return TRUE; }
    if (!p) { SetLastError(ERROR_PROC_NOT_FOUND); return FALSE; }
    return p(f, n, out);
}
DWORD KEXAPI kex_GetModuleFileNameA(HMODULE h, LPSTR buf, DWORD len)
{
    PREV(T_GMFA, p, "GetModuleFileNameA");
    return p ? p(kex_ntdll_real(h), buf, len) : 0;
}
DWORD KEXAPI kex_GetModuleFileNameW(HMODULE h, LPWSTR buf, DWORD len)
{
    PREV(T_GMFW, p, "GetModuleFileNameW");
    if (!p) { SetLastError(ERROR_PROC_NOT_FOUND); return 0; }
    return p(kex_ntdll_real(h), buf, len);
}
BOOL KEXAPI kex_FreeLibrary(HMODULE h)
{
    PREV(T_FL, p, "FreeLibrary");
    if (g_fac && h == (HMODULE)g_fac) return TRUE;     /* the facade is never "loaded" */
    return p ? p(h) : FALSE;
}
