/*
 * gate_ext.c - KernelEx-NG build 89: kexnt only for programs built for newer Windows.
 *
 * KEXNT is in every core.ini configuration, including KernelEx's "Default mode" (DCFG1) that every 32-bit
 * program gets unless KernelEx is disabled for it - so Windows 98 programs went through kexnt's versions of
 * ReadFile, CreateFileMapping, the USER32/GDI32 calls, ... too. Now every function kexnt publishes through the
 * KernelEx resolver is a small gate (gen_apitable.py):
 *   - a program built for Windows NT 5 or later (the EXE's subsystem version 5.0+, as Chromium, Firefox, Mypal),
 *     or one the user gave an NT profile on the KernelEx tab (AppSettings\Configs, anything but Default mode /
 *     Windows 95 / 98 / ME / Disable custom heap): kexnt's function, as before (one compare and a jump);
 *   - any other program (Windows 98 programs: subsystem 4.x): what KernelEx gives WITHOUT kexnt - kexbasen,
 *     kexbases or the system DLL itself. Only a function that exists nowhere else (an NT-only call such a
 *     program looked up by name) still reaches kexnt; kexnt then sets itself up on that first call.
 * In a Windows 98 program kexnt's DllMain does nothing: no TLS slots, no hooks, no logs.
 * Override for tests: HKLM\Software\KernelEx\KexNG "Gate" = DWORD 0 (every program counts as modern).
 * KEXTEST.EXE exports "KexNG_ModernProcess" so it is always tested as a modern program.
 * MS-DOS and 16-bit Windows programs are never touched by KernelEx at all.
 */
#include "kexnt_common.h"

typedef struct { const char *dll, *name; void (*real)(void); } kexgate_entry;
extern const kexgate_entry kexgate_tab[];     /* kexnt_apitable.c (generated) */
extern const int kexgate_count;
FARPROC kex_prev_impl(const char *dll, const char *name);   /* gdiguard_ext.c */

volatile LONG kex_gate_state;                  /* 0 not decided, 1 Windows 9x program, 2 modern program */
static FARPROC *g_prev;                        /* per gate: the function without kexnt (lazily) */
static int g_why;                              /* for the KEXCRASH note: 1 subsystem, 2 profile, 3 marker, 4 override, 5 .NET */
static int g_clr;                              /* build 132: the EXE is a .NET program */
int kex_gate_is_clr(void) { return g_clr; }

static void upc(char *s) { for (; *s; s++) if (*s >= 'a' && *s <= 'z') *s -= 32; }

/* KernelEx wildcard (* and ?), both strings upper case */
static BOOL wild(const char *p, const char *s)
{
    if (!*p) return !*s;
    if (*p == '*') { do { if (wild(p + 1, s)) return TRUE; } while (*s++); return FALSE; }
    if (*s && (*p == '?' || *p == *s)) return wild(p + 1, s + 1);
    return FALSE;
}

static BOOL nt_profile_chosen(const char *exe)
{
    HKEY k; DWORD i, nl, dl, t; char nm[MAX_PATH], ex[MAX_PATH], conf[64]; BOOL found = FALSE, modern = FALSE;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\AppSettings\\Configs", 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
        return FALSE;
    for (i = 0; !found; i++) {
        nl = sizeof(nm); dl = sizeof(conf) - 1;
        if (RegEnumValueA(k, i, nm, &nl, NULL, &t, (BYTE *)conf, &dl) != ERROR_SUCCESS) break;
        if (t != REG_SZ) continue;
        conf[dl < sizeof(conf) ? dl : sizeof(conf) - 1] = 0;
        if (!ExpandEnvironmentStringsA(nm, ex, MAX_PATH)) continue;
        upc(ex); upc(conf);
        if (lstrcmpA(ex, exe) && !wild(ex, exe)) continue;
        found = TRUE;
        modern = lstrcmpA(conf, "DCFG1") && lstrcmpA(conf, "WIN95") && lstrcmpA(conf, "WIN98") &&
                 lstrcmpA(conf, "WINME") && lstrcmpA(conf, "NOHEAP");
    }
    RegCloseKey(k);
    return modern;
}

static LONG decide(void)
{
    BYTE *b = (BYTE *)GetModuleHandleA(NULL); char exe[MAX_PATH]; LONG st = 1;
    HKEY k; DWORD v = 1, t, n = sizeof(v);
    /* build 90: the EXE header first - no registry or loader call for the programs kexnt is for */
    if (b && ((IMAGE_DOS_HEADER *)b)->e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE && nt->OptionalHeader.MajorSubsystemVersion >= 5) { g_why = 1; return 2; }
        /* build 132: a .NET program (CLR header). C# compilers mark their EXEs subsystem 4.0, but the runtime they need
         * (mscoree.dll -> clr.dll, built for XP) needs kexnt in the process (measured: HELLO.EXE, subsystem 4.0, died
         * in the runtime's first NT-only TEB read; with kexnt that read is fixed up - veh_ext.c teb_tls_fix). */
        if (nt->Signature == IMAGE_NT_SIGNATURE && nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress) { g_why = 5; g_clr = 1; return 2; }
    }
    if (!kex_is_win9x()) { g_why = 4; return 2; }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExA(k, "Gate", NULL, &t, (BYTE *)&v, &n) != ERROR_SUCCESS || t != REG_DWORD) v = 1;
        RegCloseKey(k);
    }
    if (!v) { g_why = 4; return 2; }
    if (st == 1 && b && GetProcAddress((HMODULE)b, "KexNG_ModernProcess")) { g_why = 3; st = 2; }
    if (st == 1 && GetModuleFileNameA(NULL, exe, MAX_PATH)) { upc(exe); if (nt_profile_chosen(exe)) { g_why = 2; st = 2; } }
    return st;
}

LONG kex_gate_decide(void)
{
    if (kex_gate_state == 0) InterlockedCompareExchange(&kex_gate_state, decide(), 0);
    return kex_gate_state;
}
BOOL kex_gate_modern(void) { return kex_gate_decide() == 2; }
int kex_gate_reason(void) { kex_gate_decide(); return g_why; }

void kex_full_init(void);                      /* kexnt.c: kexnt's own start-up, run once */

/* cdecl, from kexgate_slow: the address the call continues at */
/* build 124: functions whose kexnt version every program gets, Windows 9x programs included - only W functions
 * Windows 98 does not really have (KernelEx's addition answered differently from NT and broke programs):
 *   GetPrivateProfileStringW  default value as on NT (installer_ext.c) - NSIS 3 installers looped forever
 *   GetPrivateProfileIntW, WritePrivateProfileStringW  (build 126, uini_ext.c) UTF-16 INI files as on NT; every
 *                             other file goes to the previous implementation unchanged
 */
static const char *const g_always[] = { "GetPrivateProfileStringW", "GetPrivateProfileIntW", "WritePrivateProfileStringW", NULL };
static BOOL always_kexnt(int i)
{
    int k;
    for (k = 0; g_always[k]; k++) if (!lstrcmpA(kexgate_tab[i].name, g_always[k])) return TRUE;
    return FALSE;
}

/* build 131: Windows 98 programs keep Windows 98's LoadLibrary, with one addition: a DLL loaded by its full path
 * that fails because a DLL it needs is missing (126 / 1157) is tried once more with its own folder searched first
 * (LOAD_WITH_ALTERED_SEARCH_PATH). Modern DLLs keep their own DLLs beside them and name them in a side-by-side
 * manifest, which Windows 98 cannot read: REGSVR32 registering K-Lite's LAV filters failed with exit code 3. */
typedef HMODULE (WINAPI *T_LLA)(LPCSTR); typedef HMODULE (WINAPI *T_LLW)(LPCWSTR);
typedef HMODULE (WINAPI *T_LLEA)(LPCSTR, HANDLE, DWORD); typedef HMODULE (WINAPI *T_LLEW)(LPCWSTR, HANDLE, DWORD);
static T_LLA p_lla; static T_LLW p_llw; static T_LLEA p_llea; static T_LLEW p_llew;
static BOOL has_dir_a(LPCSTR n) { for (; n && *n; n++) if (*n == '\\' || *n == '/' || *n == ':') return TRUE; return FALSE; }
static BOOL has_dir_w(LPCWSTR n) { for (; n && *n; n++) if (*n == L'\\' || *n == L'/' || *n == L':') return TRUE; return FALSE; }
static BOOL retry_err(void) { DWORD e = GetLastError(); return e == ERROR_DLL_NOT_FOUND || e == ERROR_MOD_NOT_FOUND; }
static HMODULE WINAPI g9_LoadLibraryExA(LPCSTR n, HANDLE f, DWORD fl)
{
    HMODULE h = p_llea(n, f, fl); DWORD e;
    if (!h && has_dir_a(n) && !(fl & 0x0A) && retry_err()) { e = GetLastError(); if (!(h = p_llea(n, f, fl | 8))) SetLastError(e); }
    return h;
}
static HMODULE WINAPI g9_LoadLibraryA(LPCSTR n)
{
    HMODULE h = p_lla(n); DWORD e;
    if (!h && has_dir_a(n) && retry_err() && p_llea) { e = GetLastError(); if (!(h = p_llea(n, NULL, 8))) SetLastError(e); }
    return h;
}
static HMODULE WINAPI g9_LoadLibraryExW(LPCWSTR n, HANDLE f, DWORD fl)
{
    HMODULE h = p_llew(n, f, fl); DWORD e;
    if (!h && has_dir_w(n) && !(fl & 0x0A) && retry_err()) { e = GetLastError(); if (!(h = p_llew(n, f, fl | 8))) SetLastError(e); }
    return h;
}
static HMODULE WINAPI g9_LoadLibraryW(LPCWSTR n)
{
    HMODULE h = p_llw(n); DWORD e;
    if (!h && has_dir_w(n) && retry_err() && p_llew) { e = GetLastError(); if (!(h = p_llew(n, NULL, 8))) SetLastError(e); }
    return h;
}
static FARPROC loadlib_9x(const char *name, FARPROC prev)
{
    if (!prev || lstrcmpiA(name, "LoadLibraryA") && lstrcmpiA(name, "LoadLibraryW") && lstrcmpiA(name, "LoadLibraryExA") && lstrcmpiA(name, "LoadLibraryExW"))
        return prev;
    if (!p_llea) p_llea = (T_LLEA)(void *)kex_prev_impl("KERNEL32.DLL", "LoadLibraryExA");
    if (!p_llew) p_llew = (T_LLEW)(void *)kex_prev_impl("KERNEL32.DLL", "LoadLibraryExW");
    if (!lstrcmpiA(name, "LoadLibraryA")) { p_lla = (T_LLA)(void *)prev; return (FARPROC)g9_LoadLibraryA; }
    if (!lstrcmpiA(name, "LoadLibraryW")) { p_llw = (T_LLW)(void *)prev; return p_llew ? (FARPROC)g9_LoadLibraryW : prev; }
    if (!lstrcmpiA(name, "LoadLibraryExA")) { p_llea = (T_LLEA)(void *)prev; return (FARPROC)g9_LoadLibraryExA; }
    p_llew = (T_LLEW)(void *)prev; return (FARPROC)g9_LoadLibraryExW;
}

void *__cdecl kexgate_resolve(int i)
{
    FARPROC p;
    if (i < 0 || i >= kexgate_count) return NULL;
    if (kex_gate_decide() == 2) return (void *)kexgate_tab[i].real;
    if (g_prev && (p = g_prev[i]) != NULL) return (void *)p;
    if (always_kexnt(i)) { if (g_prev) g_prev[i] = (FARPROC)kexgate_tab[i].real; return (void *)kexgate_tab[i].real; }
    if (!g_prev) {
        FARPROC *t = (FARPROC *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FARPROC) * (SIZE_T)kexgate_count);
        if (t && InterlockedCompareExchange((volatile LONG *)&g_prev, (LONG)(ULONG_PTR)t, 0) != 0) HeapFree(GetProcessHeap(), 0, t);
    }
    if (g_prev && (p = g_prev[i]) != NULL) return (void *)p;
    p = kex_prev_impl(kexgate_tab[i].dll, kexgate_tab[i].name);
    {   /* build 131: a "previous" implementation inside kexnt itself is kexnt too (regsvr32 registering K-Lite's
         * VSFilter: FlsAlloc ran with kexnt never started -> page fault on its uninitialised lock) */
        extern IMAGE_DOS_HEADER __ImageBase; BYTE *b = (BYTE *)&__ImageBase;
        DWORD sz = ((IMAGE_NT_HEADERS *)(b + __ImageBase.e_lfanew))->OptionalHeader.SizeOfImage;
        if (p && (BYTE *)p >= b && (BYTE *)p < b + sz) p = NULL;
    }
    if (!p) { kex_full_init(); p = (FARPROC)kexgate_tab[i].real; }   /* exists only in kexnt */
    else if (!lstrcmpiA(kexgate_tab[i].dll, "KERNEL32.DLL")) p = loadlib_9x(kexgate_tab[i].name, p);
    if (g_prev) g_prev[i] = p;
    return (void *)p;
}

/* [esp] = gate index, [esp+4] = return address, arguments above: resolve, drop the index, jump with the
 * caller's stack untouched. EAX/ECX/EDX are free at a call boundary (stdcall and cdecl). */
/* build 90: EAX, ECX, EDX and the flags are kept too - a few MSVCRT helpers take arguments in registers
 * (__CxxFrameHandler3: EAX = function info), and a call can come before kexnt's DllMain decided the state. */
__asm__(".text\n"
        ".globl _kexgate_slow\n_kexgate_slow:\n"
        "  pushfl\n"
        "  pushl %eax\n  pushl %ecx\n  pushl %edx\n"
        "  pushl 16(%esp)\n"
        "  call _kexgate_resolve\n"
        "  addl $4, %esp\n"
        "  movl %eax, 16(%esp)\n"          /* the index slot now holds the target */
        "  popl %edx\n  popl %ecx\n  popl %eax\n"
        "  popfl\n"
        "  ret\n");                         /* jump to the target; the caller's return address is on top again */

/* for kextest: this process's gate state (1 Windows 9x program, 2 modern) and why */
VOID KEXAPI kex_KexGateInfo(PDWORD state, PDWORD why)
{
    LONG s = kex_gate_decide();
    if (state) *state = (DWORD)s;
    if (why) *why = (DWORD)g_why;
}

/* build 132: what Windows XP's loader does for an EXE with a CLR header before it starts the process: it calls
 * mscoree!_CorValidateImage(&ImageBase, FileName) (and starts the program at _CorExeMain). Windows 98's loader knows
 * nothing about it. Measured: .NET programs hosted through ICLRRuntimeHost run (probe clrhost.c), but an EXE started
 * directly stopped in the runtime's start-up with COR_E_BADIMAGEFORMAT (0x8007000B). kexnt's process attach runs
 * where XP's loader makes the call - after the EXE's imports (mscoree.dll) are loaded, before its entry point. */
void kex_clr_validate(void)
{
    typedef HRESULT (WINAPI *T_CVI)(PVOID *, LPCWSTR);
    void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
    HMODULE m = GetModuleHandleA("MSCOREE.DLL"); T_CVI f; PVOID base = GetModuleHandleA(NULL); WCHAR path[MAX_PATH]; char a[MAX_PATH]; HRESULT hr;
    if (!m || !(f = (T_CVI)GetProcAddress(m, "_CorValidateImage"))) { kex_crashnote("CLR: _CorValidateImage not found (mscoree loaded, -, -, -)", (DWORD)(ULONG_PTR)m, 0, 0, 0); return; }
    if (!GetModuleFileNameA(NULL, a, MAX_PATH) || !MultiByteToWideChar(CP_ACP, 0, a, -1, path, MAX_PATH)) return;
    {   /* Measured (MIN.EXE, the loaded image compared with its file): besides the bound IAT entry, Windows 98's loader
         * writes into the import descriptor itself - TimeDateStamp 0 -> 4AF3AF84 and ForwarderChain 0 -> 79000000
         * (mscoree's base) - marking it bound. NT's loader leaves descriptors as they are in the file, and the runtime's
         * IL-only image check (_CorValidateImage, and again at start-up) rejects such a descriptor: STATUS_INVALID_IMAGE_
         * FORMAT / COR_E_BADIMAGEFORMAT. Both fields are put back to the file's values. */
        HANDLE h = CreateFileA(a, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        BYTE *img = (BYTE *)base; IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(img + ((IMAGE_DOS_HEADER *)img)->e_lfanew);
        DWORD irva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, fixed = 0;
        if (h != INVALID_HANDLE_VALUE && irva) {
            IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt); int i; DWORD foff = 0;
            for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
                if (irva >= sec[i].VirtualAddress && irva < sec[i].VirtualAddress + sec[i].SizeOfRawData) foff = irva - sec[i].VirtualAddress + sec[i].PointerToRawData;
            if (foff) {
                IMAGE_IMPORT_DESCRIPTOR fd[16], *md = (IMAGE_IMPORT_DESCRIPTOR *)(img + irva); DWORD got = 0, old;
                SetFilePointer(h, foff, NULL, FILE_BEGIN); ReadFile(h, fd, sizeof(fd), &got, NULL);
                for (i = 0; i < 16 && (DWORD)(i + 1) * sizeof(fd[0]) <= got && fd[i].Name; i++)
                    if (md[i].Name == fd[i].Name && (md[i].TimeDateStamp != fd[i].TimeDateStamp || md[i].ForwarderChain != fd[i].ForwarderChain) &&
                        VirtualProtect(&md[i], sizeof(md[i]), PAGE_READWRITE, &old)) {
                        md[i].TimeDateStamp = fd[i].TimeDateStamp; md[i].ForwarderChain = fd[i].ForwarderChain; fixed++;
                        VirtualProtect(&md[i], sizeof(md[i]), old, &old);
                    }
            }
        }
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        if (fixed) kex_crashnote("CLR: import descriptors put back as in the file (Windows 98 had marked them bound) (count, -, -, -)", fixed, 0, 0, 0);
    }
    hr = f(&base, path);
    kex_crashnote("CLR: _CorValidateImage called as Windows XP's loader does (result, image base after, -, -)", (DWORD)hr, (DWORD)(ULONG_PTR)base, 0, 0);
}
