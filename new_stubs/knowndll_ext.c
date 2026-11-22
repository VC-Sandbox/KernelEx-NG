/* knowndll_ext.c - GetProcAddress for the DLLs KernelEx loads from its own folder (2026-11-10, build 20).
 *
 * KernelEx 4.5.2 redirects PDH, PSAPI, USERENV, UXTHEME, WTSAPI32 and MSIMG32 to its own copies in
 * C:\WINDOWS\KERNELEX (HKLM\Software\KernelEx\KnownDLLs). Its resolver only applies API tables to modules
 * loaded from the system folder (core/resolver.cpp resolve_mod_index: "Skip non-system modules"), so the
 * functions kexnt publishes under those DLLs (PdhAddEnglishCounterW, the USERENV ones) were never found.
 * Chromium delay-loads pdh.dll and stopped at chrome/common/win/delay_load_failure_support.cc:40
 * (DelayLoad-ModuleName pdh.dll, LastError 127).
 *
 * kex_GetProcAddress: if the name is one kexnt publishes under such a DLL and the module is that DLL
 * loaded from outside the system folder, return kexnt's function. Everything else JUMPS to KERNEL32's
 * GetProcAddress with the caller's return address untouched (KernelEx picks the API configuration from
 * the caller's address, core/thunks.cpp ExportFromNameDynamic_thunk).
 */
#include "kexnt_common.h"
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

typedef struct { const char *name; unsigned long addr; } k_named;
typedef struct { const char *lib; const k_named *named; int nnamed; const void *unnamed; int nunnamed; } k_table;
const k_table *get_api_table(void);

static const char *const g_known[] = { "PDH.DLL", "PSAPI.DLL", "USERENV.DLL", "UXTHEME.DLL", "WTSAPI32.DLL", "MSIMG32.DLL" };

/* KERNEL32's own GetProcAddress, read from its export table (not through any import that might be routed here). */
static FARPROC real_gpa(void)
{
    static FARPROC cached;
    BYTE *b; IMAGE_NT_HEADERS32 *nt; IMAGE_EXPORT_DIRECTORY *e; DWORD *names, *funcs; WORD *ords; DWORD i;
    if (cached) return cached;
    b = (BYTE *)GetModuleHandleA("KERNEL32.DLL");
    if (!b) return NULL;
    nt = (IMAGE_NT_HEADERS32 *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    e = (IMAGE_EXPORT_DIRECTORY *)(b + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names = (DWORD *)(b + e->AddressOfNames); funcs = (DWORD *)(b + e->AddressOfFunctions); ords = (WORD *)(b + e->AddressOfNameOrdinals);
    for (i = 0; i < e->NumberOfNames; i++)
        if (!lstrcmpA((const char *)(b + names[i]), "GetProcAddress")) { cached = (FARPROC)(b + funcs[ords[i]]); break; }
    return cached;
}
FARPROC knowndll_real_gpa(void) { return real_gpa(); }

static LONG g_kd_traces;
FARPROC WINAPI knowndll_gpa_extra(HMODULE h, LPCSTR name)
{
    static const k_table *tabs[8]; static volatile LONG ntabs = -1;
    const char *lib = NULL; unsigned long addr = 0; int i, k;
    char path[MAX_PATH], sys[MAX_PATH]; const char *base, *p; UINT n;
    if (!h || (ULONG_PTR)name < 0x10000) return NULL;
    if (ntabs < 0) {                      /* the kexnt tables of those DLLs, found once (a race only repeats the same work) */
        const k_table *t; LONG c = 0;
        for (t = get_api_table(); t && t->lib && c < 8; t++)
            for (i = 0; i < (int)(sizeof(g_known) / sizeof(g_known[0])); i++)
                if (!lstrcmpiA(t->lib, g_known[i])) { tabs[c++] = t; break; }
        InterlockedExchange((LONG *)&ntabs, c);
    }
    for (i = 0; i < ntabs && !addr; i++)
        for (k = 0; k < tabs[i]->nnamed; k++)
            if (tabs[i]->named[k].name && !lstrcmpA(tabs[i]->named[k].name, name)) { lib = tabs[i]->lib; addr = tabs[i]->named[k].addr; break; }
    if (!addr) return NULL;
    { DWORD le = GetLastError();
      n = GetModuleFileNameA(h, path, sizeof(path));
      SetLastError(le); }
    if (!n || n >= sizeof(path)) return NULL;
    for (base = p = path; *p; p++) if (*p == '\\' || *p == '/') base = p + 1;
    if (lstrcmpiA(base, lib)) return NULL;
    n = GetSystemDirectoryA(sys, sizeof(sys) - 2);
    if (n && n < sizeof(sys) - 2) {
        if (sys[n - 1] != '\\') sys[n++] = '\\';
        sys[n] = 0;
        if ((UINT)(base - path) == n && CompareStringA(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, path, n, sys, n) == CSTR_EQUAL) return NULL;   /* system folder: KernelEx's resolver handles it */
    }
    if (InterlockedIncrement(&g_kd_traces) <= 50) { kex_trace("GetProcAddress: kexnt function for a KernelEx-folder DLL", (DWORD)(ULONG_PTR)h, addr, 0, 0); kex_trace(name, 0, 0, 0, 0); }
    return (FARPROC)addr;
}

/* stdcall GetProcAddress(h, name): ours, or a tail jump into KERNEL32 with the caller's frame as it was. */
__asm__(
    ".text\n"
    ".globl _kex_GetProcAddress@8\n"
    "_kex_GetProcAddress@8:\n"
    "    pushl 4(%esp)\n"                    /* build 131: the NTDLL facade stands for the real NTDLL (ntfacade_ext.c) */
    "    call _kex_ntdll_real\n"
    "    addl $4, %esp\n"
    "    movl %eax, 4(%esp)\n"
    "    pushl 8(%esp)\n"
    "    pushl 8(%esp)\n"
    "    call _knowndll_gpa_extra@8\n"
    "    testl %eax, %eax\n"
    "    jz 1f\n"
    "    ret $8\n"
    "1:  call _knowndll_real_gpa\n"
    "    testl %eax, %eax\n"
    "    jz 2f\n"
    "    jmp *%eax\n"
    "2:  ret $8\n"
);
