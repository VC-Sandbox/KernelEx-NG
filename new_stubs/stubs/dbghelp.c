/* dbghelp.dll stub for Windows 98 SE: no symbol engine (callers print raw addresses). */
#include <windows.h>
static DWORD g_opts;
DWORD WINAPI SymSetOptions(DWORD o) { g_opts = o; return g_opts; }
DWORD WINAPI SymGetOptions(void) { return g_opts; }

/* EnumerateLoadedModules*: the loaded-module list of THIS process via toolhelp (Mozilla's mozglue imports
 * EnumerateLoadedModules64 for its stack walker). Other processes: FALSE, ERROR_NOT_SUPPORTED. */
#include <tlhelp32.h>
/* Win98 has no GetProcessId; a handle to our own process other than the pseudo handle is accepted when
 * kexnt's GetProcessId (KernelEx routes KERNEL32 for this DLL) says so - looked up at run time. */
static DWORD GetProcessId_compat(HANDLE h)
{
    typedef DWORD (WINAPI *T)(HANDLE);
    T f = (T)(void *)GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "GetProcessId");
    return f ? f(h) : 0;
}
typedef BOOL (CALLBACK *EMCB)(PCSTR, ULONG, ULONG, PVOID);
typedef BOOL (CALLBACK *EMCB64)(PCSTR, DWORD64, ULONG, PVOID);
typedef BOOL (CALLBACK *EMCBW64)(PCWSTR, DWORD64, ULONG, PVOID);

static BOOL enum_mods(HANDLE proc, int kind, void *cb, PVOID ctx)
{
    MODULEENTRY32 me; HANDLE s;
    if (!cb) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (proc != GetCurrentProcess() && GetProcessId_compat(proc) != GetCurrentProcessId()) {
        SetLastError(ERROR_NOT_SUPPORTED); return FALSE;
    }
    s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (s == INVALID_HANDLE_VALUE) return FALSE;
    me.dwSize = sizeof(me);
    if (Module32First(s, &me)) do {
        BOOL more;
        if (kind == 0) more = ((EMCB)cb)(me.szExePath, (ULONG)(ULONG_PTR)me.modBaseAddr, me.modBaseSize, ctx);
        else if (kind == 1) more = ((EMCB64)cb)(me.szExePath, (DWORD64)(ULONG_PTR)me.modBaseAddr, me.modBaseSize, ctx);
        else {
            WCHAR w[MAX_PATH];
            if (!MultiByteToWideChar(CP_ACP, 0, me.szExePath, -1, w, MAX_PATH)) w[0] = 0;
            more = ((EMCBW64)cb)(w, (DWORD64)(ULONG_PTR)me.modBaseAddr, me.modBaseSize, ctx);
        }
        if (!more) break;
        me.dwSize = sizeof(me);
    } while (Module32Next(s, &me));
    CloseHandle(s);
    return TRUE;
}
BOOL WINAPI EnumerateLoadedModules(HANDLE p, EMCB cb, PVOID ctx) { return enum_mods(p, 0, (void *)cb, ctx); }
BOOL WINAPI EnumerateLoadedModules64(HANDLE p, EMCB64 cb, PVOID ctx) { return enum_mods(p, 1, (void *)cb, ctx); }
BOOL WINAPI EnumerateLoadedModulesW64(HANDLE p, EMCBW64 cb, PVOID ctx) { return enum_mods(p, 2, (void *)cb, ctx); }
