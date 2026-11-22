/* psapi_ng.c - KernelEx-NG additions to KernelEx's psapi.dll (auxiliary/psapi/psapi.c, unchanged), build 131.
 *
 * KernelEx loads PSAPI from its own folder (KnownDLLs), and its resolver adds API tables only to modules in
 * SYSTEM - so names kexnt implements (K32GetModuleInformation ...) were never visible to a STATIC psapi import.
 * Supermium 150's XP wrapper pwrp_k32.dll imports GetModuleInformation and GetMappedFileNameW statically; Windows 98
 * refused to start chrome.exe (CreateProcess error 31). These exports hand the call to kexnt's implementation. */
#include <windows.h>

static FARPROC kx(const char *name)
{
    HMODULE h = GetModuleHandleA("KEXNT.DLL");
    if (!h) h = LoadLibraryA("KEXNT.DLL");
    return h ? GetProcAddress(h, name) : NULL;
}
#define FWD(ret, fail, name, params, args) \
    ret WINAPI name params { static FARPROC p; if (!p) p = kx("K32" #name); \
        if (!p) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return fail; } return ((ret (WINAPI *) params)(void *)p) args; }

FWD(BOOL, FALSE, GetModuleInformation, (HANDLE a, HMODULE b, LPVOID c, DWORD d), (a, b, c, d))
FWD(DWORD, 0, GetMappedFileNameW, (HANDLE a, LPVOID b, LPWSTR c, DWORD d), (a, b, c, d))
FWD(DWORD, 0, GetMappedFileNameA, (HANDLE a, LPVOID b, LPSTR c, DWORD d), (a, b, c, d))
FWD(BOOL, FALSE, EnumProcessModulesEx, (HANDLE a, HMODULE *b, DWORD c, LPDWORD d, DWORD e), (a, b, c, d, e))
FWD(BOOL, FALSE, GetPerformanceInfo, (LPVOID a, DWORD b), (a, b))
