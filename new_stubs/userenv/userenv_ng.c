/* userenv_ng.c - KernelEx-NG build 131: added to KernelEx's userenv.dll (../auxiliary/userenv, unchanged).
 * Google's Chrome standalone setup imports EnterCriticalPolicySection statically; KernelEx's resolver never
 * extends a DLL outside SYSTEM, so kexnt's versions could not reach it. No Group Policy on Windows 98:
 * a private critical section stands in for the policy lock. */
#include <windows.h>
static CRITICAL_SECTION g_cs[2]; static LONG g_init;
HANDLE WINAPI EnterCriticalPolicySection(BOOL machine)
{
    int i = machine ? 1 : 0;
    if (InterlockedExchange(&g_init, 1) == 0) { InitializeCriticalSection(&g_cs[0]); InitializeCriticalSection(&g_cs[1]); g_init = 2; }
    while (g_init != 2) Sleep(1);
    EnterCriticalSection(&g_cs[i]);
    return (HANDLE)&g_cs[i];
}
BOOL WINAPI LeaveCriticalPolicySection(HANDLE h)
{
    if (!h || (h != (HANDLE)&g_cs[0] && h != (HANDLE)&g_cs[1])) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    LeaveCriticalSection((CRITICAL_SECTION *)h);
    return TRUE;
}
