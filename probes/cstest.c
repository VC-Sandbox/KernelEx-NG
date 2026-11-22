/* cstest.c - CSTEST.EXE: TryEnterCriticalSection & co. as a modern program sees them -> C:\CSTEST.TXT */
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
int main(void)
{
    FILE *o = fopen("C:\\CSTEST.TXT", "w"); CRITICAL_SECTION cs, cs2; BOOL r; DWORD t0; int i, ok = 0;
    InitializeCriticalSection(&cs);
    r = TryEnterCriticalSection(&cs); fprintf(o, "TryEnter on a free CS -> %d\n", r);
    if (r) { r = TryEnterCriticalSection(&cs); fprintf(o, "TryEnter again (recursive, same thread) -> %d\n", r); if (r) LeaveCriticalSection(&cs); LeaveCriticalSection(&cs); }
    r = InitializeCriticalSectionAndSpinCount(&cs2, 4000); fprintf(o, "InitializeCriticalSectionAndSpinCount -> %d\n", r);
    r = TryEnterCriticalSection(&cs2); fprintf(o, "TryEnter on spin-count CS -> %d\n", r); if (r) LeaveCriticalSection(&cs2);
    t0 = GetTickCount(); for (i = 0; i < 100000; i++) if (TryEnterCriticalSection(&cs)) { ok++; LeaveCriticalSection(&cs); }
    fprintf(o, "100000 TryEnter/Leave: %d succeeded, %lu ms\n", ok, GetTickCount() - t0);
    t0 = GetTickCount(); for (i = 0; i < 100000; i++) { EnterCriticalSection(&cs); LeaveCriticalSection(&cs); }
    fprintf(o, "100000 Enter/Leave: %lu ms\n", GetTickCount() - t0);
    fclose(o); return 0;
}
