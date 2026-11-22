/* altdesk.c - ALTDESK.EXE: Chromium's sandbox BrokerServices::CreateAlternateDesktop(kAlternateWinstation) sequence
 * (sandbox/win/src/window.cc), each call's result and error -> C:\ALTDESK.TXT. Runs as a modern program. */
#include <windows.h>
#include <aclapi.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
int main(void)
{
    FILE *o = fopen("C:\\ALTDESK.TXT", "w"); HWINSTA cur, ws; HDESK cd, d; DWORD r, n = 0; PSECURITY_DESCRIPTOR sd = NULL; PACL dacl = NULL;
    WCHAR name[128];
    SetLastError(0); cur = GetProcessWindowStation(); fprintf(o, "GetProcessWindowStation -> %p err %lu\n", cur, GetLastError());
    SetLastError(0); r = GetSecurityInfo(cur, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
    fprintf(o, "GetSecurityInfo(winsta) -> %lu sd %p dacl %p\n", r, sd, dacl);
    SetLastError(0); ws = CreateWindowStationW(NULL, 0, GENERIC_READ | WINSTA_CREATEDESKTOP, NULL);
    fprintf(o, "CreateWindowStationW -> %p err %lu\n", ws, GetLastError());
    SetLastError(0); r = GetUserObjectInformationW(ws ? (HANDLE)ws : (HANDLE)cur, UOI_NAME, name, sizeof(name), &n);
    fprintf(o, "GetUserObjectInformationW(UOI_NAME) -> %lu err %lu len %lu\n", r, GetLastError(), n);
    SetLastError(0); cd = GetThreadDesktop(GetCurrentThreadId()); fprintf(o, "GetThreadDesktop -> %p err %lu\n", cd, GetLastError());
    SetLastError(0); r = SetProcessWindowStation(ws ? ws : cur); fprintf(o, "SetProcessWindowStation(new) -> %lu err %lu\n", r, GetLastError());
    SetLastError(0); d = CreateDesktopW(L"sbox_alternate_desktop_0x1", NULL, NULL, 0, DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | READ_CONTROL | WRITE_DAC | WRITE_OWNER, NULL);
    fprintf(o, "CreateDesktopW -> %p err %lu\n", d, GetLastError());
    SetLastError(0); r = SetProcessWindowStation(cur); fprintf(o, "SetProcessWindowStation(old) -> %lu err %lu\n", r, GetLastError());
    if (d) { sd = NULL; dacl = NULL; r = GetSecurityInfo(d, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
             fprintf(o, "GetSecurityInfo(desktop) -> %lu dacl %p\n", r, dacl);
             r = SetSecurityInfo(d, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, dacl, NULL); fprintf(o, "SetSecurityInfo(desktop) -> %lu\n", r); }
    fclose(o); return 0;
}
