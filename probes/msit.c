/* msit.c - MSIT.EXE <out> <msp> <msi>: Windows Installer calls on a patch / package through kexnt (NT 5.1 program) */
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); WCHAR msp[MAX_PATH], msi[MAX_PATH], cmd[600]; MSIHANDLE h = 0, si = 0; UINT r; INT iv; FILETIME ft; DWORD n = 0;
    MultiByteToWideChar(CP_ACP, 0, argv[2], -1, msp, MAX_PATH); MultiByteToWideChar(CP_ACP, 0, argv[3], -1, msi, MAX_PATH);
    r = MsiGetSummaryInformationW(0, msp, 0, &si); fprintf(o, "summary(msp) %u\n", r);
    if (!r) { UINT t; MsiSummaryInfoGetPropertyW(si, 15, &t, &iv, &ft, NULL, &n); fprintf(o, "  wordcount %d\n", iv); MsiCloseHandle(si); }
    r = MsiOpenDatabaseW(msp, (LPCWSTR)(ULONG_PTR)32, &h); fprintf(o, "open msp as patch %u\n", r); if (!r) MsiCloseHandle(h);
    MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);
    MsiEnableLogW(INSTALLLOGMODE_VERBOSE, L"C:\\VC10\\MSIT.LOG", 0);
    wsprintfW(cmd, L"PATCH=\"%s\" REBOOT=ReallySuppress", msp);
    r = MsiInstallProductW(msi, cmd); fprintf(o, "install msi+patch %u\n", r);
    fclose(o); return 0;
}
