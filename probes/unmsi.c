/* unmsi.c - UNMSI.EXE {ProductCode}...: uninstall products through Windows Installer from a MODERN process (kexnt
 * active, so custom actions run as they do under the product's own setup engine; msiexec.exe is a Windows 98 program).
 * Result per product -> C:\UNMSI.TXT */
#include <windows.h>
#include <msi.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
int main(int argc, char **argv)
{
    FILE *o = fopen("C:\\UNMSI.TXT", "w"); int i;
    MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);
    for (i = 1; i < argc; i++) { UINT r = MsiConfigureProductA(argv[i], INSTALLLEVEL_DEFAULT, INSTALLSTATE_ABSENT); fprintf(o, "%s -> %u\n", argv[i], r); fflush(o); }
    fclose(o); return 0;
}
