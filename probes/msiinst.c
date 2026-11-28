/* msiinst.c - install a package with MsiInstallProductW from a modern (subsystem 5.0) process, so kexnt's msicompat
 * applies (converted copy, XP launch conditions). MSIINST.EXE out.txt package.msi [command line]   |   MSIINST.EXE out.txt {product code}  (removes it) */
#include <windows.h>
#include <msi.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    WCHAR p[MAX_PATH], c[1024] = L""; UINT r; FILE *o = fopen(argv[1], "w");
    MultiByteToWideChar(CP_ACP, 0, argv[2], -1, p, MAX_PATH);
    if (argc > 3) MultiByteToWideChar(CP_ACP, 0, argv[3], -1, c, 1024);
    MsiSetInternalUI(INSTALLUILEVEL_BASIC, NULL);
    MsiEnableLogW(INSTALLLOGMODE_VERBOSE, L"C:\\MSIINST.LOG", 0);
    if (p[0] == L'{') r = MsiConfigureProductW(p, INSTALLLEVEL_DEFAULT, INSTALLSTATE_ABSENT);   /* product code: remove it */
    else r = MsiInstallProductW(p, c);
    if (o) { fprintf(o, "MsiInstallProductW %s: %u\n", argv[2], r); fclose(o); }
    return (int)r;
}
