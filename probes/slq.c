/* slq.c - which interfaces Windows 98's ShellLink object answers (Inno Setup 6 casts to IShellLinkW, IPersistFile,
 * IPropertyStore) -> C:\SLQ.LOG. Modern program for kexnt's gate. */
#include <windows.h>
#include <objbase.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
int main(void)
{
    static const GUID clsid = {0x00021401,0,0,{0xC0,0,0,0,0,0,0,0x46}};
    static const struct { const char *n; GUID g; } q[] = {
        { "IShellLinkA", {0x000214EE,0,0,{0xC0,0,0,0,0,0,0,0x46}} }, { "IShellLinkW", {0x000214F9,0,0,{0xC0,0,0,0,0,0,0,0x46}} },
        { "IPersistFile", {0x0000010B,0,0,{0xC0,0,0,0,0,0,0,0x46}} },
        { "IPropertyStore", {0x886D8EEB,0x8CF2,0x4446,{0x8D,0x02,0xCD,0xBA,0x1D,0xBD,0xCF,0x99}} },
        { "IShellLinkDataList", {0x45E2B4AE,0xB1C3,0x11D0,{0xB9,0x2F,0x00,0xA0,0xC9,0x03,0x12,0xE1}} } };
    FILE *f = fopen("C:\\SLQ.LOG", "w"); IUnknown *u = NULL; HRESULT hr; int i;
    CoInitialize(NULL);
    hr = CoCreateInstance(&clsid, NULL, CLSCTX_INPROC_SERVER, &IID_IUnknown, (void **)&u);
    fprintf(f, "CoCreateInstance(ShellLink) %08lx\n", (unsigned long)hr);
    for (i = 0; u && i < 5; i++) { void *p = NULL; hr = u->lpVtbl->QueryInterface(u, &q[i].g, &p); fprintf(f, "  %-20s %08lx\n", q[i].n, (unsigned long)hr); if (p) ((IUnknown *)p)->lpVtbl->Release((IUnknown *)p); }
    fclose(f); return 0;
}
