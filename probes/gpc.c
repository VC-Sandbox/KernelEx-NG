/* gpc.c - GetProcAddress(GetModuleHandle("comctl32.dll"), name) as Inno Setup does -> C:\GPC.LOG */
#include <windows.h>
#include <stdio.h>
#include <commctrl.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
int main(int argc, char **argv)
{
    FILE *f = fopen("C:\\GPC.LOG", "w"); HMODULE h; const char *n = argc > 1 ? argv[1] : "TaskDialogIndirect";
    InitCommonControls();
    h = GetModuleHandleA("comctl32.dll");
    fprintf(f, "comctl32 %p  %s -> %p\n", (void *)h, n, h ? (void *)GetProcAddress(h, n) : NULL);
    h = LoadLibraryA("comctl32.dll");
    fprintf(f, "LoadLibrary comctl32 %p  %s -> %p\n", (void *)h, n, h ? (void *)GetProcAddress(h, n) : NULL);
    fclose(f); return 0;
}
