/* dwf.c - DWF.EXE <DWrite.dll path>: DWriteCreateFactory + GetSystemFontCollection through a program's own DWrite.dll
 * (Supermium's DWriteCore) -> C:\DWF.TXT. Modern program. */
#include <windows.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
static const GUID IID_IDWriteFactory = {0xb859ee5a, 0xd838, 0x4b5b, {0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48}};
typedef HRESULT (WINAPI *T_DWCF)(int, const GUID *, void **);
int main(int argc, char **argv)
{
    FILE *o = fopen("C:\\DWF.TXT", "w"); HMODULE h; T_DWCF cf; void *f = NULL, *coll = NULL; HRESULT hr;
    h = LoadLibraryExA(argc > 1 ? argv[1] : "DWrite.dll", NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    fprintf(o, "LoadLibrary -> %p err %lu\n", (void *)h, GetLastError()); fflush(o);
    if (!h) return 1;
    cf = (T_DWCF)GetProcAddress(h, "DWriteCreateFactory");
    hr = cf ? cf(0, &IID_IDWriteFactory, &f) : -1; fprintf(o, "DWriteCreateFactory -> %08lx %p\n", hr, f); fflush(o);
    if (f) {
        HRESULT (WINAPI *gsfc)(void *, void **, BOOL) = (*(HRESULT (WINAPI ***)(void *, void **, BOOL))f)[3];
        hr = gsfc(f, &coll, FALSE); fprintf(o, "GetSystemFontCollection -> %08lx %p\n", hr, coll); fflush(o);
        if (coll) { UINT32 (WINAPI *cnt)(void *) = (*(UINT32 (WINAPI ***)(void *))coll)[3]; fprintf(o, "families %u\n", cnt(coll)); }
        {   /* each font file named after the DLL: CreateFontFileReference + IDWriteFontFile::Analyze */
            int i;
            for (i = 2; i < argc; i++) {
                WCHAR w[MAX_PATH]; void *ff = NULL; BOOL sup = 0; int ft = 0, fct = 0; UINT32 nf = 0;
                HRESULT (WINAPI *cffr)(void *, const WCHAR *, const FILETIME *, void **) = (*(HRESULT (WINAPI ***)(void *, const WCHAR *, const FILETIME *, void **))f)[7];
                MultiByteToWideChar(CP_ACP, 0, argv[i], -1, w, MAX_PATH);
                hr = cffr(f, w, NULL, &ff);
                fprintf(o, "%s: CreateFontFileReference %08lx", argv[i], hr);
                if (ff) { HRESULT (WINAPI *an)(void *, BOOL *, int *, int *, UINT32 *) = (*(HRESULT (WINAPI ***)(void *, BOOL *, int *, int *, UINT32 *))ff)[5];
                          hr = an(ff, &sup, &ft, &fct, &nf); fprintf(o, " Analyze %08lx supported %d type %d faces %u", hr, sup, ft, nf); }
                fprintf(o, "\n"); fflush(o);
            }
        }
    }
    fclose(o); return 0;
}
