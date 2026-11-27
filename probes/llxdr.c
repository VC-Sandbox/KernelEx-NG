/* llxdr.c - probe: LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES [| LOAD_WITH_ALTERED_SEARCH_PATH]) of a DLL on Windows 98.
 * The .NET 2.0 runtime loads mscorlib.dll with flags 9 and got error 1114 ("a DllMain returned FALSE").
 * LLXDR.EXE out.txt dll...   (subsystem 5.0: kexnt serves it, like the runtime's process) */
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    static const DWORD fl[] = { 1, 9, 2, 0 }; FILE *o; int i, k;
    if (argc < 3 || !(o = fopen(argv[1], "w"))) return 1;
    for (i = 2; i < argc; i++)
        for (k = 0; k < 4; k++) {
            HMODULE h; SetLastError(0);
            h = LoadLibraryExA(argv[i], NULL, fl[k]);
            fprintf(o, "%s flags %lu: %p error %lu\n", argv[i], fl[k], (void *)h, h ? 0 : GetLastError());
            fflush(o);
            if (h) FreeLibrary(h);
        }
    fclose(o);
    return 0;
}
