/* ldl.c - LDL.EXE <out> <dll>...: LoadLibrary each DLL, report base, file it came from / error */
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); int i;
    for (i = 2; i < argc; i++) {
        HMODULE h; char p[MAX_PATH] = ""; SetLastError(0); h = LoadLibraryA(argv[i]);
        if (h) GetModuleFileNameA(h, p, MAX_PATH);
        fprintf(o, "%s -> %p err %lu %s\n", argv[i], h, h ? 0 : GetLastError(), p); fflush(o);
    }
    fclose(o); return 0;
}
