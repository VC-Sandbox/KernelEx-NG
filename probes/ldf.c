/* ldf.c - LDF.EXE <out> <dll> [free]: LoadLibrary, then FreeLibrary, flushing a line before/after each step (subsystem 6.0) */
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); HMODULE h; char p[MAX_PATH] = "";
    fprintf(o, "load %s\n", argv[2]); fflush(o);
    h = LoadLibraryA(argv[2]); if (h) GetModuleFileNameA(h, p, MAX_PATH);
    fprintf(o, " -> %p err %lu %s\n", (void *)h, h ? 0 : GetLastError(), p); fflush(o);
    if (h && argc > 3) { fprintf(o, "free\n"); fflush(o); fprintf(o, " -> %d\n", FreeLibrary(h)); fflush(o); }
    fprintf(o, "exit\n"); fclose(o); return 0;
}
