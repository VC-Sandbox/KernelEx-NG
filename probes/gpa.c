/* gpa.c - GPA.EXE <listfile> <outfile>: for each line "DLL NAME" prints whether GetProcAddress finds it
 * (through KernelEx's resolver, under this exe's KernelEx settings). Built as an NT 5.1 program. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
    char dll[128], name[256]; FILE *f = fopen(argv[1], "r"), *o = fopen(argv[2], "w");
    if (!f || !o) return 1;
    while (fscanf(f, "%127s %255s", dll, name) == 2) {
        HMODULE h = LoadLibraryA(dll); FARPROC p = h ? GetProcAddress(h, name) : NULL;
        fprintf(o, "%s %s %s %p\n", p ? "OK  " : (h ? "MISS" : "NODLL"), dll, name, (void *)p);
    }
    fclose(o); return 0;
}
