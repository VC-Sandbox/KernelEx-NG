/* dirl.c - DIRL.EXE <pattern> <out>: file names and sizes matching a pattern (the agent has no dir command) */
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    WIN32_FIND_DATAA fd; HANDLE h; FILE *o;
    if (argc < 3 || !(o = fopen(argv[2], "w"))) return 1;
    if ((h = FindFirstFileA(argv[1], &fd)) != INVALID_HANDLE_VALUE) {
        do fprintf(o, "%10lu %s\n", fd.nFileSizeLow, fd.cFileName); while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    fclose(o); return 0;
}
