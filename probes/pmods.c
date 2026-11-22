/* pmods.c - PMODS.EXE <exe substring> <out>: every module of the matching processes with its full path and base
 * (Toolhelp; Windows 4.0 program). Shows whether a program uses the DLLs it ships or copies from SYSTEM. */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[2], "w"); HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); PROCESSENTRY32 p; p.dwSize = sizeof(p);
    if (argc < 3 || !o) return 1;
    if (Process32First(s, &p)) do {
        char up[MAX_PATH]; HANDLE m; MODULEENTRY32 e;
        lstrcpynA(up, p.szExeFile, MAX_PATH); CharUpperA(up);
        if (!strstr(up, argv[1])) continue;
        fprintf(o, "== %08lx %s\n", p.th32ProcessID, p.szExeFile);
        m = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, p.th32ProcessID); e.dwSize = sizeof(e);
        if (m != INVALID_HANDLE_VALUE && Module32First(m, &e)) do fprintf(o, "%p %s\n", (void *)e.modBaseAddr, e.szExePath); while (Module32Next(m, &e));
        if (m != INVALID_HANDLE_VALUE) CloseHandle(m);
    } while (Process32Next(s, &p));
    fclose(o); return 0;
}
