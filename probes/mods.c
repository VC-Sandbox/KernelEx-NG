/* mods.c - MODS.EXE <out>: every process and whether KEXNT.DLL is loaded in it (Toolhelp; Windows 4.0 program) */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); PROCESSENTRY32 p; p.dwSize = sizeof(p);
    if (Process32First(s, &p)) do {
        HANDLE m = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, p.th32ProcessID); MODULEENTRY32 e; int k = 0; e.dwSize = sizeof(e);
        if (m != INVALID_HANDLE_VALUE && Module32First(m, &e)) do { if (!lstrcmpiA(e.szModule, "KEXNT.DLL")) k = 1; } while (Module32Next(m, &e));
        if (m != INVALID_HANDLE_VALUE) CloseHandle(m);
        fprintf(o, "%08lx kexnt %d %s\n", p.th32ProcessID, k, p.szExeFile);
    } while (Process32Next(s, &p));
    fclose(o); return 0;
}
