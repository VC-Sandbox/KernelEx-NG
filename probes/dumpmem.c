/* dumpmem.c - DUMPMEM.EXE <pid hex> <address hex> <length hex> <out file>: raw copy of another process's memory */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv)
{
    DWORD pid, a, n, got = 0, off; HANDLE hp; FILE *o; static BYTE b[4096];
    if (argc < 5) return 1;
    pid = strtoul(argv[1], 0, 16); a = strtoul(argv[2], 0, 16); n = strtoul(argv[3], 0, 16);
    hp = OpenProcess(PROCESS_VM_READ, FALSE, pid); if (!hp) return 2;
    o = fopen(argv[4], "wb"); if (!o) return 3;
    for (off = 0; off < n; off += 4096) {
        memset(b, 0, sizeof(b));
        ReadProcessMemory(hp, (LPCVOID)(a + off), b, 4096, &got);
        fwrite(b, 1, 4096, o);
    }
    fclose(o); return 0;
}
