/* peek.c - PEEK.EXE <pid hex> <addr hex> <len hex> <out>: reads another process's memory page by page; logs which
 * pages read and writes the bytes that could be read (unreadable pages as zero) to <out>.bin, a report to <out> */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv)
{
    DWORD pid = strtoul(argv[1], 0, 16), a = strtoul(argv[2], 0, 16), n = strtoul(argv[3], 0, 16), off, got;
    HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); FILE *o = fopen(argv[4], "w"), *b; char bn[MAX_PATH];
    static BYTE pg[4096]; MEMORY_BASIC_INFORMATION m;
    sprintf(bn, "%s.bin", argv[4]); b = fopen(bn, "wb");
    if (!hp) { fprintf(o, "OpenProcess %lu\n", GetLastError()); return 1; }
    for (off = 0; off < n; off += 4096) {
        DWORD pa = (a + off) & ~4095UL; BOOL ok;
        memset(pg, 0, 4096); got = 0;
        ok = ReadProcessMemory(hp, (LPCVOID)pa, pg, 4096, &got);
        if (!ok) { memset(&m, 0, sizeof(m)); VirtualQueryEx(hp, (LPCVOID)pa, &m, sizeof(m));
                   fprintf(o, "%08lx fail %lu state %lx prot %lx base %08lx size %lx\n", pa, GetLastError(), m.State, m.Protect, (DWORD)m.BaseAddress, m.RegionSize); }
        else fprintf(o, "%08lx ok\n", pa);
        fwrite(pg, 1, 4096, b);
    }
    fclose(b); fclose(o); return 0;
}
