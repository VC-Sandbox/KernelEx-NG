/* secres.c - probe: NT's reserve-then-commit file mapping (WPF font cache: CreateFileMapping SEC_RESERVE,
 * MapViewOfFile, VirtualAlloc(view, MEM_COMMIT)) on Windows 98. SECRES.EXE > out.txt */
#include <windows.h>
#include <stdio.h>
static int tryw(BYTE *p) { if (IsBadWritePtr(p, 1)) return -1; *p = 0x5A; return *p == 0x5A; }
static void t(DWORD flags, const char *what)
{
    HANDLE m = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | flags, 0, 8 << 20, NULL);
    BYTE *v; void *c; MEMORY_BASIC_INFORMATION mb;
    printf("%s: mapping %p err %lu\n", what, (void *)m, GetLastError());
    if (!m) return;
    v = (BYTE *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    printf("  view %p err %lu\n", (void *)v, GetLastError());
    if (!v) { CloseHandle(m); return; }
    VirtualQuery(v, &mb, sizeof(mb)); printf("  query state %lx protect %lx type %lx region %lx\n", mb.State, mb.Protect, mb.Type, (DWORD)mb.RegionSize);
    SetLastError(0); c = VirtualAlloc(v, 65536, MEM_COMMIT, PAGE_READWRITE);
    printf("  VirtualAlloc commit 64K -> %p err %lu\n", c, GetLastError());
    printf("  write first page -> %d, write at 4 MB -> %d\n", tryw(v), tryw(v + (4 << 20)));
    UnmapViewOfFile(v); CloseHandle(m);
}
int main(void) { t(SEC_RESERVE, "SEC_RESERVE"); t(SEC_COMMIT, "SEC_COMMIT"); return 0; }
