/* rlc.c - can Windows 98 load two DLLs that share a preferred base when they have NO relocation directory
 * (Microsoft's app-local api-ms-win-*.dll: Characteristics 0x2102, reloc dir 0/0, no code)? -> C:\RLC.LOG.
 * No KexNG marker: this measures the plain Windows 98 (+KernelEx) loader. Args: DLL paths. */
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *f = fopen("C:\\RLC.LOG", "w"); int i; MEMORY_BASIC_INFORMATION m;
    for (i = 1; i < argc; i++) {
        HMODULE h; DWORD e;
        SetLastError(0); h = LoadLibraryA(argv[i]); e = GetLastError();
        fprintf(f, "%s -> %p err %lu\n", argv[i], (void *)h, e);
    }
    VirtualQuery((void *)0x10000000, &m, sizeof(m));
    fprintf(f, "0x10000000: state %lx alloc %p\n", m.State, m.AllocationBase);
    fclose(f); return 0;
}
