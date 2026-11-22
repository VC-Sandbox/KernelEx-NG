/* relocmem.c - RELOCMEM.EXE <exe>: is the .reloc (discardable) section of the process's own EXE still in memory on
 * this system? Compares the first bytes of the base-relocation directory in memory with the file -> C:\RELOCMEM.TXT */
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *o = fopen("C:\\RELOCMEM.TXT", "w"); BYTE *b = (BYTE *)GetModuleHandleA(NULL);
    IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[5].VirtualAddress, sz = nt->OptionalHeader.DataDirectory[5].Size;
    MEMORY_BASIC_INFORMATION m; int i; IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
    fprintf(o, "base %p reloc rva %lx size %lx\n", b, rva, sz);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) fprintf(o, "section %.8s rva %lx chars %08lx\n", s[i].Name, s[i].VirtualAddress, s[i].Characteristics);
    if (rva) {
        VirtualQuery(b + rva, &m, sizeof(m));
        fprintf(o, "VirtualQuery: state %lx protect %lx type %lx\n", m.State, m.Protect, m.Type);
        if (!IsBadReadPtr(b + rva, 8)) fprintf(o, "in memory: %08lx %08lx\n", ((DWORD *)(b + rva))[0], ((DWORD *)(b + rva))[1]);
        else fprintf(o, "in memory: NOT READABLE\n");
    }
    fclose(o); return 0;
}
