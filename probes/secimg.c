/* secimg.c - SECIMG.EXE <pe file>: what CreateFileMapping(PAGE_READONLY | SEC_IMAGE) gives on this system.
 * NT: the view is the IMAGE layout (each section at its RVA, headers at 0). A plain (flat) view has section data at
 * its FILE offset. Compares the first 16 bytes of the first section at RVA vs file offset -> C:\SECIMG.TXT. */
#include <windows.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
int main(int argc, char **argv)
{
    FILE *o = fopen("C:\\SECIMG.TXT", "w"); HANDLE f, m; BYTE *v, hdr[4096]; DWORD got = 0;
    IMAGE_NT_HEADERS32 *nt; IMAGE_SECTION_HEADER *s; BYTE filebytes[16];
    f = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ReadFile(f, hdr, sizeof(hdr), &got, NULL);
    nt = (IMAGE_NT_HEADERS32 *)(hdr + ((IMAGE_DOS_HEADER *)hdr)->e_lfanew); s = IMAGE_FIRST_SECTION(nt);
    SetFilePointer(f, s->PointerToRawData, NULL, FILE_BEGIN); ReadFile(f, filebytes, 16, &got, NULL);
    fprintf(o, "first section %.8s RVA %lx file offset %lx\n", s->Name, s->VirtualAddress, s->PointerToRawData);
    SetLastError(0); m = CreateFileMappingA(f, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    fprintf(o, "CreateFileMapping(SEC_IMAGE) -> %p err %lu\n", m, GetLastError());
    if (m) {
        v = (BYTE *)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
        fprintf(o, "MapViewOfFile -> %p err %lu\n", v, GetLastError());
        if (v && !IsBadReadPtr(v + s->VirtualAddress, 16))
            fprintf(o, "data at RVA %s the section's file bytes -> %s layout\n", memcmp(v + s->VirtualAddress, filebytes, 16) ? "differs from" : "matches",
                    memcmp(v + s->VirtualAddress, filebytes, 16) ? "FLAT (not image)" : "IMAGE");
        if (v && !IsBadReadPtr(v + s->PointerToRawData, 16))
            fprintf(o, "data at file offset %s the section's file bytes\n", memcmp(v + s->PointerToRawData, filebytes, 16) ? "differs from" : "matches");
    }
    fclose(o); return 0;
}
