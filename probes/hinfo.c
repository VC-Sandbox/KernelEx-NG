/* hinfo.c - HINFO.EXE <pid hex> <handle hex> <out> [times] [ms]: duplicates another process's handle and logs its
 * file type, size, current file position (shared with the owner) and file index, several times. Win95 program. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv)
{
    DWORD pid = strtoul(argv[1], 0, 16), hv = strtoul(argv[2], 0, 16); int n = argc > 4 ? atoi(argv[4]) : 1, ms = argc > 5 ? atoi(argv[5]) : 1000, i;
    FILE *o = fopen(argv[3], "w"); HANDLE hp = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid), h = NULL;
    if (!o) return 1;
    if (!hp || !DuplicateHandle(hp, (HANDLE)hv, GetCurrentProcess(), &h, 0, FALSE, DUPLICATE_SAME_ACCESS)) { fprintf(o, "dup failed %lu\n", GetLastError()); return 2; }
    for (i = 0; i < n; i++) {
        BY_HANDLE_FILE_INFORMATION fi; DWORD pos = SetFilePointer(h, 0, NULL, FILE_CURRENT);
        memset(&fi, 0, sizeof(fi)); GetFileInformationByHandle(h, &fi);
        fprintf(o, "%d type %lu size %lu pos %lu attr %lx vol %08lx index %08lx:%08lx tick %lu\n", i, GetFileType(h), GetFileSize(h, NULL), pos,
                fi.dwFileAttributes, fi.dwVolumeSerialNumber, fi.nFileIndexHigh, fi.nFileIndexLow, GetTickCount());
        fflush(o); if (i + 1 < n) Sleep(ms);
    }
    return 0;
}
