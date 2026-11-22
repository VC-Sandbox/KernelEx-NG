/* fread.c - FREAD.EXE <file> <out>: opens a file the way Qt does (CreateFileW) and logs GetFileType,
 * GetFileSizeEx, and each ReadFile / SetFilePointerEx result, to see where a read loop could stall. NT 5.1 program. */
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    WCHAR w[MAX_PATH]; HANDLE h; FILE *o = fopen(argv[2], "w"); LARGE_INTEGER sz, np, z; DWORD got, i; static char buf[16384]; BOOL r;
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, w, MAX_PATH);
    h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    fprintf(o, "CreateFileW %p err %lu type %lu\n", h, GetLastError(), GetFileType(h));
    sz.QuadPart = -1; r = GetFileSizeEx(h, &sz); fprintf(o, "GetFileSizeEx %d %I64d err %lu\n", r, sz.QuadPart, GetLastError());
    for (i = 0; i < 6; i++) {
        z.QuadPart = 0; np.QuadPart = -1; SetFilePointerEx(h, z, &np, FILE_CURRENT);
        got = 12345; r = ReadFile(h, buf, sizeof(buf), &got, NULL);
        fprintf(o, "read %lu: ret %d got %lu err %lu pos before %I64d\n", i, r, got, GetLastError(), np.QuadPart);
    }
    z.QuadPart = 10; r = SetFilePointerEx(h, z, &np, FILE_BEGIN); fprintf(o, "seek 10: %d new %I64d\n", r, np.QuadPart);
    got = 0; r = ReadFile(h, buf, 5, &got, NULL); fprintf(o, "read 5: %d got %lu '%.5s'\n", r, got, buf);
    z.QuadPart = 0; r = SetFilePointerEx(h, z, &np, FILE_CURRENT); fprintf(o, "pos now %I64d\n", np.QuadPart);
    fclose(o); return 0;
}
