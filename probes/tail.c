/* tail.c - copy the last N bytes of a file (big logs from the VM without uploading all of them). TAIL.EXE in out N */
#include <windows.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    HANDLE i, o; DWORD sz, n, got, w; static char buf[65536];
    if (argc < 4) return 1;
    i = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (i == INVALID_HANDLE_VALUE) return 2;
    o = CreateFileA(argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (o == INVALID_HANDLE_VALUE) return 3;
    sz = GetFileSize(i, NULL); n = (DWORD)atol(argv[3]); if (n > sz) n = sz;
    SetFilePointer(i, (LONG)(sz - n), NULL, FILE_BEGIN);
    while (ReadFile(i, buf, sizeof(buf), &got, NULL) && got) WriteFile(o, buf, got, &w, NULL);
    CloseHandle(i); CloseHandle(o);
    return 0;
}
