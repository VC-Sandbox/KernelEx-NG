/* lpath.c - LPATH.EXE <out>: how "\\?\" long-path names behave through KernelEx/kexnt (NT 5.1 program) */
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); WIN32_FILE_ATTRIBUTE_DATA ad; WIN32_FIND_DATAW fd; HANDLE h; DWORD r; WCHAR full[MAX_PATH], *fp;
    const WCHAR *f = L"\\\\?\\C:\\WINDOWS\\WIN.INI", *d = L"\\\\?\\C:\\KXLP_DIR", *t1 = L"\\\\?\\C:\\KXLP1.TXT", *t2 = L"\\\\?\\C:\\KXLP2.TXT";
    SetLastError(0); r = GetFileAttributesW(f); fprintf(o, "GetFileAttributesW %lx err %lu\n", r, GetLastError());
    SetLastError(0); r = GetFileAttributesExW(f, GetFileExInfoStandard, &ad); fprintf(o, "GetFileAttributesExW %lu err %lu size %lu\n", r, GetLastError(), ad.nFileSizeLow);
    SetLastError(0); h = FindFirstFileW(f, &fd); fprintf(o, "FindFirstFileW %p err %lu\n", h, GetLastError()); if (h != INVALID_HANDLE_VALUE) FindClose(h);
    SetLastError(0); r = CreateDirectoryW(d, NULL); fprintf(o, "CreateDirectoryW %lu err %lu attr-plain %lx\n", r, GetLastError(), GetFileAttributesA("C:\\KXLP_DIR"));
    SetLastError(0); r = RemoveDirectoryW(d); fprintf(o, "RemoveDirectoryW %lu err %lu\n", r, GetLastError()); RemoveDirectoryA("C:\\KXLP_DIR");
    h = CreateFileW(t1, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL); fprintf(o, "CreateFileW create %p err %lu type %lu plain-attr %lx\n", h, GetLastError(), GetFileType(h), GetFileAttributesA("C:\\KXLP1.TXT"));
    if (h != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(h, "abc", 3, &w, NULL); CloseHandle(h); }
    SetLastError(0); r = MoveFileW(t1, t2); fprintf(o, "MoveFileW %lu err %lu plain2 %lx\n", r, GetLastError(), GetFileAttributesA("C:\\KXLP2.TXT"));
    SetLastError(0); r = DeleteFileW(t2); fprintf(o, "DeleteFileW %lu err %lu\n", r, GetLastError()); DeleteFileA("C:\\KXLP1.TXT"); DeleteFileA("C:\\KXLP2.TXT");
    SetLastError(0); r = GetFullPathNameW(f, MAX_PATH, full, &fp); fprintf(o, "GetFullPathNameW %lu err %lu '%ls'\n", r, GetLastError(), r ? full : L"");
    fclose(o); return 0;
}
