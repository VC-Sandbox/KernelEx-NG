/* sdbread.c - probe: does a UTF-16 INF (the .NET 3.5 setup's setup.sdb) read through the W profile functions?
 * SDBREAD.EXE out.txt file.sdb   (subsystem 5.0, so kexnt treats it as a modern program like SETUP.EXE) */
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    WCHAR f[MAX_PATH], b[4096]; DWORD n, i; FILE *o;
    if (argc < 3 || !(o = fopen(argv[1], "w"))) return 1;
    MultiByteToWideChar(CP_ACP, 0, argv[2], -1, f, MAX_PATH);
    SetLastError(0);
    n = GetPrivateProfileStringW(L"Version", L"Signature", L"<default>", b, 4096, f);
    fprintf(o, "StringW Version/Signature: %lu chars, err %lu: %ls\n", n, GetLastError(), b);
    SetLastError(0);
    n = GetPrivateProfileStringW(L"Version", L"Provider", L"<default>", b, 4096, f);
    fprintf(o, "StringW Version/Provider: %lu chars, err %lu: %ls\n", n, GetLastError(), b);
    SetLastError(0);
    n = GetPrivateProfileSectionW(L"Version", b, 4096, f);
    fprintf(o, "SectionW Version: %lu chars, err %lu:", n, GetLastError());
    for (i = 0; i < n && i < 400; i++) fputc(b[i] ? (b[i] < 128 ? (char)b[i] : '?') : '|', o);
    fprintf(o, "\n");
    SetLastError(0);
    n = GetPrivateProfileStringW(NULL, NULL, L"", b, 4096, f);
    fprintf(o, "StringW section list: %lu chars, err %lu\n", n, GetLastError());
    fclose(o);
    return 0;
}
