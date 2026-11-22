/* fmsg.c - FMSG.EXE <out>: FormatMessageW with FROM_STRING + ALLOCATE_BUFFER and printf-style inserts, as
 * Visual Studio 2010's SetupUi.dll uses it (it treats any last error as failure). NT 5.1 program. */
#include <windows.h>
#include <stdio.h>
static void t(FILE *o, const WCHAR *fmt, ...)
{
    va_list a; WCHAR *buf = NULL; DWORD r, le;
    va_start(a, fmt); SetLastError(0);
    r = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING, fmt, 0, 0, (LPWSTR)&buf, 0, &a);
    le = GetLastError(); va_end(a);
    fprintf(o, "fmt '%ls': ret %lu err %lu -> '%ls'\n", fmt, r, le, buf ? buf : L"(null)");
    if (buf) LocalFree(buf);
}
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); ULONGLONG big = 12345678901ULL;
    t(o, L"plain text");
    t(o, L"x %1 y", L"str");
    t(o, L"n=%1!u!", 42u);
    t(o, L"n=%1!I64u! KB", big);
    t(o, L"%1!s! has %2!I64u! bytes", L"C:", big);
    t(o, L"w=%1!d! h=%2!d!", 3, 4);
    fclose(o); return 0;
}
