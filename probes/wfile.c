/* wfile.c - WFILE.EXE: W file APIs on the .NET 4 runtime folder (what the shim uses to find a runtime) -> C:\WFILE.TXT */
#include <windows.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
int main(void)
{
    static const WCHAR *paths[] = { L"C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319", L"C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\",
        L"C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\clr.dll", L"C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\mscorlib.dll",
        L"C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\mscoreei.dll" };
    FILE *o = fopen("C:\\WFILE.TXT", "w"); int i;
    for (i = 0; i < 5; i++) {
        WIN32_FIND_DATAW fd; WIN32_FILE_ATTRIBUTE_DATA ad; HANDLE h; DWORD a; BOOL x;
        SetLastError(0); a = GetFileAttributesW(paths[i]); fprintf(o, "[%d] GetFileAttributesW %lx err %lu", i, a, GetLastError());
        SetLastError(0); x = GetFileAttributesExW(paths[i], GetFileExInfoStandard, &ad); fprintf(o, " | ExW %d attr %lx err %lu", x, x ? ad.dwFileAttributes : 0, GetLastError());
        SetLastError(0); h = FindFirstFileW(paths[i], &fd); fprintf(o, " | FindFirstFileW %p err %lu\n", h, GetLastError()); if (h != INVALID_HANDLE_VALUE) FindClose(h);
    }
    {   WCHAR buf[MAX_PATH]; DWORD n = sizeof(buf); HKEY k; LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\.NETFramework", 0, KEY_READ, &k);
        fprintf(o, "RegOpenKeyExW %ld", r);
        if (!r) { DWORD t; r = RegQueryValueExW(k, L"InstallRoot", NULL, &t, (BYTE *)buf, &n); fprintf(o, " | InstallRoot %ld type %lu len %lu '%ls'", r, t, n, r ? L"" : buf); RegCloseKey(k); }
        fprintf(o, "\n");
    }
    fclose(o); return 0;
}
