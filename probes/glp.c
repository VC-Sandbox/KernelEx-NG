/* glp.c - GLP.EXE <out>: GetLongPathNameW/A, GetShortPathNameW, SHGetFolderPathW, registry ProgramFilesDir (W) */
#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
typedef DWORD (WINAPI *T_GLPW)(LPCWSTR, LPWSTR, DWORD);
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); static const WCHAR *p[] = { L"C:\\Program Files\\Mozilla Firefox\\", L"C:\\Program Files\\Mozilla Firefox",
        L"C:\\PROGRA~1\\MOZILL~1\\", L"C:\\Program Files\\", L"C:\\Program Files", L"C:\\Program Files\\NoSuchDir\\", L"C:\\" };
    WCHAR b[MAX_PATH]; char a[MAX_PATH]; int i; DWORD r; HKEY k;
    T_GLPW g = (T_GLPW)(void *)GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "GetLongPathNameW");
    for (i = 0; i < 7; i++) {
        b[0] = 0; SetLastError(0); r = g ? g(p[i], b, MAX_PATH) : 12345;
        WideCharToMultiByte(CP_ACP, 0, p[i], -1, a, MAX_PATH, 0, 0);
        fprintf(o, "GetLongPathNameW(%s) -> %lu err %lu ", a, r, GetLastError());
        WideCharToMultiByte(CP_ACP, 0, b, -1, a, MAX_PATH, 0, 0); fprintf(o, "\"%s\"\n", a);
        b[0] = 0; SetLastError(0); r = GetShortPathNameW(p[i], b, MAX_PATH);
        WideCharToMultiByte(CP_ACP, 0, b, -1, a, MAX_PATH, 0, 0); fprintf(o, "   GetShortPathNameW -> %lu err %lu \"%s\"\n", r, GetLastError(), a);
    }
    b[0] = 0; r = SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, 0, b);
    WideCharToMultiByte(CP_ACP, 0, b, -1, a, MAX_PATH, 0, 0); fprintf(o, "SHGetFolderPathW(PROGRAM_FILES) -> %08lx \"%s\"\n", r, a);
    {   LPITEMIDLIST pidl = NULL; HRESULT h = SHGetSpecialFolderLocation(NULL, CSIDL_PROGRAM_FILES, &pidl); BOOL ok = FALSE;
        b[0] = 0x55; b[1] = 0; if (h == 0 && pidl) ok = SHGetPathFromIDListW(pidl, b);
        WideCharToMultiByte(CP_ACP, 0, b, -1, a, MAX_PATH, 0, 0); fprintf(o, "SHGetSpecialFolderLocation(0x26) -> %08lx pidl %p, SHGetPathFromIDListW %d \"%s\"\n", h, (void *)pidl, ok, a);
        b[0] = 0; ok = SHGetSpecialFolderPathW(NULL, b, CSIDL_PROGRAM_FILES, FALSE);
        WideCharToMultiByte(CP_ACP, 0, b, -1, a, MAX_PATH, 0, 0); fprintf(o, "SHGetSpecialFolderPathW(0x26) -> %d \"%s\"\n", ok, a);
        b[0] = 0; ok = SHGetSpecialFolderPathW(NULL, b, CSIDL_APPDATA, FALSE);
        WideCharToMultiByte(CP_ACP, 0, b, -1, a, MAX_PATH, 0, 0); fprintf(o, "SHGetSpecialFolderPathW(APPDATA) -> %d \"%s\"\n", ok, a);
        b[0] = 0; h = SHGetSpecialFolderLocation(NULL, CSIDL_PROGRAM_FILES_COMMON, &pidl); ok = h == 0 && SHGetPathFromIDListW(pidl, b);
        WideCharToMultiByte(CP_ACP, 0, b, -1, a, MAX_PATH, 0, 0); fprintf(o, "SHGetSpecialFolderLocation(COMMONFILES) -> %08lx %d \"%s\"\n", h, ok, a);
    }
    {   typedef HRESULT (WINAPI *T_SGFP)(HWND, int, HANDLE, DWORD, LPWSTR); HMODULE sf = LoadLibraryA("SHFOLDER.DLL");
        T_SGFP f = sf ? (T_SGFP)(void *)GetProcAddress(sf, "SHGetFolderPathW") : NULL; HRESULT h; char mp[MAX_PATH] = "";
        if (sf) GetModuleFileNameA(sf, mp, MAX_PATH);
        fprintf(o, "SHFOLDER %p %s SHGetFolderPathW %p\n", (void *)sf, mp, (void *)f);
        if (f) { int c[] = { 0x8026, 0x802b, 0x801a, 0x8023, 0x8024, 0x801c, 0x802a }; int j;
          for (j = 0; j < 7; j++) { b[0] = 0x55; b[1] = 0; h = f(NULL, c[j], NULL, 0, b);
            WideCharToMultiByte(CP_ACP, 0, b, -1, a, MAX_PATH, 0, 0); fprintf(o, "  shfolder SHGetFolderPathW(%02x) -> %08lx \"%s\"\n", c[j], h, a); } }
    }
    {   static const WCHAR *q[] = { L"C:\\Program Files\\Mozilla Firefox", L"C:\\Program Files\\Mozilla Firefox\\", L"C:\\PROGRA~1\\MOZILL~1\\firefox.exe", L"C:\\" }; int j;
        for (j = 0; j < 4; j++) { WCHAR *fp = (WCHAR *)1; DWORD rr; b[0] = 0; rr = GetFullPathNameW(q[j], MAX_PATH, b, &fp);
          WideCharToMultiByte(CP_ACP, 0, b, -1, a, MAX_PATH, 0, 0);
          fprintf(o, "GetFullPathNameW -> %lu \"%s\" filepart %p (buffer %p, offset %d)\n", rr, a, (void *)fp, (void *)b, fp && fp != (WCHAR *)1 ? (int)(fp - b) : -1); }
    }
    {   DWORD sams[] = { KEY_READ, KEY_READ | 0x100, KEY_READ | 0x200, KEY_QUERY_VALUE | 0x200 }; int j;
        for (j = 0; j < 4; j++) { HKEY kk; LONG rr = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion", 0, sams[j], &kk);
          fprintf(o, "RegOpenKeyExW sam %08lx -> %ld\n", sams[j], rr); if (!rr) RegCloseKey(kk);
          rr = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion", 0, sams[j], &kk);
          fprintf(o, "RegOpenKeyExA sam %08lx -> %ld\n", sams[j], rr); if (!rr) RegCloseKey(kk); }
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion", 0, KEY_READ, &k) == 0) {
        DWORD t, n = sizeof(b); b[0] = 0; r = RegQueryValueExW(k, L"ProgramFilesDir", NULL, &t, (BYTE *)b, &n);
        WideCharToMultiByte(CP_ACP, 0, b, -1, a, MAX_PATH, 0, 0); fprintf(o, "RegQueryValueExW(ProgramFilesDir) -> %lu type %lu n %lu \"%s\"\n", r, t, n, a);
        RegCloseKey(k);
    } else fprintf(o, "RegOpenKeyExW failed\n");
    fclose(o); return 0;
}
