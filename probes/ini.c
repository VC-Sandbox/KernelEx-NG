/* ini.c - INI.EXE <out> [modern]: what GetPrivateProfileStringW (through KernelEx) returns for a missing key with
 * NSIS's default "\n" (ReadINIStr sets its error flag only when the default comes back). */
#include <windows.h>
#include <stdio.h>
static void one(FILE *o, LPCWSTR sec, LPCWSTR key, LPCWSTR def, LPCWSTR file)
{
    WCHAR b[256]; DWORD r, i; for (i = 0; i < 256; i++) b[i] = 0x7777;
    SetLastError(0xdead);
    r = GetPrivateProfileStringW(sec, key, def, b, 255, file);
    fprintf(o, "sec %ls key %ls def %s: ret %lu err %lu buf", sec ? sec : L"(null)", key ? key : L"(null)",
            def ? (def[0] == L'\n' ? "\\n" : "other") : "(null)", r, GetLastError());
    for (i = 0; i < 6; i++) fprintf(o, " %04x", b[i]);
    fprintf(o, "\n");
}
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); FILE *f = fopen("C:\\INITEST.INI", "w");
    fprintf(f, "[STARTMENU]\nShortcut0=Mozilla Firefox.lnk\n"); fclose(f);
    one(o, L"STARTMENU", L"Shortcut0", L"\n", L"C:\\INITEST.INI");
    one(o, L"STARTMENU", L"Shortcut1", L"\n", L"C:\\INITEST.INI");
    one(o, L"NOSECTION", L"Shortcut0", L"\n", L"C:\\INITEST.INI");
    one(o, L"STARTMENU", L"Shortcut1", L"\n", L"C:\\NOFILE.INI");
    one(o, L"STARTMENU", L"Shortcut1", L"xyz", L"C:\\INITEST.INI");
    {   char b[64]; DWORD r = GetPrivateProfileStringA("STARTMENU", "Shortcut1", "\n", b, 63, "C:\\INITEST.INI");
        fprintf(o, "A: ret %lu first %02x\n", r, (BYTE)b[0]); }
    fclose(o); return 0;
}
