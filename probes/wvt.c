/* wvt.c - WVT.EXE <out> <file>...: WinVerifyTrust (generic verify v2) and the SIP subject GUID per file (NT 5.1 program) */
#include <windows.h>
#include <wintrust.h>
#include <mssip.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); int i;
    for (i = 2; i < argc; i++) {
        WCHAR w[MAX_PATH]; WINTRUST_FILE_INFO fi = {0}; WINTRUST_DATA wd = {0}; GUID act = { 0xaac56b, 0xcd44, 0x11d0, { 0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee } }, sg;
        LONG r; BOOL b;
        MultiByteToWideChar(CP_ACP, 0, argv[i], -1, w, MAX_PATH);
        memset(&sg, 0, sizeof(sg)); SetLastError(0);
        b = CryptSIPRetrieveSubjectGuid(w, NULL, &sg);
        fprintf(o, "%s\n  sip %d err %08lx guid %08lx-%04x-%04x\n", argv[i], b, GetLastError(), sg.Data1, sg.Data2, sg.Data3);
        fi.cbStruct = sizeof(fi); fi.pcwszFilePath = w;
        wd.cbStruct = sizeof(wd); wd.dwUIChoice = WTD_UI_NONE; wd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wd.dwUnionChoice = WTD_CHOICE_FILE; wd.pFile = &fi; wd.dwStateAction = WTD_STATEACTION_VERIFY;
        r = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &act, &wd);
        fprintf(o, "  WinVerifyTrust %08lx (err %08lx)\n", r, GetLastError());
        wd.dwStateAction = WTD_STATEACTION_CLOSE; WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &act, &wd);
        fflush(o);
    }
    fclose(o); return 0;
}
