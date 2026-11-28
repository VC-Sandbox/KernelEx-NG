/* errcap.c - run a program with stdout and stderr redirected to a file (Windows 98 command.com cannot redirect stderr).
 * ERRCAP.EXE out.txt program [arguments]   - e.g. the .NET runtime's "Unhandled Exception: ..." text of a console program */
#include <windows.h>
int main(int argc, char **argv)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE }; STARTUPINFOA si; PROCESS_INFORMATION pi; HANDLE f;
    char *cmd = GetCommandLineA(); int i; DWORD code = 0;
    if (argc < 3) return 1;
    f = CreateFileA(argv[1], GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 2;
    for (i = 0; i < 2; i++) {                      /* skip our own name and the output file in the command line */
        while (*cmd == ' ') cmd++;
        if (*cmd == '"') { cmd++; while (*cmd && *cmd != '"') cmd++; if (*cmd) cmd++; } else while (*cmd && *cmd != ' ') cmd++;
    }
    while (*cmd == ' ') cmd++;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE); si.hStdOutput = f; si.hStdError = f;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) return 3;
    WaitForSingleObject(pi.hProcess, 120000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(f);
    return (int)code;
}
