/* kxlegacy.c - a plain Windows 98 program (subsystem 4.0) for kextest's gate check (build 89).
 * Exit code: 1 kexnt counts this process as a Windows 9x program, 2 as modern, 8 kexnt not loaded here,
 * 9 kexnt has no KexGateInfo. It also makes a few ordinary calls through KernelEx first. */
#include <windows.h>
int main(void)
{
    typedef VOID (WINAPI *T_GI)(PDWORD, PDWORD);
    HMODULE k = GetModuleHandleA("KEXNT.DLL"); T_GI gi; DWORD st = 0, why = 0, w; char buf[64];
    HANDLE f = CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) { WriteFile(f, "x", 1, &w, NULL); CloseHandle(f); }
    GetWindowsDirectoryA(buf, sizeof(buf));
    if (!k) return 8;
    if (!(gi = (T_GI)(void *)GetProcAddress(k, "KexGateInfo"))) return 9;
    gi(&st, &why);
    return (int)st;
}
