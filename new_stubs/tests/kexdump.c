/* KEXDUMP.EXE - KernelEx-NG: ask every running NT 6+ program (its main process) to write where all its threads
 * are right now, to KEXHANG_<program>.LOG next to the program. Run it while the program is stuck. */
#include <windows.h>
int main(void)
{
    HANDLE ev = OpenEventA(EVENT_MODIFY_STATE, FALSE, "KexNG_ThreadDump");
    DWORD w; HANDLE o = GetStdHandle(STD_OUTPUT_HANDLE);
    const char *ok = "KEXDUMP: asked. Look for KEXHANG_<program>.LOG in the program's folder (e.g. KEXHANG_chrome.LOG).\r\n";
    const char *no = "KEXDUMP: no program is listening (start the program first; it must run with the new KEXNT.DLL).\r\n";
    if (!ev) { WriteFile(o, no, lstrlenA(no), &w, NULL); return 1; }
    PulseEvent(ev);
    CloseHandle(ev);
    WriteFile(o, ok, lstrlenA(ok), &w, NULL);
    Sleep(2500);
    return 0;
}
