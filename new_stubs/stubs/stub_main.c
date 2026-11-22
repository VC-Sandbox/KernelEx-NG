/* Entry point shared by the stub DLLs (no C runtime). It also gives every stub a KERNEL32 import:
 * the Win9x loader is happiest with images that import KERNEL32. */
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(inst);
    return TRUE;
}
