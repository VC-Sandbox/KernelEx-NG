/* kexnotls.dll - a DLL WITHOUT static TLS, built at the same image base as kextls.dll. kextest loads and frees it
 * first, so kextls.dll then lands on an address a different, already-unloaded module used (build 45: Chromium's
 * vk_swiftshader.dll got no TLS because kexnt remembered modules by address). */
#include <windows.h>
__declspec(dllexport) int kexnotls_dummy(void) { return 1; }
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) { (void)h; (void)r; (void)p; return TRUE; }
