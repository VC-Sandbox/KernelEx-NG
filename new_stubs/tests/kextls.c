/* kextls.dll - test DLL with a static TLS directory and a TLS callback, loaded by kextest with
 * LoadLibrary (chrome.dll has static TLS and 6 callbacks). Windows 98 does not set up TLS for DLLs
 * loaded later; kexnt's LoadLibrary does (tls_ext.c). */
#include <windows.h>

__thread int tls_value = 42;
static volatile LONG cb_attach, cb_thread_attach, cb_thread_detach;

static void NTAPI tls_cb(PVOID h, DWORD reason, PVOID r)
{
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) InterlockedIncrement(&cb_attach);
    else if (reason == DLL_THREAD_ATTACH) InterlockedIncrement(&cb_thread_attach);
    else if (reason == DLL_THREAD_DETACH) InterlockedIncrement(&cb_thread_detach);
}
/* .CRT$XL? entries are collected between __xl_a and __xl_z by the mingw CRT into the TLS directory */
__attribute__((section(".CRT$XLB"), used)) PIMAGE_TLS_CALLBACK kextls_cb = tls_cb;

static int attach_tls = -1, attach_cb = -1;   /* seen inside DllMain(DLL_PROCESS_ATTACH) */
__declspec(dllexport) int get_attach(int which) { return which ? attach_cb : attach_tls; }
__declspec(dllexport) int get_tls(void) { return tls_value; }
__declspec(dllexport) void set_tls(int v) { tls_value = v; }
__declspec(dllexport) LONG get_cb(int which)
{ return which == 0 ? cb_attach : which == 1 ? cb_thread_attach : cb_thread_detach; }
/* NT: TLS is set up and the TLS callbacks have run before the entry point. Reading tls_value here would
 * fault or read another module's slot if not - so only read it when the index slot holds something. */
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p)
{
    extern DWORD _tls_index;
    (void)h; (void)p;
    if (r == DLL_PROCESS_ATTACH) {
        attach_cb = (int)cb_attach;
        attach_tls = TlsGetValue(_tls_index) && !IsBadReadPtr(TlsGetValue(_tls_index), 4) ? tls_value : -2;
    }
    return TRUE;
}
