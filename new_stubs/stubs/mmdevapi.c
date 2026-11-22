/* mmdevapi.dll stub for Windows 98 SE (build 128): ActivateAudioInterfaceAsync (ordinal 17) is carried out by
 * KEXAUDIO.DLL, our Core Audio implementation (process loopback = what other programs play through it). */
#include <windows.h>
typedef HRESULT (WINAPI *T_AAIA)(LPCWSTR, const void *, void *, void *, void **);
HRESULT WINAPI ActivateAudioInterfaceAsync(LPCWSTR path, const void *iid, void *params, void *handler, void **op)
{
    static T_AAIA f;
    if (op) *op = NULL;
    if (!f) {
        HMODULE m = LoadLibraryA("KEXAUDIO.DLL");
        if (m) f = (T_AAIA)(void *)GetProcAddress(m, "KexActivateAudioInterfaceAsync");
    }
    return f ? f(path, iid, params, handler, op) : (HRESULT)0x80004001L;   /* E_NOTIMPL */
}
