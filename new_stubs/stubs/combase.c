/* combase.dll for Windows 98 SE (build 131). Firefox 160's xul.dll imports it statically (Windows 8 split COM out
 * of ole32). Memory and marshaler calls go to OLE32; WinRT calls to kexnt's implementations; the rest refuse. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static FARPROC kx(const char *n)
{
    HMODULE h = GetModuleHandleA("KEXNT.DLL");
    if (!h) h = LoadLibraryA("KEXNT.DLL");
    return h ? GetProcAddress(h, n) : NULL;
}
static FARPROC ole(const char *n) { HMODULE h = GetModuleHandleA("OLE32.DLL"); if (!h) h = LoadLibraryA("OLE32.DLL"); return h ? GetProcAddress(h, n) : NULL; }
LPVOID WINAPI CoTaskMemAlloc(SIZE_T n) { typedef LPVOID (WINAPI *T)(SIZE_T); T f = (T)(void *)ole("CoTaskMemAlloc"); return f ? f(n) : NULL; }
void WINAPI CoTaskMemFree(LPVOID p) { typedef void (WINAPI *T)(LPVOID); T f = (T)(void *)ole("CoTaskMemFree"); if (f) f(p); }
LPVOID WINAPI CoTaskMemRealloc(LPVOID p, SIZE_T n) { typedef LPVOID (WINAPI *T)(LPVOID, SIZE_T); T f = (T)(void *)ole("CoTaskMemRealloc"); return f ? f(p, n) : NULL; }
HRESULT WINAPI CoCreateFreeThreadedMarshaler(void * outer, void * *m)
{
    typedef HRESULT (WINAPI *T)(void *, void * *); T f = (T)(void *)ole("CoCreateFreeThreadedMarshaler");
    if (m) *m = NULL;
    return f ? f(outer, m) : E_NOTIMPL;
}
HRESULT WINAPI CoIncrementMTAUsage(PVOID *cookie)
{
    typedef HRESULT (WINAPI *T)(PVOID *); T f = (T)(void *)kx("CoIncrementMTAUsage");
    if (f) return f(cookie);
    if (cookie) *cookie = (PVOID)1;
    return S_OK;
}
HRESULT WINAPI CoDecrementMTAUsage(PVOID cookie)
{ typedef HRESULT (WINAPI *T)(PVOID); T f = (T)(void *)kx("CoDecrementMTAUsage"); return f ? f(cookie) : S_OK; }
HRESULT WINAPI CoGetApartmentType(int *t, int *q)
{ typedef HRESULT (WINAPI *T)(int *, int *); T f = (T)(void *)kx("CoGetApartmentType"); return f ? f(t, q) : E_NOTIMPL; }
HRESULT WINAPI RoGetAgileReference(int opts, const GUID * riid, void *u, void **out) { if (out) *out = NULL; return E_NOTIMPL; }
HRESULT WINAPI RoInitialize(int t) { typedef HRESULT (WINAPI *T)(int); T f = (T)(void *)kx("RoInitialize"); return f ? f(t) : E_NOTIMPL; }
void WINAPI RoUninitialize(void) { typedef void (WINAPI *T)(void); T f = (T)(void *)kx("RoUninitialize"); if (f) f(); }
HRESULT WINAPI RoGetActivationFactory(PVOID id, const GUID * riid, void **out)
{ typedef HRESULT (WINAPI *T)(PVOID, const GUID *, void **); T f = (T)(void *)kx("RoGetActivationFactory"); if (out) *out = NULL; return f ? f(id, riid, out) : E_NOTIMPL; }
HRESULT WINAPI RoActivateInstance(PVOID id, void **out)
{ typedef HRESULT (WINAPI *T)(PVOID, void **); T f = (T)(void *)kx("RoActivateInstance"); if (out) *out = NULL; return f ? f(id, out) : E_NOTIMPL; }
HRESULT WINAPI WindowsCreateString(LPCWSTR s, UINT32 n, PVOID *out)
{ typedef HRESULT (WINAPI *T)(LPCWSTR, UINT32, PVOID *); T f = (T)(void *)kx("WindowsCreateString"); return f ? f(s, n, out) : E_NOTIMPL; }
HRESULT WINAPI WindowsDeleteString(PVOID s)
{ typedef HRESULT (WINAPI *T)(PVOID); T f = (T)(void *)kx("WindowsDeleteString"); return f ? f(s) : S_OK; }
LPCWSTR WINAPI WindowsGetStringRawBuffer(PVOID s, UINT32 *n)
{ typedef LPCWSTR (WINAPI *T)(PVOID, UINT32 *); T f = (T)(void *)kx("WindowsGetStringRawBuffer"); if (f) return f(s, n); if (n) *n = 0; return L""; }
