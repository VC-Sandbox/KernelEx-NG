/* clrhost.c - CLRHOST.EXE: load the .NET 4 runtime through the shim's documented hosting API, each step's HRESULT
 * -> C:\CLRHOST.TXT. Modern program (kexnt active and logging). */
#include <windows.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
static const GUID CLSID_CLRMetaHost = {0x9280188d,0x0e8e,0x4867,{0xb3,0x0c,0x7f,0xa8,0x38,0x84,0xe8,0xde}};
static const GUID IID_ICLRMetaHost  = {0xD332DB9E,0xB9B3,0x4125,{0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16}};
static const GUID IID_ICLRRuntimeInfo = {0xBD39D1D2,0xBA2F,0x486a,{0x89,0xB0,0xB4,0xB0,0xCB,0x46,0x68,0x91}};
static const GUID CLSID_CLRRuntimeHost = {0x90F1A06E,0x7712,0x4762,{0x86,0xB5,0x7A,0x5E,0xBA,0x6B,0xDB,0x02}};
static const GUID IID_ICLRRuntimeHost = {0x90F1A06C,0x7712,0x4762,{0x86,0xB5,0x7A,0x5E,0xBA,0x6B,0xDB,0x02}};
typedef HRESULT (WINAPI *T_CCI)(REFCLSID, REFIID, void **);
int main(void)
{
    FILE *o = fopen("C:\\CLRHOST.TXT", "w"); HMODULE m; T_CCI cci; void *mh = NULL, *ri = NULL, *rh = NULL; HRESULT hr;
    SetLastError(0); m = LoadLibraryA("mscoree.dll"); fprintf(o, "mscoree %p err %lu\n", (void *)m, GetLastError()); fflush(o);
    if (!m) return 1;
    cci = (T_CCI)GetProcAddress(m, "CLRCreateInstance"); fprintf(o, "CLRCreateInstance %p\n", (void *)cci); fflush(o);
    if (!cci) return 1;
    hr = cci(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, &mh); fprintf(o, "CLRCreateInstance -> %08lx\n", hr); fflush(o);
    if (!mh) return 1;
    {   HRESULT (WINAPI *gr)(void *, LPCWSTR, REFIID, void **) = (*(HRESULT (WINAPI ***)(void *, LPCWSTR, REFIID, void **))mh)[3];
        hr = gr(mh, L"v4.0.30319", &IID_ICLRRuntimeInfo, &ri); fprintf(o, "GetRuntime -> %08lx\n", hr); fflush(o); }
    if (!ri) return 1;
    {   HRESULT (WINAPI *gi)(void *, REFCLSID, REFIID, void **) = (*(HRESULT (WINAPI ***)(void *, REFCLSID, REFIID, void **))ri)[9];
        hr = gi(ri, &CLSID_CLRRuntimeHost, &IID_ICLRRuntimeHost, &rh); fprintf(o, "GetInterface(CLRRuntimeHost) -> %08lx\n", hr); fflush(o); }
    if (rh) { HRESULT (WINAPI *st)(void *) = (*(HRESULT (WINAPI ***)(void *))rh)[3]; hr = st(rh); fprintf(o, "Start -> %08lx\n", hr); fflush(o);
        {   /* ICLRRuntimeHost::ExecuteInDefaultAppDomain = vtable slot 11 */
            HRESULT (WINAPI *ex)(void *, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, DWORD *) = (*(HRESULT (WINAPI ***)(void *, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, DWORD *))rh)[11];
            DWORD ret = 0; hr = ex(rh, L"C:\\KEXTEST\\LIB.DLL", L"Entry", L"Run", L"hello98", &ret);
            fprintf(o, "ExecuteInDefaultAppDomain -> %08lx return %lu\n", hr, ret); } }
    fclose(o); return 0;
}
