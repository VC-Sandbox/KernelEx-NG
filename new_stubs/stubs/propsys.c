/* propsys.dll stub for Windows 98 SE. */
#include <windows.h>
#include <objbase.h>
HRESULT WINAPI InitPropVariantFromCLSID(REFCLSID clsid, PROPVARIANT *pv)
{
    CLSID *c;
    if (!clsid || !pv) return E_INVALIDARG;
    if (!(c = CoTaskMemAlloc(sizeof(CLSID)))) return E_OUTOFMEMORY;
    *c = *clsid;
    ZeroMemory(pv, sizeof(*pv));
    pv->vt = VT_CLSID; pv->puuid = c;
    return S_OK;
}
