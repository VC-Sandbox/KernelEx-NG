/*
 * assoc_ext.c - KernelEx-NG build 132: IApplicationAssociationRegistration (CLSID_ApplicationAssociationRegistration).
 *
 * Measured (Firefox 115 ESR, Browser Console): every address typed into the URL bar became a web search. The URI
 * fixup service could not be created: URIFixup.sys.mjs:263, its constructor, calls
 * nsIExternalProtocolService.externalProtocolHandlerExists(), which threw NS_ERROR_NOT_AVAILABLE (0x80040111).
 * Mozilla's Windows code (uriloader/exthandler/win/nsOSHelperAppService.cpp) gets that answer from the Vista shell
 * class ApplicationAssociationRegistration: it is created once with CoCreateInstance, and when that fails (Windows 98
 * has no such class) every protocol query returns NS_ERROR_NOT_AVAILABLE.
 *
 * kexnt's CoCreateInstance (filedlg_ext.c) now answers this class with the object below. The answers come from the
 * same registry Windows 98's own shell uses (HKEY_CLASSES_ROOT); there are no per-user default-program choices
 * (Vista's UserChoice keys) on 98:
 *   QueryCurrentDefault  AT_URLPROTOCOL:   HKCR\<scheme> with a "URL Protocol" value -> the scheme name
 *                        AT_FILEEXTENSION: HKCR\<.ext> default value (the ProgID)
 *                        AT_MIMETYPE:      HKCR\MIME\Database\Content Type\<type> "Extension" -> that ProgID
 *                        AT_STARTMENUCLIENT: HKLM\Software\Clients\<type> default value
 *                        nothing registered -> HRESULT_FROM_WIN32(ERROR_NO_ASSOCIATION), as on Vista
 *   QueryAppIsDefault(All) -> S_OK, "not the default" (98 has no registered-application model)
 *   SetAppAsDefault(All), ClearUserAssociations -> E_NOTIMPL (no Default Programs on 98)
 * Written from the documented interface (shobjidl.h); returned strings are CoTaskMemAlloc'ed, as documented.
 */
#include "kexnt_common.h"
#include <stddef.h>

void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);   /* crashlog_ext.c */

static const GUID IID_IUnknown_a = {0x00000000,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const GUID IID_IAAR_      = {0x4e530b0a,0xe611,0x4c77,{0xa3,0xac,0x90,0x31,0xd0,0x22,0x28,0x1b}};
const GUID kex_CLSID_ApplicationAssociationRegistration =
                                   {0x591209c7,0x767b,0x42b2,{0x9f,0xba,0x44,0xee,0x46,0x15,0xf2,0xc7}};

#define AT_FILEEXTENSION_   0
#define AT_URLPROTOCOL_     1
#define AT_STARTMENUCLIENT_ 2
#define AT_MIMETYPE_        3
#define E_NOINTERFACE_  ((HRESULT)0x80004002L)
#define E_INVALIDARG_   ((HRESULT)0x80070057L)
#define E_NOTIMPL_      ((HRESULT)0x80004001L)
#define E_OUTOFMEMORY_  ((HRESULT)0x8007000EL)
#define NO_ASSOC_       ((HRESULT)0x80070483L)   /* HRESULT_FROM_WIN32(ERROR_NO_ASSOCIATION) */

typedef struct { void **vt; LONG ref; } AAR;
static void *g_vt[9];

static int same_(const GUID *a, const GUID *b) { return a && b && !memcmp(a, b, sizeof(GUID)); }

/* UTF-16 -> ANSI (Windows 98's registry is ANSI); FALSE if it does not fit or does not convert */
static BOOL to_a(const WCHAR *w, char *a, int cb)
{
    int n;
    if (!w || !*w) return FALSE;
    n = WideCharToMultiByte(CP_ACP, 0, w, -1, a, cb, NULL, NULL);
    return n > 0;
}
/* default value (name NULL) or a named string value of HKCR/HKLM\key; FALSE if absent or empty */
static BOOL reg_str(HKEY root, const char *key, const char *name, char *out, DWORD cb)
{
    HKEY k; DWORD t = 0, n = cb; LONG r;
    if (RegOpenKeyExA(root, key, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS) return FALSE;
    r = RegQueryValueExA(k, name, NULL, &t, (BYTE *)out, &n);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || (t != REG_SZ && t != REG_EXPAND_SZ) || n < 2 || !out[0]) return FALSE;
    out[cb - 1] = 0;
    return TRUE;
}
static BOOL reg_has(HKEY root, const char *key, const char *name)
{
    HKEY k; LONG r;
    if (RegOpenKeyExA(root, key, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS) return FALSE;
    r = RegQueryValueExA(k, name, NULL, NULL, NULL, NULL);
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}
static HRESULT ret_str(const char *a, LPWSTR *out)
{
    typedef void *(WINAPI *T_CTMA)(SIZE_T);
    T_CTMA ctma = (T_CTMA)(void *)kex_sysproc("OLE32.DLL", "CoTaskMemAlloc");
    int n = MultiByteToWideChar(CP_ACP, 0, a, -1, NULL, 0);
    WCHAR *w;
    if (n <= 0 || !ctma || !(w = (WCHAR *)ctma((SIZE_T)n * sizeof(WCHAR)))) return E_OUTOFMEMORY_;
    MultiByteToWideChar(CP_ACP, 0, a, -1, w, n);
    *out = w;
    return S_OK;
}

static HRESULT WINAPI aar_qi(AAR *t, const GUID *iid, void **out)
{
    if (!out) return E_INVALIDARG_;
    if (same_(iid, &IID_IUnknown_a) || same_(iid, &IID_IAAR_)) { *out = t; InterlockedIncrement(&t->ref); return S_OK; }
    *out = NULL; return E_NOINTERFACE_;
}
static ULONG WINAPI aar_addref(AAR *t) { return (ULONG)InterlockedIncrement(&t->ref); }
static ULONG WINAPI aar_release(AAR *t)
{
    LONG r = InterlockedDecrement(&t->ref);
    if (!r) HeapFree(GetProcessHeap(), 0, t);
    return (ULONG)r;
}
static HRESULT WINAPI aar_query_current(AAR *t, LPCWSTR query, int type, int level, LPWSTR *out)
{
    char q[260], key[400], v[260];
    if (!out) return E_INVALIDARG_;
    *out = NULL;
    if (!to_a(query, q, sizeof(q))) return E_INVALIDARG_;
    switch (type) {
    case AT_URLPROTOCOL_:
        if (reg_has(HKEY_CLASSES_ROOT, q, "URL Protocol")) return ret_str(q, out);
        break;
    case AT_FILEEXTENSION_:
        if (q[0] == '.' && reg_str(HKEY_CLASSES_ROOT, q, NULL, v, sizeof(v))) return ret_str(v, out);
        break;
    case AT_MIMETYPE_:
        lstrcpyA(key, "MIME\\Database\\Content Type\\"); lstrcatA(key, q);
        if (reg_str(HKEY_CLASSES_ROOT, key, "Extension", v, sizeof(v)) && reg_str(HKEY_CLASSES_ROOT, v, NULL, q, sizeof(q)))
            return ret_str(q, out);
        break;
    case AT_STARTMENUCLIENT_:
        lstrcpyA(key, "Software\\Clients\\"); lstrcatA(key, q);
        if (reg_str(HKEY_LOCAL_MACHINE, key, NULL, v, sizeof(v))) return ret_str(v, out);
        break;
    default:
        return E_INVALIDARG_;
    }
    return NO_ASSOC_;
}
static HRESULT WINAPI aar_query_isdefault(AAR *t, LPCWSTR q, int type, int level, LPCWSTR app, BOOL *def)
{ if (!def) return E_INVALIDARG_; *def = FALSE; return S_OK; }
static HRESULT WINAPI aar_query_isdefault_all(AAR *t, int level, LPCWSTR app, BOOL *def)
{ if (!def) return E_INVALIDARG_; *def = FALSE; return S_OK; }
static HRESULT WINAPI aar_set_default(AAR *t, LPCWSTR app, LPCWSTR set, int type) { return E_NOTIMPL_; }
static HRESULT WINAPI aar_set_default_all(AAR *t, LPCWSTR app) { return E_NOTIMPL_; }
static HRESULT WINAPI aar_clear(AAR *t) { return E_NOTIMPL_; }

/* filedlg_ext.c's kex_CoCreateInstance calls this for kex_CLSID_ApplicationAssociationRegistration */
HRESULT kex_assocreg_new(const GUID *riid, void **out)
{
    AAR *t; HRESULT hr;
    if (!g_vt[0]) {
        g_vt[1] = (void *)aar_addref; g_vt[2] = (void *)aar_release; g_vt[3] = (void *)aar_query_current;
        g_vt[4] = (void *)aar_query_isdefault; g_vt[5] = (void *)aar_query_isdefault_all; g_vt[6] = (void *)aar_set_default;
        g_vt[7] = (void *)aar_set_default_all; g_vt[8] = (void *)aar_clear;
        InterlockedExchangePointer(&g_vt[0], (void *)aar_qi);
    }
    if (!(t = (AAR *)HeapAlloc(GetProcessHeap(), 0, sizeof(AAR)))) return E_OUTOFMEMORY_;
    t->vt = g_vt; t->ref = 1;
    hr = aar_qi(t, riid, out);
    aar_release(t);
    { static LONG n; if (InterlockedIncrement(&n) <= 5) kex_crashnote("ApplicationAssociationRegistration object made by kexnt (result)", (DWORD)hr, 0, 0, 0); }
    return hr;
}

/* ---- build 132: ShellLink objects with IPropertyStore ----
 * Measured (K-Lite Codec Pack 20.2, Inno Setup 6, KEXSETUP's Windows 10 profile): "Setup: Interface not supported"
 * at the end of the install. Inno's CreateShellLink (Setup.InstFunc.Ole.pas) casts the CLSID_ShellLink object to
 * IPropertyStore to set the Windows 7 shortcut properties (AppUserModel ID, ExcludeFromShowInNewInstall,
 * PreventPinning, StartPinOption). Windows 98's ShellLink answers IShellLinkA/W and IPersistFile but not
 * IPropertyStore (probe probes/slq.c: 80004002) -> Delphi EIntfCastError. Those properties only steer the
 * Windows 7+ taskbar and Start menu; Windows 98 has neither feature. kexnt's CoCreateInstance wraps the real ShellLink:
 * IPropertyStore is answered by a small store that accepts values (and reads them back) without writing them into the
 * .lnk; every other interface comes from the real object, so the shortcut itself is made by Windows 98's shell. */
static const GUID IID_IPropertyStore_ = {0x886D8EEB,0x8CF2,0x4446,{0x8D,0x02,0xCD,0xBA,0x1D,0xBD,0xCF,0x99}};
const GUID kex_CLSID_ShellLink = {0x00021401,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
typedef struct { GUID fmtid; DWORD pid; } PKEY_;
typedef struct { WORD vt, r1, r2, r3; DWORD v[2]; } PV_;    /* PROPVARIANT, 16 bytes on x86 */
#define NPS 8
typedef struct SLW { void **vt; void **psvt; LONG ref; void *inner; int n; PKEY_ k[NPS]; PV_ v[NPS]; } SLW;
static void *g_slw_vt[3], *g_ps_vt[8];
#define PS2SLW(p) ((SLW *)((BYTE *)(p) - offsetof(SLW, psvt)))
typedef HRESULT (WINAPI *T_QI)(void *, const GUID *, void **);
typedef ULONG (WINAPI *T_REF)(void *);
static HRESULT WINAPI slw_qi(SLW *t, const GUID *iid, void **out)
{
    if (!out) return E_INVALIDARG_;
    if (same_(iid, &IID_IUnknown_a)) { *out = t; InterlockedIncrement(&t->ref); return S_OK; }
    if (same_(iid, &IID_IPropertyStore_)) { *out = &t->psvt; InterlockedIncrement(&t->ref); return S_OK; }
    return ((T_QI)(*(void ***)t->inner)[0])(t->inner, iid, out);
}
static ULONG WINAPI slw_addref(SLW *t) { return (ULONG)InterlockedIncrement(&t->ref); }
static ULONG WINAPI slw_release(SLW *t)
{
    LONG r = InterlockedDecrement(&t->ref);
    if (!r) { ((T_REF)(*(void ***)t->inner)[2])(t->inner); HeapFree(GetProcessHeap(), 0, t); }
    return (ULONG)r;
}
static HRESULT WINAPI ps_qi(void *p, const GUID *iid, void **out) { return slw_qi(PS2SLW(p), iid, out); }
static ULONG WINAPI ps_addref(void *p) { return slw_addref(PS2SLW(p)); }
static ULONG WINAPI ps_release(void *p) { return slw_release(PS2SLW(p)); }
static HRESULT WINAPI ps_getcount(void *p, DWORD *n) { if (!n) return E_INVALIDARG_; *n = (DWORD)PS2SLW(p)->n; return S_OK; }
static HRESULT WINAPI ps_getat(void *p, DWORD i, PKEY_ *k)
{ SLW *t = PS2SLW(p); if (!k || i >= (DWORD)t->n) return E_INVALIDARG_; *k = t->k[i]; return S_OK; }
static HRESULT WINAPI ps_getvalue(void *p, const PKEY_ *k, PV_ *v)
{
    SLW *t = PS2SLW(p); int i;
    if (!k || !v) return E_INVALIDARG_;
    memset(v, 0, sizeof(*v));                                   /* VT_EMPTY when not set, as documented */
    for (i = 0; i < t->n; i++) if (!memcmp(&t->k[i], k, sizeof(*k))) {
        if (t->v[i].vt == 3 /*VT_I4*/ || t->v[i].vt == 11 /*VT_BOOL*/ || t->v[i].vt == 19 /*VT_UI4*/) *v = t->v[i];
        break;
    }
    return S_OK;
}
static HRESULT WINAPI ps_setvalue(void *p, const PKEY_ *k, const PV_ *v)
{
    SLW *t = PS2SLW(p); int i;
    if (!k || !v) return E_INVALIDARG_;
    for (i = 0; i < t->n && memcmp(&t->k[i], k, sizeof(*k)); i++) ;
    if (i == t->n && t->n < NPS) t->n++;
    if (i < NPS) { t->k[i] = *k; t->v[i] = *v; if (t->v[i].vt != 3 && t->v[i].vt != 11 && t->v[i].vt != 19) t->v[i].v[0] = t->v[i].v[1] = 0; }
    return S_OK;                                                /* kept in memory only - no Windows 98 user */
}
static HRESULT WINAPI ps_commit(void *p) { return S_OK; }
/* filedlg_ext.c's kex_CoCreateInstance: `real` = a new ShellLink (IUnknown) from the previous implementation */
HRESULT kex_shelllink_wrap(void *real, const GUID *riid, void **out)
{
    SLW *t; HRESULT hr;
    if (!g_slw_vt[0]) {
        g_slw_vt[1] = (void *)slw_addref; g_slw_vt[2] = (void *)slw_release;
        g_ps_vt[1] = (void *)ps_addref; g_ps_vt[2] = (void *)ps_release; g_ps_vt[3] = (void *)ps_getcount;
        g_ps_vt[4] = (void *)ps_getat; g_ps_vt[5] = (void *)ps_getvalue; g_ps_vt[6] = (void *)ps_setvalue; g_ps_vt[7] = (void *)ps_commit;
        g_ps_vt[0] = (void *)ps_qi;
        InterlockedExchangePointer(&g_slw_vt[0], (void *)slw_qi);
    }
    if (!(t = (SLW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SLW)))) { ((T_REF)(*(void ***)real)[2])(real); return E_OUTOFMEMORY_; }
    t->vt = g_slw_vt; t->psvt = g_ps_vt; t->ref = 1; t->inner = real;
    hr = slw_qi(t, riid, out);
    slw_release(t);
    { static LONG n; if (InterlockedIncrement(&n) <= 5) kex_crashnote("ShellLink with IPropertyStore made by kexnt (result)", (DWORD)hr, 0, 0, 0); }
    return hr;
}
