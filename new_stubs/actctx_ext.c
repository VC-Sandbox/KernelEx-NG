/*
 * actctx_ext.c - activation contexts and a few shell/COM functions Firefox 52 imports (KernelEx-NG build 126).
 *
 * Measured (Firefox 52.9 ESR as installed by its setup, KEXCRASH_firefox.LOG): "Couldn't load XPCOM" -
 * LoadLibrary(xul.dll) error 31, "linked to missing export KERNEL32.DLL:CreateActCtxW". GPA.EXE over all 804
 * imports of firefox.exe / xul / mozglue / nss3 / lgpllibs: missing were CreateActCtxW, ActivateActCtx,
 * DeactivateActCtx, ReleaseActCtx (KERNEL32), SHParseDisplayName (SHELL32, already in sysdll_ext.c), CoGetContextToken, CoGetInterceptor,
 * CoGetInterceptorFromTypeInfo (OLE32); VerSetConditionMask / VerifyVersionInfo come from the version profiles.
 *
 * Activation contexts select side-by-side assemblies; Windows 98 has none, so every DLL load finds the one copy
 * there is. A context is accepted (a small object with a reference count), activating it changes nothing and
 * returns a cookie, as on XP for a manifest that names no assemblies. FindActCtxSectionString is NOT provided, so
 * code that asks which assembly a name maps to still sees "not available" (the VC++ 2008 CRT's manifest check).
 */
#include "kexnt_common.h"

typedef struct { DWORD magic; volatile LONG ref; } KACTCTX;
#define ACT_MAGIC 0x4354434BUL       /* "KCTC" */
static KACTCTX g_default = { ACT_MAGIC, 0x40000000 };
static volatile LONG g_cookie;

static BOOL valid_ctx(HANDLE h) { return h && h != INVALID_HANDLE_VALUE && !IsBadReadPtr(h, sizeof(KACTCTX)) && ((KACTCTX *)h)->magic == ACT_MAGIC; }

static HANDLE make_ctx(DWORD cb, const void *src)
{
    KACTCTX *c;
    if (!src || IsBadReadPtr(src, 4) || *(const DWORD *)src < 8 || cb < 8) { SetLastError(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE; }
    if (!(c = (KACTCTX *)HeapAlloc(GetProcessHeap(), 0, sizeof(*c)))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return INVALID_HANDLE_VALUE; }
    c->magic = ACT_MAGIC; c->ref = 1;
    return (HANDLE)c;
}
HANDLE KEXAPI kex_CreateActCtxW(const void *ac) { return make_ctx(ac && !IsBadReadPtr(ac, 4) ? *(const DWORD *)ac : 0, ac); }
HANDLE KEXAPI kex_CreateActCtxA(const void *ac) { return make_ctx(ac && !IsBadReadPtr(ac, 4) ? *(const DWORD *)ac : 0, ac); }
VOID KEXAPI kex_AddRefActCtx(HANDLE h) { if (valid_ctx(h) && h != (HANDLE)&g_default) InterlockedIncrement(&((KACTCTX *)h)->ref); }
VOID KEXAPI kex_ReleaseActCtx(HANDLE h)
{
    if (!valid_ctx(h) || h == (HANDLE)&g_default) return;
    if (InterlockedDecrement(&((KACTCTX *)h)->ref) == 0) { ((KACTCTX *)h)->magic = 0; HeapFree(GetProcessHeap(), 0, h); }
}
BOOL KEXAPI kex_ActivateActCtx(HANDLE h, ULONG_PTR *cookie)
{
    if (!cookie) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (h && h != INVALID_HANDLE_VALUE && !valid_ctx(h)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    *cookie = (ULONG_PTR)(InterlockedIncrement(&g_cookie) | 0x10000);
    return TRUE;
}
BOOL KEXAPI kex_DeactivateActCtx(DWORD flags, ULONG_PTR cookie) { (void)flags; (void)cookie; return TRUE; }
BOOL KEXAPI kex_GetCurrentActCtx(HANDLE *h)
{
    if (!h) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *h = NULL;                                       /* the process default (no context active) */
    return TRUE;
}

/* COM+ contexts and interceptors (Windows 2000+ COM): not there on Windows 98 */
HRESULT KEXAPI kex_CoGetContextToken(ULONG_PTR *t) { if (t) *t = 0; return E_NOTIMPL; }
HRESULT KEXAPI kex_CoGetInterceptor(REFIID a, void *b, REFIID c, void **d) { (void)a; (void)b; (void)c; if (d) *d = NULL; return E_NOTIMPL; }
HRESULT KEXAPI kex_CoGetInterceptorFromTypeInfo(REFIID a, void *b, void *c, REFIID d, void **e) { (void)a; (void)b; (void)c; (void)d; if (e) *e = NULL; return E_NOTIMPL; }

/* ---- the "runas" verb (build 126) ----
 * Measured (VC++ 2015-2022 setup, Burn 3.14, run as Windows 7): to start its per-machine part Burn calls
 * ShellExecuteEx with the verb "runas" (elevation, Vista+). Windows 98 has no such verb -> ERROR_NO_ASSOCIATION
 * (0x80070483 "Failed to launch elevated child process"). Every Windows 98 user already has full rights, so
 * "runas" is carried out as the default verb, the way an administrator without UAC gets it. */
typedef BOOL (WINAPI *T_SEEW)(void *);
typedef HINSTANCE (WINAPI *T_SEW)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
typedef HINSTANCE (WINAPI *T_SEA)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
FARPROC kex_prev_impl(const char *dll, const char *name);
static BOOL is_runas_w(LPCWSTR v) { return v && !IsBadStringPtrW(v, 16) && (v[0] | 32) == 'r' && (v[1] | 32) == 'u' && (v[2] | 32) == 'n' && (v[3] | 32) == 'a' && (v[4] | 32) == 's' && !v[5]; }
static BOOL is_runas_a(LPCSTR v) { return v && !IsBadStringPtrA(v, 16) && !lstrcmpiA(v, "runas"); }
BOOL KEXAPI kex_ShellExecuteExW(void *info)
{
    static T_SEEW prev; BYTE copy[64]; DWORD cb;
    if (!prev) prev = (T_SEEW)(void *)kex_prev_impl("SHELL32.DLL", "ShellExecuteExW");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    /* SHELLEXECUTEINFOW: cbSize, fMask, hwnd, lpVerb (offset 12) ... hProcess (offset 56); 60 bytes */
    if (!info || IsBadReadPtr(info, 16) || (cb = *(DWORD *)info) < 16 || cb > sizeof(copy) || !is_runas_w(*(LPCWSTR *)((BYTE *)info + 12)))
        return prev(info);
    {   BOOL r; memcpy(copy, info, cb); *(LPCWSTR *)(copy + 12) = NULL;
        r = prev(copy);
        memcpy((BYTE *)info + 32, copy + 32, cb - 32);              /* hInstApp and the outputs after it */
        return r; }
}
BOOL KEXAPI kex_ShellExecuteExA(void *info)
{
    static T_SEEW prev; BYTE copy[64]; DWORD cb;
    if (!prev) prev = (T_SEEW)(void *)kex_prev_impl("SHELL32.DLL", "ShellExecuteExA");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    if (!info || IsBadReadPtr(info, 16) || (cb = *(DWORD *)info) < 16 || cb > sizeof(copy) || !is_runas_a(*(LPCSTR *)((BYTE *)info + 12)))
        return prev(info);
    {   BOOL r; memcpy(copy, info, cb); *(LPCSTR *)(copy + 12) = NULL;
        r = prev(copy);
        memcpy((BYTE *)info + 32, copy + 32, cb - 32);
        return r; }
}
HINSTANCE KEXAPI kex_ShellExecuteW(HWND h, LPCWSTR verb, LPCWSTR file, LPCWSTR params, LPCWSTR dir, INT show)
{
    static T_SEW prev;
    if (!prev) prev = (T_SEW)(void *)kex_prev_impl("SHELL32.DLL", "ShellExecuteW");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return (HINSTANCE)0; }
    return prev(h, is_runas_w(verb) ? NULL : verb, file, params, dir, show);
}
HINSTANCE KEXAPI kex_ShellExecuteA(HWND h, LPCSTR verb, LPCSTR file, LPCSTR params, LPCSTR dir, INT show)
{
    static T_SEA prev;
    if (!prev) prev = (T_SEA)(void *)kex_prev_impl("SHELL32.DLL", "ShellExecuteA");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return (HINSTANCE)0; }
    return prev(h, is_runas_a(verb) ? NULL : verb, file, params, dir, show);
}
