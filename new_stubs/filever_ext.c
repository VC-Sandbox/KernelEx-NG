/* filever_ext.c - file version of the core system DLLs follows the KernelEx profile (2026-11-02).
 *
 * Programs that want the "real" Windows version read the version resource of kernel32.dll (or kernelbase.dll /
 * ntdll.dll) instead of asking GetVersionEx - Chromium's base::win::OSInfo::Kernel32Version() does, and its
 * user-agent code stops (NOTREACHED, components/embedder_support/user_agent_utils.cc:104) on anything older
 * than Windows 10 when the reported OS is Windows 10. On Windows 98 that file says 4.10.2222.
 * When the process runs under an NT version profile (the api-ms shells pass it, peb_ext.c), GetFileVersionInfo
 * of those three files reports the profile's version in VS_FIXEDFILEINFO (file and product version, x.y.build.0),
 * the same way Windows' compatibility layers keep these consistent. Other files and programs in plain
 * Windows 98 mode are untouched. VERSION.DLL routes: GetFileVersionInfoA/W, GetFileVersionInfoExA/W. */
#include <windows.h>

#define KEXAPI WINAPI
FARPROC kex_prev_impl(const char *dll, const char *name);                  /* gdiguard_ext.c */
BOOL kex_profile_nt_version(PDWORD major, PDWORD minor, PDWORD build);      /* peb_ext.c */

static int is_core(const void *path, int wide)
{
    static const char *const names[] = { "kernel32", "kernelbase", "ntdll" };
    char base[32]; int i, n = 0, start = 0, k;
    if (!path) return 0;
    for (i = 0; ; i++) {                                     /* start of the last path component */
        unsigned c = wide ? ((const WCHAR *)path)[i] : ((const unsigned char *)path)[i];
        if (!c) break;
        if (c == '\\' || c == '/' || c == ':') start = i + 1;
        if (i > 4096) return 0;
    }
    for (i = start; n < (int)sizeof(base) - 1; i++) {
        unsigned c = wide ? ((const WCHAR *)path)[i] : ((const unsigned char *)path)[i];
        if (!c || c == '.') break;
        if (c >= 'A' && c <= 'Z') c += 32;
        if (c > 127) return 0;
        base[n++] = (char)c;
    }
    base[n] = 0;
    for (k = 0; k < 3; k++) if (!lstrcmpA(base, names[k])) return 1;
    return 0;
}

static void patch(void *data, DWORD len)
{
    DWORD maj, min, build, i, *d = (DWORD *)data;
    if (!data || len < 64 || !kex_profile_nt_version(&maj, &min, &build)) return;
    for (i = 0; i + 13 <= len / 4; i++)
        if (d[i] == 0xFEEF04BDUL) {                          /* VS_FIXEDFILEINFO.dwSignature */
            d[i + 2] = d[i + 4] = (maj << 16) | (min & 0xFFFF);   /* dwFileVersionMS, dwProductVersionMS */
            d[i + 3] = d[i + 5] = build << 16;                     /* dwFileVersionLS, dwProductVersionLS */
            return;
        }
}

typedef BOOL (WINAPI *T_GFVI)(const void *, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI *T_GFVIX)(DWORD, const void *, DWORD, DWORD, LPVOID);
static BOOL gfvi(const char *fn, T_GFVI *cache, const void *name, DWORD h, DWORD len, LPVOID data, int wide)
{
    BOOL r;
    if (!*cache) *cache = (T_GFVI)(void *)kex_prev_impl("VERSION.DLL", fn);
    if (!*cache) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    r = (*cache)(name, h, len, data);
    if (r && is_core(name, wide)) patch(data, len);
    return r;
}
static T_GFVI c_a, c_w;
BOOL KEXAPI kex_GetFileVersionInfoA(LPCSTR name, DWORD h, DWORD len, LPVOID data)
{ return gfvi("GetFileVersionInfoA", &c_a, name, h, len, data, 0); }
BOOL KEXAPI kex_GetFileVersionInfoW(LPCWSTR name, DWORD h, DWORD len, LPVOID data)
{ return gfvi("GetFileVersionInfoW", &c_w, name, h, len, data, 1); }

/* Ex (Vista+): the flags only choose MUI/neutral resources; Windows 98 has neither. */
static BOOL gfvix(const char *fn, const char *plain, T_GFVIX *cx, T_GFVI *cp, DWORD fl, const void *name,
                  DWORD h, DWORD len, LPVOID data, int wide)
{
    BOOL r;
    if (!*cx) *cx = (T_GFVIX)(void *)kex_prev_impl("VERSION.DLL", fn);
    if (!*cx) return gfvi(plain, cp, name, h, len, data, wide);
    r = (*cx)(fl, name, h, len, data);
    if (r && is_core(name, wide)) patch(data, len);
    return r;
}
static T_GFVIX cx_a, cx_w;
BOOL KEXAPI kex_GetFileVersionInfoExA(DWORD fl, LPCSTR name, DWORD h, DWORD len, LPVOID data)
{ return gfvix("GetFileVersionInfoExA", "GetFileVersionInfoA", &cx_a, &c_a, fl, name, h, len, data, 0); }
BOOL KEXAPI kex_GetFileVersionInfoExW(DWORD fl, LPCWSTR name, DWORD h, DWORD len, LPVOID data)
{ return gfvix("GetFileVersionInfoExW", "GetFileVersionInfoW", &cx_w, &c_w, fl, name, h, len, data, 1); }
