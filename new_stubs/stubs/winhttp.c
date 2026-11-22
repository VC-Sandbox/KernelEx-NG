/* winhttp.dll stub for Windows 98 SE: no WinHTTP stack. The proxy settings query reads the Internet
 * Explorer settings Win98 keeps in the registry, so programs still honour the user's proxy. */
#include <windows.h>

typedef struct { BOOL fAutoDetect; LPWSTR lpszAutoConfigUrl, lpszProxy, lpszProxyBypass; } IE_PROXY;

static LPWSTR reg_wstr(HKEY k, const char *name)
{
    char a[2048]; DWORD sz = sizeof(a) - 1, t; int n; LPWSTR w;
    if (RegQueryValueExA(k, name, NULL, &t, (BYTE *)a, &sz) != ERROR_SUCCESS || t != REG_SZ || sz <= 1) return NULL;
    a[sz] = 0;
    n = MultiByteToWideChar(CP_ACP, 0, a, -1, NULL, 0);
    if (!n || !(w = GlobalAlloc(GMEM_FIXED, n * sizeof(WCHAR)))) return NULL;   /* caller GlobalFree()s */
    MultiByteToWideChar(CP_ACP, 0, a, -1, w, n);
    return w;
}

BOOL WINAPI WinHttpGetIEProxyConfigForCurrentUser(IE_PROXY *cfg)
{
    HKEY k; DWORD en = 0, sz = sizeof(en), t;
    if (!cfg) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    ZeroMemory(cfg, sizeof(*cfg));
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                      0, KEY_READ, &k) != ERROR_SUCCESS) {
        cfg->fAutoDetect = FALSE; return TRUE;                   /* no IE settings: direct */
    }
    if (RegQueryValueExA(k, "ProxyEnable", NULL, &t, (BYTE *)&en, &sz) == ERROR_SUCCESS && en) {
        cfg->lpszProxy = reg_wstr(k, "ProxyServer");
        cfg->lpszProxyBypass = reg_wstr(k, "ProxyOverride");
    }
    cfg->lpszAutoConfigUrl = reg_wstr(k, "AutoConfigURL");
    RegCloseKey(k);
    return TRUE;
}
