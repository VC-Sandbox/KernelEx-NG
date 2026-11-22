/* spi_ext.c - SystemParametersInfoW with real Unicode structures (2026-11-10, build 20).
 *
 * KernelEx 4.5.2 (kexbasen/user32/uniuser32.c SystemParametersInfoW_new) hands the caller's buffer to
 * SystemParametersInfoA unchanged. For SPI_GETNONCLIENTMETRICS that writes a NONCLIENTMETRICSA (LOGFONTA,
 * 60 bytes each) into a NONCLIENTMETRICSW (LOGFONTW, 92 bytes each): only the first font lines up, the
 * others read neighbouring bytes as their height and a face name of ANSI bytes taken as UTF-16. Chromium
 * takes its UI fonts from lfMessageFont/lfMenuFont/... (ui/gfx/system_fonts_win.cc), so tabs, menus,
 * bubbles and dialogs came out a few pixels tall (build 19 screenshots).
 *
 * Here the structure-carrying actions are translated field by field; every other action goes to
 * kexnt's guarded SystemParametersInfoA (the same values, no strings).
 */
#include "kexnt_common.h"

BOOL WINAPI kex_SystemParametersInfoA(UINT a, UINT u, PVOID p, UINT f);   /* guard_gen.c (guarded USER32 call) */

#define K_SPI_SETDESKWALLPAPER      0x0014
#define K_SPI_GETICONTITLELOGFONT   0x001F
#define K_SPI_SETICONTITLELOGFONT   0x0022
#define K_SPI_GETNONCLIENTMETRICS   0x0029
#define K_SPI_SETNONCLIENTMETRICS   0x002A
#define K_SPI_GETICONMETRICS        0x002D
#define K_SPI_SETICONMETRICS        0x002E
#define K_SPI_GETHIGHCONTRAST       0x0042
#define K_SPI_GETDESKWALLPAPER      0x0073

static void lf_a2w(const LOGFONTA *a, LOGFONTW *w)
{
    CopyMemory(w, a, FIELD_OFFSET(LOGFONTA, lfFaceName));
    if (!MultiByteToWideChar(CP_ACP, 0, a->lfFaceName, -1, w->lfFaceName, LF_FACESIZE)) w->lfFaceName[0] = 0;
    w->lfFaceName[LF_FACESIZE - 1] = 0;
}
static void lf_w2a(const LOGFONTW *w, LOGFONTA *a)
{
    CopyMemory(a, w, FIELD_OFFSET(LOGFONTW, lfFaceName));
    if (!WideCharToMultiByte(CP_ACP, 0, w->lfFaceName, -1, a->lfFaceName, LF_FACESIZE, NULL, NULL)) a->lfFaceName[0] = 0;
    a->lfFaceName[LF_FACESIZE - 1] = 0;
}

/* NONCLIENTMETRICS: cbSize, 5 ints, caption font, 2 ints, small caption font, 2 ints, menu/status/message fonts
 * (+ iPaddedBorderWidth from Vista on: the W size is 500 without it, 504 with it). */
typedef struct { UINT cbSize; int m1[5]; LOGFONTW cap; int m2[2]; LOGFONTW smcap; int m3[2]; LOGFONTW menu, status, msg; int pad; } K_NCMW;
typedef struct { UINT cbSize; int m1[5]; LOGFONTA cap; int m2[2]; LOGFONTA smcap; int m3[2]; LOGFONTA menu, status, msg; } K_NCMA;
typedef struct { UINT cbSize; int h, v, wrap; LOGFONTW lf; } K_ICMW;
typedef struct { UINT cbSize; int h, v, wrap; LOGFONTA lf; } K_ICMA;
typedef struct { UINT cbSize; DWORD dwFlags; LPWSTR scheme; } K_HCW;

BOOL KEXAPI kex_SystemParametersInfoW(UINT act, UINT up, PVOID pv, UINT ini)
{
    switch (act) {
    case K_SPI_GETNONCLIENTMETRICS: case K_SPI_SETNONCLIENTMETRICS: {
        K_NCMW *w = (K_NCMW *)pv; K_NCMA a; BOOL r;
        if (!w || (w->cbSize != sizeof(K_NCMW) && w->cbSize != FIELD_OFFSET(K_NCMW, pad))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        ZeroMemory(&a, sizeof(a)); a.cbSize = sizeof(a);
        if (act == K_SPI_SETNONCLIENTMETRICS) {
            CopyMemory(a.m1, w->m1, sizeof(a.m1)); CopyMemory(a.m2, w->m2, sizeof(a.m2)); CopyMemory(a.m3, w->m3, sizeof(a.m3));
            lf_w2a(&w->cap, &a.cap); lf_w2a(&w->smcap, &a.smcap); lf_w2a(&w->menu, &a.menu); lf_w2a(&w->status, &a.status); lf_w2a(&w->msg, &a.msg);
            return kex_SystemParametersInfoA(act, sizeof(a), &a, ini);
        }
        if (!(r = kex_SystemParametersInfoA(act, sizeof(a), &a, ini))) return FALSE;
        CopyMemory(w->m1, a.m1, sizeof(a.m1)); CopyMemory(w->m2, a.m2, sizeof(a.m2)); CopyMemory(w->m3, a.m3, sizeof(a.m3));
        lf_a2w(&a.cap, &w->cap); lf_a2w(&a.smcap, &w->smcap); lf_a2w(&a.menu, &w->menu); lf_a2w(&a.status, &w->status); lf_a2w(&a.msg, &w->msg);
        if (w->cbSize == sizeof(K_NCMW)) w->pad = 0;
        return TRUE;
    }
    case K_SPI_GETICONTITLELOGFONT: case K_SPI_SETICONTITLELOGFONT: {
        LOGFONTA a;
        if (!pv) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        if (act == K_SPI_SETICONTITLELOGFONT) { lf_w2a((LOGFONTW *)pv, &a); return kex_SystemParametersInfoA(act, sizeof(a), &a, ini); }
        if (!kex_SystemParametersInfoA(act, sizeof(a), &a, ini)) return FALSE;
        lf_a2w(&a, (LOGFONTW *)pv);
        return TRUE;
    }
    case K_SPI_GETICONMETRICS: case K_SPI_SETICONMETRICS: {
        K_ICMW *w = (K_ICMW *)pv; K_ICMA a;
        if (!w || w->cbSize != sizeof(K_ICMW)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        ZeroMemory(&a, sizeof(a)); a.cbSize = sizeof(a);
        if (act == K_SPI_SETICONMETRICS) { a.h = w->h; a.v = w->v; a.wrap = w->wrap; lf_w2a(&w->lf, &a.lf); return kex_SystemParametersInfoA(act, sizeof(a), &a, ini); }
        if (!kex_SystemParametersInfoA(act, sizeof(a), &a, ini)) return FALSE;
        w->h = a.h; w->v = a.v; w->wrap = a.wrap; lf_a2w(&a.lf, &w->lf);
        return TRUE;
    }
    case K_SPI_GETHIGHCONTRAST: {
        K_HCW *w = (K_HCW *)pv; HIGHCONTRASTA a;
        if (!w) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        ZeroMemory(&a, sizeof(a)); a.cbSize = sizeof(a);
        if (!kex_SystemParametersInfoA(act, sizeof(a), &a, ini)) {   /* Win98 without accessibility: "off" (as KernelEx's A fix) */
            w->dwFlags = 0; w->scheme = NULL; return TRUE;
        }
        w->dwFlags = a.dwFlags; w->scheme = NULL;                    /* the ANSI scheme name is not handed over as UTF-16 */
        return TRUE;
    }
    case K_SPI_GETDESKWALLPAPER: {
        char buf[MAX_PATH]; WCHAR *out = (WCHAR *)pv;
        if (!out || !up) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        buf[0] = 0;
        if (!kex_SystemParametersInfoA(act, sizeof(buf), buf, ini)) return FALSE;
        if (!MultiByteToWideChar(CP_ACP, 0, buf, -1, out, (int)up)) out[0] = 0;
        out[up - 1] = 0;
        return TRUE;
    }
    case K_SPI_SETDESKWALLPAPER: {
        char buf[MAX_PATH];
        if (!pv || (ULONG_PTR)pv < 0x10000) return kex_SystemParametersInfoA(act, up, pv, ini);   /* SETWALLPAPER_DEFAULT etc. */
        if (!WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)pv, -1, buf, sizeof(buf), NULL, NULL)) buf[0] = 0;
        return kex_SystemParametersInfoA(act, up, buf, ini);
    }
    }
    return kex_SystemParametersInfoA(act, up, pv, ini);
}
