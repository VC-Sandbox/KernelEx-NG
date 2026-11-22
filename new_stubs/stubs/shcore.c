/* shcore.dll for Windows 98 SE (build 131): Inno Setup 6.4's setup program delay-loads GetDpiForMonitor and
 * GetProcessDpiAwareness once Windows reports 8.1 or newer. One system DPI on 98; no per-process awareness. */
#include <windows.h>
static UINT sys_dpi(void)
{
    HDC dc = GetDC(NULL); int d = dc ? GetDeviceCaps(dc, LOGPIXELSX) : 96;
    if (dc) ReleaseDC(NULL, dc);
    return d > 0 ? (UINT)d : 96;
}
HRESULT WINAPI GetDpiForMonitor(HMONITOR m, int type, UINT *x, UINT *y)
{
    UINT d;
    if (!x || !y) return E_INVALIDARG;
    d = sys_dpi(); *x = d; *y = d;
    return S_OK;
}
HRESULT WINAPI GetProcessDpiAwareness(HANDLE p, int *v)
{
    if (!v) return E_INVALIDARG;
    *v = 0;                        /* PROCESS_DPI_UNAWARE */
    return S_OK;
}
HRESULT WINAPI SetProcessDpiAwareness(int v) { return S_OK; }
