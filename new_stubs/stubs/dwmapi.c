/* dwmapi.dll stub for Windows 98 SE: there is no Desktop Window Manager; composition is "off". */
#include <windows.h>
HRESULT WINAPI DwmIsCompositionEnabled(BOOL *on) { if (!on) return E_INVALIDARG; *on = FALSE; return S_OK; }

/* build 45: no DWM to blend a "sheet of glass" window (all margins -1) - kexnt shapes it from its alpha instead
 * (layered_ext.c, at SwapBuffers). The call still reports composition as disabled, as before. */
typedef struct { int l, r, t, b; } KEX_MARGINS;
LONG WINAPI KexSetGlass(HWND h, LONG on);    /* kexnt.dll */
HRESULT WINAPI DwmExtendFrameIntoClientArea(HWND h, const KEX_MARGINS *m)
{
    if (h && m) KexSetGlass(h, m->l == -1 && m->r == -1 && m->t == -1 && m->b == -1);
    return (HRESULT)0x80263001L;   /* DWM_E_COMPOSITIONDISABLED */
}
