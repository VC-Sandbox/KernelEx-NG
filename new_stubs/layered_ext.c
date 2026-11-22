/* layered_ext.c - per-pixel-alpha layered windows on Windows 98 (2026-11-10, build 35).
 *
 * Chromium draws translucent windows (menus with their drop shadow, omnibox popup, bubbles) as WS_EX_LAYERED +
 * UpdateLayeredWindow(..., ULW_ALPHA) with a 32-bit premultiplied DIB (components/viz/host/
 * layered_window_updater_impl.cc). Windows 98 has no layered windows; KernelEx 4.5's UpdateLayeredWindow
 * (kexbases User32/window.c) moves the window and BitBlts the picture, ignoring alpha - every transparent pixel
 * (the shadow, the rounded corners) comes out black.
 *
 * Windows 98 cannot blend a window with what is behind it, but it can shape one: before KernelEx's blit, the
 * window gets a region made from the alpha channel (pixels below half opacity are cut out). Menus then show
 * without the black frame, with their rounded corners; the soft shadow itself is simply not there.
 * The region is rebuilt only when the shape changes (signature per window). Rows with the same runs are merged
 * into one rectangle, so a rounded menu is a handful of rectangles.
 */
#include "kexnt_common.h"
FARPROC kex_prev_impl(const char *dll, const char *name);
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

#ifndef ULW_ALPHA
#define ULW_ALPHA 2
#endif
#ifndef AC_SRC_ALPHA
#define AC_SRC_ALPHA 1
#endif
#define MAXRECTS 3000

typedef BOOL (WINAPI *T_ULW)(HWND, HDC, POINT *, SIZE *, HDC, POINT *, COLORREF, BLENDFUNCTION *, DWORD);
typedef HGDIOBJ (WINAPI *T_GCO)(HDC, UINT);
typedef int (WINAPI *T_GOA)(HGDIOBJ, int, LPVOID);
typedef HRGN (WINAPI *T_ECR)(const XFORM *, DWORD, const RGNDATA *);
typedef int (WINAPI *T_SWR)(HWND, HRGN, BOOL);
typedef BOOL (WINAPI *T_GWR)(HWND, LPRECT);
typedef BOOL (WINAPI *T_ISW)(HWND);

static T_GCO p_gco; static T_GOA p_goa; static T_ECR p_ecr; static T_SWR p_swr; static T_GWR p_gwr; static T_ISW p_isw;
static BOOL resolve(void)
{
    if (!p_gco) {
        p_goa = (T_GOA)(void *)kex_sysproc("GDI32.DLL", "GetObjectA");
        p_ecr = (T_ECR)(void *)kex_sysproc("GDI32.DLL", "ExtCreateRegion");
        p_swr = (T_SWR)(void *)kex_sysproc("USER32.DLL", "SetWindowRgn");
        p_gwr = (T_GWR)(void *)kex_sysproc("USER32.DLL", "GetWindowRect");
        p_isw = (T_ISW)(void *)kex_sysproc("USER32.DLL", "IsWindow");
        p_gco = (T_GCO)(void *)kex_sysproc("GDI32.DLL", "GetCurrentObject");
    }
    return p_gco && p_goa && p_ecr && p_swr && p_gwr && p_isw;
}

#define NCACHE 64
static struct { HWND h; DWORD sig; BOOL shaped; HRGN mine; } g_c[NCACHE];
static volatile LONG g_lk;

typedef struct { RGNDATAHEADER h; RECT r[MAXRECTS]; } RGNBUF;
/* build 45: glass windows - did the window's region change since we set it? (the program resets it on resize) */
typedef int (WINAPI *T_GWRG)(HWND, HRGN);
typedef HRGN (WINAPI *T_CRR)(int, int, int, int);
typedef int (WINAPI *T_CMB)(HRGN, HRGN, HRGN, int);
typedef BOOL (WINAPI *T_EQR)(HRGN, HRGN);
typedef BOOL (WINAPI *T_DO)(HGDIOBJ);
static void remember_rgn(int slot, HRGN rgn)
{
    T_CRR crr = (T_CRR)(void *)kex_sysproc("GDI32.DLL", "CreateRectRgn");
    T_CMB cmb = (T_CMB)(void *)kex_sysproc("GDI32.DLL", "CombineRgn");
    T_DO del = (T_DO)(void *)kex_sysproc("GDI32.DLL", "DeleteObject");
    HRGN c;
    if (!crr || !cmb || !del) return;
    if (g_c[slot].mine) { del(g_c[slot].mine); g_c[slot].mine = NULL; }
    if ((c = crr(0, 0, 0, 0)) != NULL) { if (cmb(c, rgn, NULL, RGN_COPY) != ERROR) g_c[slot].mine = c; else del(c); }
}
static BOOL region_changed(HWND hwnd, int slot)
{
    T_GWRG gwrg = (T_GWRG)(void *)kex_sysproc("USER32.DLL", "GetWindowRgn");
    T_CRR crr = (T_CRR)(void *)kex_sysproc("GDI32.DLL", "CreateRectRgn");
    T_EQR eqr = (T_EQR)(void *)kex_sysproc("GDI32.DLL", "EqualRgn");
    T_DO del = (T_DO)(void *)kex_sysproc("GDI32.DLL", "DeleteObject");
    HRGN cur; BOOL ch = TRUE;
    if (!g_c[slot].mine || !gwrg || !crr || !eqr || !del) return TRUE;
    if (!(cur = crr(0, 0, 0, 0))) return TRUE;
    if (gwrg(hwnd, cur) != ERROR) ch = !eqr(cur, g_c[slot].mine);
    del(cur);
    return ch;
}


/* runs of alpha >= 128 in one row: start/end pairs into run[], returns count (max 64 runs, else -1) */
static int row_runs(const BYTE *px, int w, int *run)
{
    int x = 0, n = 0;
    while (x < w) {
        while (x < w && px[x * 4 + 3] < 128) x++;
        if (x >= w) break;
        if (n >= 64) return -1;
        run[2 * n] = x;
        while (x < w && px[x * 4 + 3] >= 128) x++;
        run[2 * n + 1] = x;
        n++;
    }
    return n;
}

/* build 51: SetWindowRgn must run on the window's own thread. Chromium calls SwapBuffers on its GPU thread, the
 * menu window belongs to the UI thread: USER's SetWindowRgn then has to send messages across threads (the UI
 * thread is often waiting for that very frame) - the shape never stuck and the menus flashed. A region made on
 * another thread is queued here and applied by the window's thread the next time it makes any guarded USER/GDI
 * call (gdiguard_ext.c asks kex_glass_pending); a WM_NULL is posted so that happens at once. */
#define NPEND 16
static struct { HWND h; HRGN r; int used; int hasr; int mv; RECT mr; } g_pend[NPEND];
volatile LONG kex_glass_pending;
static volatile LONG g_pendlk;
typedef DWORD (WINAPI *T_GWTP)(HWND, LPDWORD);
typedef BOOL (WINAPI *T_PM)(HWND, UINT, WPARAM, LPARAM);
typedef BOOL (WINAPI *T_MW)(HWND, int, int, int, int, BOOL);
static void glass_note(const char *what, HWND w, DWORD a, DWORD b);
static void set_rgn(HWND hwnd, HRGN rgn)
{
    T_GWTP gwtp = (T_GWTP)(void *)kex_sysproc("USER32.DLL", "GetWindowThreadProcessId");
    T_PM pm = (T_PM)(void *)kex_sysproc("USER32.DLL", "PostMessageA");
    T_DO del = (T_DO)(void *)kex_sysproc("GDI32.DLL", "DeleteObject");
    DWORD wt = gwtp ? gwtp(hwnd, NULL) : 0; int i, fr = -1; HRGN old = NULL;
    static LONG said;
    { extern volatile LONG kex_st_swr_kex; InterlockedIncrement(&kex_st_swr_kex); }
    if (!wt || wt == GetCurrentThreadId() || !pm) {
        if (!p_swr(hwnd, rgn, TRUE) && rgn && del) del(rgn);
        return;
    }
    if (!InterlockedExchange(&said, 1)) glass_note("region made on another thread - queued for the window's thread (window thread, this thread)", hwnd, wt, GetCurrentThreadId());
    kex_spin_acquire(&g_pendlk);
    for (i = 0; i < NPEND; i++) { if (g_pend[i].used && g_pend[i].h == hwnd) break; if (fr < 0 && !g_pend[i].used) fr = i; }
    if (i < NPEND) { old = g_pend[i].hasr ? g_pend[i].r : NULL; g_pend[i].r = rgn; g_pend[i].hasr = 1; }
    else if (fr >= 0) { g_pend[fr].h = hwnd; g_pend[fr].r = rgn; g_pend[fr].hasr = 1; g_pend[fr].mv = 0; g_pend[fr].used = 1; InterlockedIncrement(&kex_glass_pending); }
    else old = rgn;                                         /* queue full: drop this one */
    InterlockedExchange(&g_pendlk, 0);
    if (old && del) del(old);
    pm(hwnd, 0 /* WM_NULL */, 0, 0);
}
/* gdiguard_ext.c, on every guarded call while something is queued: apply what belongs to this thread */
void kex_glass_apply_pending(void)
{
    T_GWTP gwtp; T_DO del; DWORD me = GetCurrentThreadId(); int i;
    static LONG said;
    if (!kex_glass_pending || !resolve()) return;
    gwtp = (T_GWTP)(void *)kex_sysproc("USER32.DLL", "GetWindowThreadProcessId");
    del = (T_DO)(void *)kex_sysproc("GDI32.DLL", "DeleteObject");
    if (!gwtp) return;
    for (i = 0; i < NPEND; i++) {
        HWND h = NULL; HRGN r = NULL; int take = 0, hasr = 0, mv = 0; RECT mr;
        if (!g_pend[i].used) continue;
        kex_spin_acquire(&g_pendlk);
        if (g_pend[i].used) {
            DWORD wt = p_isw(g_pend[i].h) ? gwtp(g_pend[i].h, NULL) : 0;
            if (!wt || wt == me) {
                h = g_pend[i].h; r = g_pend[i].r; hasr = g_pend[i].hasr; mv = g_pend[i].mv; mr = g_pend[i].mr;
                g_pend[i].used = 0; g_pend[i].r = NULL; g_pend[i].hasr = 0; g_pend[i].mv = 0;
                InterlockedDecrement(&kex_glass_pending); take = wt ? 1 : 2;
            }
        }
        InterlockedExchange(&g_pendlk, 0);
        if (take == 1 && mv) {                               /* build 132: queued UpdateLayeredWindow move */
            static T_MW mw; static LONG saidmv;
            if (!mw) mw = (T_MW)(void *)kex_sysproc("USER32.DLL", "MoveWindow");
            if (mw) mw(h, mr.left, mr.top, mr.right - mr.left, mr.bottom - mr.top, FALSE);
            if (!InterlockedExchange(&saidmv, 1)) glass_note("queued layered-window move applied on the window's thread (x, y)", h, (DWORD)mr.left, (DWORD)mr.top);
        }
        if (take == 1 && hasr) {
            BOOL ok = p_swr(h, r, TRUE);
            if (!InterlockedExchange(&said, 1)) glass_note("queued region applied on the window's thread (result, error)", h, (DWORD)ok, ok ? 0 : GetLastError());
            if (!ok && r && del) del(r);
        } else if (take == 2 && hasr && r && del) del(r);   /* the window is gone */
    }
}

/* build 45: the region is built from any 32-bit pixel memory (row 0 = top when !bottomup); `recheck` = also
 * re-apply when someone else changed the window's region since (glass windows: the program resets it itself) */
static void shape_px(HWND hwnd, const BYTE *bits, LONG stride, int bmh, int px0, int py0, int w, int h, BOOL bottomup, BOOL recheck);
static void shape(HWND hwnd, HDC src, const POINT *ps, const SIZE *sz)
{
    HGDIOBJ bm; DIBSECTION ds; int w, h;
    if (!resolve() || !src || !ps) return;
    bm = p_gco(src, OBJ_BITMAP);
    if (!bm || p_goa(bm, sizeof(ds), &ds) != (int)sizeof(ds) || !ds.dsBm.bmBits || ds.dsBm.bmBitsPixel != 32) return;
    if (sz) { w = sz->cx; h = sz->cy; }
    else { RECT wr; if (!p_gwr(hwnd, &wr)) return; w = wr.right - wr.left; h = wr.bottom - wr.top; }
    if (ps->x < 0 || ps->y < 0) return;
    if (w > ds.dsBm.bmWidth - ps->x) w = ds.dsBm.bmWidth - ps->x;
    if (h > ds.dsBm.bmHeight - ps->y) h = ds.dsBm.bmHeight - ps->y;
    if (w <= 0 || h <= 0) return;
    shape_px(hwnd, (const BYTE *)ds.dsBm.bmBits, ds.dsBm.bmWidthBytes, ds.dsBm.bmHeight, ps->x, ps->y, w, h, ds.dsBmih.biHeight > 0, FALSE);
}
static void shape_px(HWND hwnd, const BYTE *bits, LONG stride, int bmh, int px0, int py0, int w, int h, BOOL bottomup, BOOL recheck)
{
    int y, i, prevn = -1, nrect = 0, open0 = 0, slot;
    int run[128], prev[128]; DWORD sig = 2166136261UL;
    BOOL full;
    RGNBUF *rb;
    if (!resolve()) return;
    rb = (RGNBUF *)HeapAlloc(GetProcessHeap(), 0, sizeof(RGNBUF));
    if (!rb) return;
    full = TRUE;
    for (y = 0; y < h; y++) {
        int sy = py0 + y, n, same;
        const BYTE *row = bits + (bottomup ? (LONG)(bmh - 1 - sy) : (LONG)sy) * stride + px0 * 4;
        n = row_runs(row, w, run);
        if (n < 0) { HeapFree(GetProcessHeap(), 0, rb); return; }   /* too ragged: leave the window square */
        if (!(n == 1 && run[0] == 0 && run[1] == w)) full = FALSE;
        same = (n == prevn);
        for (i = 0; same && i < 2 * n; i++) if (run[i] != prev[i]) same = 0;
        if (same) {                                         /* extend the rectangles of the previous row */
            for (i = 0; i < n; i++) rb->r[open0 + i].bottom = y + 1;
        } else {
            if (nrect + n > MAXRECTS) { HeapFree(GetProcessHeap(), 0, rb); return; }
            open0 = nrect;
            for (i = 0; i < n; i++) {
                rb->r[nrect].left = run[2 * i]; rb->r[nrect].right = run[2 * i + 1];
                rb->r[nrect].top = y; rb->r[nrect].bottom = y + 1; nrect++;
            }
            for (i = 0; i < 2 * n; i++) prev[i] = run[i];
            prevn = n;
            sig = (sig ^ (DWORD)y) * 16777619UL;
            for (i = 0; i < 2 * n; i++) sig = (sig ^ (DWORD)run[i]) * 16777619UL;
        }
    }
    sig = (sig ^ (DWORD)w) * 16777619UL; sig = (sig ^ (DWORD)h) * 16777619UL;

    kex_spin_acquire(&g_lk);
    for (slot = 0; slot < NCACHE && g_c[slot].h != hwnd; slot++) ;
    if (slot == NCACHE) {
        for (slot = 0; slot < NCACHE && g_c[slot].h && p_isw(g_c[slot].h); slot++) ;
        if (slot == NCACHE) slot = (int)(((ULONG_PTR)hwnd >> 2) % NCACHE);
        g_c[slot].h = hwnd; g_c[slot].sig = 0; g_c[slot].shaped = FALSE;
    }
    if (full) {
        BOOL was = g_c[slot].shaped;
        g_c[slot].shaped = FALSE; g_c[slot].sig = 0;
        InterlockedExchange((LONG *)&g_lk, 0);
        if (was) set_rgn(hwnd, NULL);
    } else if (g_c[slot].shaped && g_c[slot].sig == sig && !(recheck && region_changed(hwnd, slot))) {
        InterlockedExchange((LONG *)&g_lk, 0);                       /* same shape as last frame */
    } else {
        HRGN rgn;
        g_c[slot].sig = sig; g_c[slot].shaped = TRUE;
        InterlockedExchange((LONG *)&g_lk, 0);
        rb->h.dwSize = sizeof(RGNDATAHEADER); rb->h.iType = RDH_RECTANGLES; rb->h.nCount = (DWORD)nrect;
        rb->h.nRgnSize = (DWORD)nrect * sizeof(RECT);
        rb->h.rcBound.left = 0; rb->h.rcBound.top = 0; rb->h.rcBound.right = w; rb->h.rcBound.bottom = h;
        rgn = p_ecr(NULL, sizeof(RGNDATAHEADER) + (DWORD)nrect * sizeof(RECT), (const RGNDATA *)rb);
        if (rgn && recheck) remember_rgn(slot, rgn);
        if (rgn) set_rgn(hwnd, rgn);
        else { static LONG k; if (InterlockedIncrement(&k) <= 10) kex_trace("UpdateLayeredWindow: ExtCreateRegion failed", (DWORD)nrect, (DWORD)w, (DWORD)h, GetLastError()); }
    }
    HeapFree(GetProcessHeap(), 0, rb);
}

/* build 132: a move made on another thread is queued for the window's thread (like set_rgn above) */
static void queue_move(HWND hwnd, const RECT *r)
{
    T_PM pm = (T_PM)(void *)kex_sysproc("USER32.DLL", "PostMessageA");
    int i, fr = -1; static LONG said;
    if (!InterlockedExchange(&said, 1)) glass_note("layered-window move made on another thread - queued for the window's thread (x, y)", hwnd, (DWORD)r->left, (DWORD)r->top);
    kex_spin_acquire(&g_pendlk);
    for (i = 0; i < NPEND; i++) { if (g_pend[i].used && g_pend[i].h == hwnd) break; if (fr < 0 && !g_pend[i].used) fr = i; }
    if (i < NPEND) { g_pend[i].mv = 1; g_pend[i].mr = *r; }
    else if (fr >= 0) { g_pend[fr].h = hwnd; g_pend[fr].hasr = 0; g_pend[fr].r = NULL; g_pend[fr].mv = 1; g_pend[fr].mr = *r; g_pend[fr].used = 1; InterlockedIncrement(&kex_glass_pending); }
    InterlockedExchange(&g_pendlk, 0);
    if (pm) pm(hwnd, 0 /* WM_NULL */, 0, 0);
}

/* build 132: KernelEx 4.5's UpdateLayeredWindow (kexbases User32/window.c) always calls MoveWindow, then BitBlts.
 * Firefox calls UpdateLayeredWindow from its Renderer thread (InProcessWinCompositorWidget::
 * RedrawTransparentWindow) for popups owned by the main thread; MoveWindow on another thread's window sends
 * messages to that thread and waits. The main thread was itself waiting for the Renderer (WM_PAINT ->
 * FlushRendering) - a deadlock that froze Firefox at its first popup. Here the same work is done without waiting:
 * no move when position and size are unchanged, and a move from another thread is queued for the window's thread.
 * Calls on the window's own thread, and calls the old code did not handle, behave exactly as before. */
typedef LONG (WINAPI *T_GWL)(HWND, int);
typedef HDC (WINAPI *T_GDC)(HWND);
typedef int (WINAPI *T_RDC)(HWND, HDC);
typedef BOOL (WINAPI *T_BB)(HDC, int, int, int, int, HDC, int, int, DWORD);
BOOL KEXAPI kex_UpdateLayeredWindow(HWND hwnd, HDC dst, POINT *pdst, SIZE *psize, HDC src, POINT *psrc,
                                    COLORREF key, BLENDFUNCTION *blend, DWORD flags)
{
    static T_ULW prev; static T_GWL gwl; static T_GWTP gwtp; static T_GDC gdc; static T_RDC rdc; static T_BB bb;
    RECT rc, nr; HDC hdc; BOOL ret;
    if (!prev) prev = (T_ULW)(void *)kex_prev_impl("USER32.DLL", "UpdateLayeredWindow");
    if ((flags & ULW_ALPHA) && blend && (blend->AlphaFormat & AC_SRC_ALPHA) && src && psrc) shape(hwnd, src, psrc, psize);
    if (!prev || (void *)prev == (void *)kex_UpdateLayeredWindow) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    if (!gwl) {
        gwtp = (T_GWTP)(void *)kex_sysproc("USER32.DLL", "GetWindowThreadProcessId");
        gdc = (T_GDC)(void *)kex_sysproc("USER32.DLL", "GetDC");
        rdc = (T_RDC)(void *)kex_sysproc("USER32.DLL", "ReleaseDC");
        bb = (T_BB)(void *)kex_sysproc("GDI32.DLL", "BitBlt");
        gwl = (T_GWL)(void *)kex_sysproc("USER32.DLL", "GetWindowLongA");
    }
    if (!resolve() || !gwl || !gwtp || !gdc || !rdc || !bb || !src || !psrc ||
        !(gwl(hwnd, GWL_EXSTYLE) & WS_EX_LAYERED) || !p_gwr(hwnd, &rc))
        return prev(hwnd, dst, pdst, psize, src, psrc, key, blend, flags);
    nr = rc;
    if (pdst) { nr.right += pdst->x - nr.left; nr.bottom += pdst->y - nr.top; nr.left = pdst->x; nr.top = pdst->y; }
    if (psize) { nr.right = nr.left + psize->cx; nr.bottom = nr.top + psize->cy; }
    if (nr.left != rc.left || nr.top != rc.top || nr.right != rc.right || nr.bottom != rc.bottom) {
        if (gwtp(hwnd, NULL) == GetCurrentThreadId()) {
            T_MW mw = (T_MW)(void *)kex_sysproc("USER32.DLL", "MoveWindow");
            if (mw) mw(hwnd, nr.left, nr.top, nr.right - nr.left, nr.bottom - nr.top, FALSE);
        } else queue_move(hwnd, &nr);
    }
    if (!(hdc = gdc(hwnd))) return FALSE;
    ret = bb(hdc, 0, 0, nr.right - nr.left, nr.bottom - nr.top, src, psrc->x, psrc->y, SRCCOPY);
    rdc(hwnd, hdc);
    return ret;
}

/* ---- build 45: "sheet of glass" windows drawn with OpenGL.
 * Chromium with GPU compositing draws translucent windows (menus, bubbles, the omnibox popup) straight into the
 * HWND with an alpha channel and calls DwmExtendFrameIntoClientArea(-1) so the Desktop Window Manager blends them
 * (ui/views/win/hwnd_message_handler.cc OnCreate). Windows 98 has no DWM: the transparent pixels came out as raw
 * buffer colours (blue/black margins, flashing). The dwmapi stub marks such windows (KexSetGlass); before each
 * SwapBuffers on one, kexnt reads the back buffer's alpha (glReadPixels) and shapes the window from it, the same way
 * as layered windows above. Nothing happens for windows that did not ask for glass, or without an alpha channel. */
#define NGLASS 32
static HWND g_glass[NGLASS];
void kex_crashlog_text(const char *s);   /* crashlog_ext.c */
/* build 46: what happened to glass windows goes to KEXCRASH_<program>.LOG (always on, at most 40 lines) */
static void glass_note(const char *what, HWND w, DWORD a, DWORD b)
{
    static LONG n; char t[160]; int l; DWORD v[3]; int k, j;
    if (InterlockedIncrement(&n) > 120) return;
    lstrcpyA(t, "--- glass window "); l = lstrlenA(t);
    v[0] = (DWORD)(ULONG_PTR)w; v[1] = a; v[2] = b;
    for (k = 0; k < 3; k++) { for (j = 7; j >= 0; j--) t[l++] = "0123456789abcdef"[(v[k] >> (j * 4)) & 15]; t[l++] = ' '; }
    t[l] = 0; lstrcatA(t, what); kex_crashlog_text(t);
}
LONG KEXAPI kex_KexSetGlass(HWND h, LONG on)
{
    int i, fr = -1;
    if (!h) return 0;
    kex_spin_acquire(&g_lk);
    for (i = 0; i < NGLASS; i++) { if (g_glass[i] == h) break; if (fr < 0 && (!g_glass[i] || (resolve() && !p_isw(g_glass[i])))) fr = i; }
    if (on) { if (i == NGLASS && fr >= 0) g_glass[fr] = h; }
    else if (i < NGLASS) g_glass[i] = NULL;
    InterlockedExchange((LONG *)&g_lk, 0);
    glass_note(on ? "marked (DwmExtendFrameIntoClientArea -1)" : "unmarked", h, 0, 0);
    return 1;
}
static BOOL is_glass(HWND h)
{
    int i;
    if (!h) return FALSE;
    for (i = 0; i < NGLASS; i++) if (g_glass[i] == h) return TRUE;
    return FALSE;
}

/* build 50: Chromium resets a window's region itself (SetWindowRgn(hwnd, NULL) from HWNDMessageHandler when it is
 * shown / moved / resized). On NT that is right - DWM blends a glass window by its alpha - but here our shape was
 * thrown away after the menu's last frame (the fade-in) and the menu stayed a blue rectangle. kexnt's SetWindowRgn
 * asks this first: for a glass window with a shape, a NULL region becomes a copy of that shape. */
HRGN kex_glass_region(HWND h)
{
    int slot; HRGN c = NULL;
    T_CRR crr = (T_CRR)(void *)kex_sysproc("GDI32.DLL", "CreateRectRgn");
    T_CMB cmb = (T_CMB)(void *)kex_sysproc("GDI32.DLL", "CombineRgn");
    T_DO del = (T_DO)(void *)kex_sysproc("GDI32.DLL", "DeleteObject");
    if (!h || !is_glass(h) || !crr || !cmb || !del) return NULL;
    kex_spin_acquire(&g_lk);
    for (slot = 0; slot < NCACHE && g_c[slot].h != h; slot++) ;
    if (slot < NCACHE && g_c[slot].shaped && g_c[slot].mine && (c = crr(0, 0, 0, 0)) != NULL &&
        cmb(c, g_c[slot].mine, NULL, RGN_COPY) == ERROR) { del(c); c = NULL; }
    InterlockedExchange((LONG *)&g_lk, 0);
    return c;
}

typedef HWND (WINAPI *T_WFDC)(HDC);
typedef HWND (WINAPI *T_GANC)(HWND, UINT);
typedef BOOL (WINAPI *T_GCR)(HWND, LPRECT);
typedef int (WINAPI *T_GPF)(HDC);
typedef int (WINAPI *T_DPF)(HDC, int, UINT, LPPIXELFORMATDESCRIPTOR);
typedef void (WINAPI *T_GLRP)(int, int, int, int, unsigned, unsigned, void *);
typedef void (WINAPI *T_GLGI)(unsigned, int *);
typedef void (WINAPI *T_GLPI)(unsigned, int);
typedef void (WINAPI *T_GLRB)(unsigned);
typedef void (WINAPI *T_GLBF)(unsigned, unsigned);
typedef unsigned (WINAPI *T_GLGE)(void);
typedef void *(WINAPI *T_WGCC)(void);
typedef PROC (WINAPI *T_WGPA)(LPCSTR);

void kex_glass_before_swap(HDC dc)
{
    static T_WFDC wfdc; static T_GANC ganc; static T_GCR gcr; static T_GPF gpf; static T_DPF dpf;
    static T_GLRP rp; static T_GLGI gi; static T_GLPI pi; static T_GLRB rb; static T_GLGE ge; static T_WGCC wgcc;
    static T_GLBF bfb, bbuf; static LONG got, notalpha;
    HWND w, root; RECT cr, wr, rr; int pf, cw, ch, xo, yo, i, n; PIXELFORMATDESCRIPTOR pfd; BYTE *buf;
    int sv_fb = 0, sv_pbo = 0, sv_align = 4, sv_rb = 0x0405;
    {   int any = 0; for (i = 0; i < NGLASS; i++) if (g_glass[i]) { any = 1; break; } if (!any) return; }
    if (!InterlockedExchange(&got, 1)) {
        HMODULE gl = GetModuleHandleA("OPENGL32.DLL");
        wfdc = (T_WFDC)(void *)kex_sysproc("USER32.DLL", "WindowFromDC");
        ganc = (T_GANC)(void *)kex_sysproc("USER32.DLL", "GetAncestor");
        gcr = (T_GCR)(void *)kex_sysproc("USER32.DLL", "GetClientRect");
        gpf = (T_GPF)(void *)kex_sysproc("GDI32.DLL", "GetPixelFormat");
        dpf = (T_DPF)(void *)kex_sysproc("GDI32.DLL", "DescribePixelFormat");
        if (gl) {
            T_WGPA wgpa = (T_WGPA)(void *)GetProcAddress(gl, "wglGetProcAddress");
            rp = (T_GLRP)(void *)GetProcAddress(gl, "glReadPixels"); gi = (T_GLGI)(void *)GetProcAddress(gl, "glGetIntegerv");
            pi = (T_GLPI)(void *)GetProcAddress(gl, "glPixelStorei"); rb = (T_GLRB)(void *)GetProcAddress(gl, "glReadBuffer");
            ge = (T_GLGE)(void *)GetProcAddress(gl, "glGetError"); wgcc = (T_WGCC)(void *)GetProcAddress(gl, "wglGetCurrentContext");
            if (wgpa) { bfb = (T_GLBF)(void *)wgpa("glBindFramebuffer"); bbuf = (T_GLBF)(void *)wgpa("glBindBuffer"); }
        }
    }
    if (!wfdc || !ganc || !gcr || !gpf || !dpf || !rp || !gi || !pi || !rb || !ge || !wgcc || !resolve()) return;
    if (!(w = wfdc(dc))) return;
    root = ganc(w, 2 /* GA_ROOT */);
    if (!is_glass(w) && !is_glass(root)) {
        static HWND seen[16]; static int ns; int q;
        for (q = 0; q < ns && seen[q] != w; q++) ;
        if (q == ns && ns < 16) { seen[ns++] = w; glass_note("SwapBuffers on a window that is not glass (window, root)", w, (DWORD)(ULONG_PTR)root, 0); }
        return;
    }
    if (!root) root = w;
    if (!wgcc()) { glass_note("no current GL context at SwapBuffers", w, 0, 0); return; }
    pf = gpf(dc);
    if (pf <= 0 || !dpf(dc, pf, sizeof(pfd), &pfd) || pfd.cAlphaBits == 0) {
        if (!InterlockedExchange(&notalpha, 1)) glass_note("pixel format has no alpha - not shaped (pf, alpha bits)", w, (DWORD)pf, pf > 0 ? pfd.cAlphaBits : 0);
        return;
    }
    if (!gcr(w, &cr) || (cw = cr.right) <= 0 || (ch = cr.bottom) <= 0 || cw > 4096 || ch > 4096) return;
    /* where the GL window's client area sits inside the root window (region coordinates are window-relative) */
    if (!p_gwr(root, &rr)) return;
    { POINT o = {0, 0}; typedef BOOL (WINAPI *T_C2S)(HWND, LPPOINT);
      T_C2S c2s = (T_C2S)(void *)kex_sysproc("USER32.DLL", "ClientToScreen");
      if (!c2s || !c2s(w, &o)) return; xo = o.x - rr.left; yo = o.y - rr.top; wr = rr; }
    if (xo != 0 || yo != 0 || cw != wr.right - wr.left || ch != wr.bottom - wr.top) {   /* only the simple case: GL fills the root window */
        static LONG k; if (InterlockedIncrement(&k) <= 5) glass_note("GL area is not the whole window - not shaped (offset x<<16|y, size w<<16|h)", w, (DWORD)(xo << 16 | (yo & 0xFFFF)), (DWORD)(cw << 16 | ch));
        return;
    }
    if (!(buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)cw * ch * 4))) return;
    while (ge() != 0) ;                                      /* nothing of the program's pending */
    gi(0x8CAA /* READ_FRAMEBUFFER_BINDING */, &sv_fb); gi(0x88ED /* PIXEL_PACK_BUFFER_BINDING */, &sv_pbo);
    gi(0x0D05 /* PACK_ALIGNMENT */, &sv_align); gi(0x0C02 /* READ_BUFFER */, &sv_rb);
    while (ge() != 0) ;
    if (bfb) bfb(0x8CA8 /* READ_FRAMEBUFFER */, 0);
    if (bbuf) bbuf(0x88EB /* PIXEL_PACK_BUFFER */, 0);
    pi(0x0D05, 4); rb(0x0405 /* BACK */);
    rp(0, 0, cw, ch, 0x80E1 /* BGRA */, 0x1401 /* UNSIGNED_BYTE */, buf);
    n = (int)ge();
    rb((unsigned)sv_rb); pi(0x0D05, sv_align);
    if (bbuf) bbuf(0x88EB, (unsigned)sv_pbo);
    if (bfb) bfb(0x8CA8, (unsigned)sv_fb);
    while (ge() != 0) ;
    if (n == 0) {
        /* build 48: the first 4 frames of each glass window: how its alpha looks (counts of a=0 / 1-127 / 128-254 / 255)
         * and three pixels (top-left, centre, a quarter in) as BGRA - menus were still blue with "0 opaque samples" */
        static struct { HWND h; int k; } seen[24]; static int ns; int q, j; DWORD hist[4] = {0, 0, 0, 0};
        for (j = 3; j < cw * ch * 4; j += 4) { BYTE a = buf[j]; hist[a == 0 ? 0 : a < 128 ? 1 : a < 255 ? 2 : 3]++; }
        for (q = 0; q < ns && seen[q].h != root; q++) ;
        if (q == ns && ns < 24) { seen[ns].h = root; seen[ns].k = 0; ns++; }
        if (q < ns && seen[q].k < 4) {
            DWORD tl = *(DWORD *)(buf + (SIZE_T)(ch - 1) * cw * 4), mid = *(DWORD *)(buf + ((SIZE_T)(ch / 2) * cw + cw / 2) * 4),
                  qu = *(DWORD *)(buf + ((SIZE_T)(ch * 3 / 4) * cw + cw / 4) * 4);
            seen[q].k++;
            glass_note("frame: size w<<16|h, alpha 0 count", root, (DWORD)(cw << 16 | ch), hist[0]);
            glass_note("       alpha 1-127, 128-254", root, hist[1], hist[2]);
            glass_note("       alpha 255, pixel top-left (BGRA)", root, hist[3], tl);
            glass_note("       pixel centre, pixel quarter", root, mid, qu);
        }
        shape_px(root, buf, (LONG)cw * 4, ch, 0, 0, cw, ch, TRUE /* GL rows are bottom-up */, TRUE);
    } else { static LONG k; if (InterlockedIncrement(&k) <= 5) glass_note("glReadPixels failed (GL error)", w, (DWORD)n, 0); }
    HeapFree(GetProcessHeap(), 0, buf);
}

/* ---- build 53: keep the back buffer after SwapBuffers ("copy" swap, as Windows' own drivers behave).
 * Chromium redraws only the part of a window that changed (partial swap / damage) and expects every other pixel
 * of the back buffer to still hold the previous frame. Mesa's WGL (SoftGPU, SVGA3D) swaps by exchanging the two
 * buffers, so after SwapBuffers the back buffer holds the frame before last: menus stayed at an old step of their
 * fade-in except the row under the mouse, web content showed old frames and the blue that Chromium's debug build
 * clears unfinished areas with, and windows flashed between two frames. After each SwapBuffers kexnt copies the
 * frame just shown (front) back into the back buffer with glBlitFramebuffer (GL 3.0+), restoring all state it
 * touches. Only for the DC current on this thread and double-buffered pixel formats. KexNG\GLKeepBack = 0 turns
 * it off (registry, DWORD). */
typedef void (WINAPI *T_GLBLIT)(int, int, int, int, int, int, int, int, unsigned, unsigned);
typedef void (WINAPI *T_GLEN)(unsigned);
typedef unsigned char (WINAPI *T_GLISEN)(unsigned);
typedef HDC (WINAPI *T_WGCD)(void);
static LONG g_keep = -1;
static LONG keep_on(void)
{
    if (g_keep < 0) {
        HKEY k; DWORD v = 0, t, n = sizeof(v);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_READ, &k) == ERROR_SUCCESS) {
            if (RegQueryValueExA(k, "GLKeepBack", NULL, &t, (BYTE *)&v, &n) != ERROR_SUCCESS || t != REG_DWORD) v = 0;   /* build 54: off by default - SoftGPU already keeps the back buffer (kextest) */
            RegCloseKey(k);
        }
        InterlockedExchange(&g_keep, v ? 1 : 0);
    }
    return g_keep;
}
void kex_gl_keep_back(HDC dc)
{
    static T_WGCD wgcd; static T_WGPA wgpa; static T_GLGI gi; static T_GLRB rb, db; static T_GLEN en, dis; static T_GLISEN isen;
    static T_WFDC wfdc; static T_GCR gcr; static T_GPF gpf; static T_DPF dpf; static LONG got; static LONG said;
    T_GLBF bfb; T_GLBLIT blit; HWND w; RECT cr; int pf, rfb = 0, dfb = 0, rbuf = 0x0405, dbuf = 0x0405, sc, srgb;
    PIXELFORMATDESCRIPTOR pfd;
    if (!keep_on()) return;
    if (!InterlockedExchange(&got, 1)) {
        HMODULE gl = GetModuleHandleA("OPENGL32.DLL");
        if (gl) {
            wgcd = (T_WGCD)(void *)GetProcAddress(gl, "wglGetCurrentDC"); wgpa = (T_WGPA)(void *)GetProcAddress(gl, "wglGetProcAddress");
            gi = (T_GLGI)(void *)GetProcAddress(gl, "glGetIntegerv"); rb = (T_GLRB)(void *)GetProcAddress(gl, "glReadBuffer");
            db = (T_GLRB)(void *)GetProcAddress(gl, "glDrawBuffer"); en = (T_GLEN)(void *)GetProcAddress(gl, "glEnable");
            dis = (T_GLEN)(void *)GetProcAddress(gl, "glDisable"); isen = (T_GLISEN)(void *)GetProcAddress(gl, "glIsEnabled");
        }
        wfdc = (T_WFDC)(void *)kex_sysproc("USER32.DLL", "WindowFromDC");
        gcr = (T_GCR)(void *)kex_sysproc("USER32.DLL", "GetClientRect");
        gpf = (T_GPF)(void *)kex_sysproc("GDI32.DLL", "GetPixelFormat");
        dpf = (T_DPF)(void *)kex_sysproc("GDI32.DLL", "DescribePixelFormat");
    }
    if (!wgcd || !wgpa || !gi || !rb || !db || !en || !dis || !isen || !wfdc || !gcr || !gpf || !dpf) return;
    if (wgcd() != dc) return;                                       /* not the DC this thread draws to */
    pf = gpf(dc);
    if (pf <= 0 || !dpf(dc, pf, sizeof(pfd), &pfd) || !(pfd.dwFlags & PFD_DOUBLEBUFFER)) return;
    /* context-dependent in principle: look them up each time (cheap, one driver) */
    bfb = (T_GLBF)(void *)wgpa("glBindFramebuffer");
    blit = (T_GLBLIT)(void *)wgpa("glBlitFramebuffer");
    if (!bfb || !blit) return;                                      /* GL < 3.0: nothing to do it with */
    if (!(w = wfdc(dc)) || !gcr(w, &cr) || cr.right <= 0 || cr.bottom <= 0) return;
    gi(0x8CAA /* READ_FRAMEBUFFER_BINDING */, &rfb); gi(0x8CA6 /* DRAW_FRAMEBUFFER_BINDING */, &dfb);
    bfb(0x8CA8 /* READ_FRAMEBUFFER */, 0); bfb(0x8CA9 /* DRAW_FRAMEBUFFER */, 0);
    gi(0x0C02 /* READ_BUFFER */, &rbuf); gi(0x0C01 /* DRAW_BUFFER */, &dbuf);
    sc = isen(0x0C11 /* SCISSOR_TEST */); srgb = isen(0x8DB9 /* FRAMEBUFFER_SRGB */);
    if (sc) dis(0x0C11);
    if (srgb) dis(0x8DB9);
    rb(0x0404 /* FRONT */); db(0x0405 /* BACK */);
    blit(0, 0, cr.right, cr.bottom, 0, 0, cr.right, cr.bottom, 0x4000 /* COLOR_BUFFER_BIT */, 0x2600 /* NEAREST */);
    rb((unsigned)rbuf); db((unsigned)dbuf);
    if (sc) en(0x0C11);
    if (srgb) en(0x8DB9);
    bfb(0x8CA8, (unsigned)rfb); bfb(0x8CA9, (unsigned)dfb);
    if (!InterlockedExchange(&said, 1)) glass_note("back buffer kept after SwapBuffers (front copied back; size w<<16|h)", w, (DWORD)(cr.right << 16 | cr.bottom), 0);
}

/* ---- build 57: GDI present (KexNG\GLPresent = 1, CHRVAR 7).
 * Round 18 statistics: with GPU compositing Chrome swaps ~20 frames/s on its main window (sometimes from two DCs
 * on the same window), WM_PAINT and SetWindowRgn stay rare - nothing in Chrome's own Windows calls explains the
 * flashing, so the suspect is how the frame reaches the screen (SoftGPU/Mesa present on the VMware SVGA screen,
 * mixed with GDI's own drawing of the desktop). With GLPresent, SwapBuffers does not swap: kexnt reads the back
 * buffer (glReadPixels, BGRA) and draws it into the window with SetDIBitsToDevice - the same path every 2D
 * program uses. The back buffer is left as it was, which is what Chrome's partial frames expect anyway.
 * Only when the DC is this thread's current GL DC; anything unusual -> the normal SwapBuffers. */
typedef int (WINAPI *T_SDBTD)(HDC, int, int, DWORD, DWORD, int, int, UINT, UINT, const void *, const BITMAPINFO *, UINT);
static LONG g_gdipres = -1;
static LONG gdipres_on(void)
{
    if (g_gdipres < 0) {
        HKEY k; DWORD v = 0, t, n = sizeof(v);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_READ, &k) == ERROR_SUCCESS) {
            if (RegQueryValueExA(k, "GLPresent", NULL, &t, (BYTE *)&v, &n) != ERROR_SUCCESS || t != REG_DWORD) v = 0;
            RegCloseKey(k);
        }
        InterlockedExchange(&g_gdipres, v ? 1 : 0);
        if (v) { void kex_crashnote(const char *, DWORD, DWORD, DWORD, DWORD); kex_crashnote("GLPresent on: SwapBuffers -> glReadPixels + SetDIBitsToDevice", v, 0, 0, 0); }
    }
    return g_gdipres;
}
BOOL kex_gl_present_gdi(HDC dc)
{
    static T_WGCD wgcd; static T_GLRP rp; static T_GLGI gi; static T_GLPI pi; static T_GLRB rb; static T_GLGE ge;
    static T_GLBF bfb, bbuf; static T_WFDC wfdc; static T_GCR gcr; static T_SDBTD sdb; static LONG got;
    static BYTE *buf; static DWORD bufsz; static volatile LONG lk; static LONG frames, fails;
    HWND w; RECT cr; int cw, ch, n; int sv_fb = 0, sv_pbo = 0, sv_align = 4, sv_rb = 0x0405; BITMAPINFO bi; BOOL ok = FALSE;
    void kex_crashnote(const char *, DWORD, DWORD, DWORD, DWORD);
    if (gdipres_on() != 1) return FALSE;
    if (!InterlockedExchange(&got, 1)) {
        HMODULE gl = GetModuleHandleA("OPENGL32.DLL");
        wfdc = (T_WFDC)(void *)kex_sysproc("USER32.DLL", "WindowFromDC");
        gcr = (T_GCR)(void *)kex_sysproc("USER32.DLL", "GetClientRect");
        sdb = (T_SDBTD)(void *)kex_sysproc("GDI32.DLL", "SetDIBitsToDevice");
        if (gl) {
            T_WGPA wgpa = (T_WGPA)(void *)GetProcAddress(gl, "wglGetProcAddress");
            wgcd = (T_WGCD)(void *)GetProcAddress(gl, "wglGetCurrentDC");
            rp = (T_GLRP)(void *)GetProcAddress(gl, "glReadPixels"); gi = (T_GLGI)(void *)GetProcAddress(gl, "glGetIntegerv");
            pi = (T_GLPI)(void *)GetProcAddress(gl, "glPixelStorei"); rb = (T_GLRB)(void *)GetProcAddress(gl, "glReadBuffer");
            ge = (T_GLGE)(void *)GetProcAddress(gl, "glGetError");
            if (wgpa) { bfb = (T_GLBF)(void *)wgpa("glBindFramebuffer"); bbuf = (T_GLBF)(void *)wgpa("glBindBuffer"); }
        }
    }
    if (!wgcd || !rp || !gi || !pi || !rb || !ge || !wfdc || !gcr || !sdb) return FALSE;
    if (wgcd() != dc || !(w = wfdc(dc)) || !gcr(w, &cr)) return FALSE;
    cw = cr.right; ch = cr.bottom;
    if (cw <= 0 || ch <= 0 || cw > 4096 || ch > 4096) return FALSE;
    kex_spin_acquire(&lk);
    if ((DWORD)cw * ch * 4 > bufsz) {
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
        bufsz = (DWORD)cw * ch * 4; buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, bufsz);
        if (!buf) bufsz = 0;
    }
    if (buf) {
        while (ge() != 0) ;
        gi(0x8CAA, &sv_fb); gi(0x88ED, &sv_pbo); gi(0x0D05, &sv_align); gi(0x0C02, &sv_rb);
        while (ge() != 0) ;
        if (bfb) bfb(0x8CA8, 0);
        if (bbuf) bbuf(0x88EB, 0);
        pi(0x0D05, 4); rb(0x0405 /* BACK */);
        rp(0, 0, cw, ch, 0x80E1 /* BGRA */, 0x1401, buf);
        n = (int)ge();
        rb((unsigned)sv_rb); pi(0x0D05, sv_align);
        if (bbuf) bbuf(0x88EB, (unsigned)sv_pbo);
        if (bfb) bfb(0x8CA8, (unsigned)sv_fb);
        while (ge() != 0) ;
        if (n == 0) {
            memset(&bi, 0, sizeof(bi));
            bi.bmiHeader.biSize = sizeof(bi.bmiHeader); bi.bmiHeader.biWidth = cw; bi.bmiHeader.biHeight = ch;   /* bottom-up, like GL */
            bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
            ok = sdb(dc, 0, 0, (DWORD)cw, (DWORD)ch, 0, 0, 0, (UINT)ch, buf, &bi, DIB_RGB_COLORS) != 0;
        }
        if (!ok && InterlockedIncrement(&fails) <= 5) kex_crashnote("GLPresent: frame not drawn (GL error, size w<<16|h, window)", (DWORD)n, (DWORD)(cw << 16 | ch), (DWORD)(ULONG_PTR)w, 0);
    }
    InterlockedExchange(&lk, 0);
    if (ok) { void kex_hang_note_call(const char *n); kex_hang_note_call("SwapBuffers"); }   /* the hang watcher counts this as drawing */
    if (ok && InterlockedIncrement(&frames) == 1) kex_crashnote("GLPresent: first frame drawn by GDI (window, size w<<16|h)", (DWORD)(ULONG_PTR)w, (DWORD)(cw << 16 | ch), 0, 0);
    return ok;
}
