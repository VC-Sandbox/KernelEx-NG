/* etog.c - ExtTextOutW(ETO_GLYPH_INDEX, lpDx) on a raster font the way Gecko draws a label: which pixel columns
 * get ink? -> C:\ETOG.LOG. Modern program for kexnt's gate. */
#include <windows.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
typedef DWORD (WINAPI *T_GGI)(HDC, LPCWSTR, int, LPWORD, DWORD);
static void run(FILE *f, HDC dc, HBITMAP bm, const char *what, UINT opt, const void *str, int n, const INT *dx)
{
    BITMAPINFO bi; static DWORD px[100 * 20]; int x, y, last = -1, first = -1;
    RECT r = {0, 0, 100, 20}; FillRect(dc, &r, (HBRUSH)GetStockObject(WHITE_BRUSH));
    ExtTextOutW(dc, 2, 2, opt, NULL, (LPCWSTR)str, n, dx);
    memset(&bi, 0, sizeof(bi)); bi.bmiHeader.biSize = sizeof(bi.bmiHeader); bi.bmiHeader.biWidth = 100; bi.bmiHeader.biHeight = -20;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
    GetDIBits(dc, bm, 0, 20, px, &bi, DIB_RGB_COLORS);
    for (x = 0; x < 100; x++) for (y = 0; y < 20; y++) if ((px[y * 100 + x] & 0xFFFFFF) != 0xFFFFFF) { if (first < 0) first = x; last = x; break; }
    fprintf(f, "%-44s ink columns %d..%d (width %d)\n", what, first, last, last - first + 1);
}
int main(void)
{
    FILE *f = fopen("C:\\ETOG.LOG", "w"); HDC sc = GetDC(NULL), dc = CreateCompatibleDC(sc);
    HBITMAP bm = CreateCompatibleBitmap(sc, 100, 20); HFONT h = CreateFontA(13, 0, 0, 0, 400, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, "MS Serif");
    T_GGI ggi = (T_GGI)GetProcAddress(GetModuleHandleA("GDI32.DLL"), "GetGlyphIndicesW");
    WORD gi[4]; INT dx0[4] = {7, 5, 5, 0}, dx1[4] = {7, 5, 5, 5};
    SelectObject(dc, bm); SelectObject(dc, h); SetBkMode(dc, TRANSPARENT);
    if (ggi) ggi(dc, L"Copy", 4, gi, 0);
    fprintf(f, "indices %04x %04x %04x %04x\n", gi[0], gi[1], gi[2], gi[3]);
    run(f, dc, bm, "chars, no dx", 0, L"Copy", 4, NULL);
    run(f, dc, bm, "chars, dx 7 5 5 0", 0, L"Copy", 4, dx0);
    run(f, dc, bm, "glyph index, no dx", ETO_GLYPH_INDEX, gi, 4, NULL);
    run(f, dc, bm, "glyph index, dx 7 5 5 0 (Gecko)", ETO_GLYPH_INDEX, gi, 4, dx0);
    run(f, dc, bm, "glyph index, dx 7 5 5 5", ETO_GLYPH_INDEX, gi, 4, dx1);
    {   /* TrueType: Tahoma 15 px "Restore" */
        HFONT t = CreateFontA(-15, 0, 0, 0, 400, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, "Tahoma"); WORD g7[7]; INT w7[7], d0[7], d1[7]; int k;
        TEXTMETRICA tm; SelectObject(dc, t); GetTextMetricsA(dc, &tm);
        if (ggi) ggi(dc, L"Restore", 7, g7, 0);
        for (k = 0; k < 7; k++) { GetCharWidth32W(dc, L"Restore"[k], L"Restore"[k], &w7[k]); d0[k] = d1[k] = w7[k]; }
        d0[6] = 0; d1[6] = tm.tmMaxCharWidth;
        fprintf(f, "Tahoma indices %04x %04x .. maxcharwidth %ld pitch %02x\n", g7[0], g7[1], tm.tmMaxCharWidth, tm.tmPitchAndFamily);
        run(f, dc, bm, "TT glyph index, no dx", ETO_GLYPH_INDEX, g7, 7, NULL);
        run(f, dc, bm, "TT glyph index, dx .. 0 (Gecko)", ETO_GLYPH_INDEX, g7, 7, d0);
        run(f, dc, bm, "TT glyph index, dx .. maxcharwidth", ETO_GLYPH_INDEX, g7, 7, d1);
    }
    fclose(f); return 0;
}
