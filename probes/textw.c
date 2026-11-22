/* textw.c - text widths three ways (Gecko's GDI path vs GDI extents) for UI fonts -> C:\TEXTW.LOG.
 * A modern program for kexnt's gate (KexNG_ModernProcess), like a browser. */
#include <windows.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
typedef DWORD (WINAPI *T_GGI)(HDC, LPCWSTR, int, LPWORD, DWORD);
typedef BOOL (WINAPI *T_GCWI)(HDC, UINT, UINT, LPWORD, LPINT);
int main(void)
{
    static const char *faces[] = { "Tahoma", "MS Sans Serif", "Arial", "MS Serif", NULL };
    static const WCHAR *ws[] = { L"Copy", L"Search", L"New Window", L"Preferences", NULL };
    static const char *as[] = { "Copy", "Search", "New Window", "Preferences", NULL };
    FILE *f = fopen("C:\\TEXTW.LOG", "w"); HDC dc = GetDC(NULL); int i, j, k;
    HMODULE g = GetModuleHandleA("GDI32.DLL");
    T_GGI ggi = (T_GGI)GetProcAddress(g, "GetGlyphIndicesW"); T_GCWI gcwi = (T_GCWI)GetProcAddress(g, "GetCharWidthI");
    fprintf(f, "GetGlyphIndicesW %p GetCharWidthI %p\n", (void *)ggi, (void *)gcwi);
    for (i = 0; faces[i]; i++) {
        HFONT h = CreateFontA(i == 3 ? 13 : -11, 0, 0, 0, 400, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, faces[i]), o = SelectObject(dc, h);
        for (j = 0; ws[j]; j++) {
            SIZE sw = {0}, sa = {0}; WORD gi[32]; int w[32], n = lstrlenW(ws[j]), sum = 0; DWORD r = 0; BOOL ok = FALSE;
            GetTextExtentPoint32W(dc, ws[j], n, &sw); GetTextExtentPoint32A(dc, as[j], n, &sa);
            if (ggi && gcwi) { r = ggi(dc, ws[j], n, gi, 0); ok = gcwi(dc, 0, n, gi, w); for (k = 0; k < n && ok; k++) sum += w[k]; }
            fprintf(f, "%-14s %-12s extentW %3ld extentA %3ld glyphs+CharWidthI %3d (ggi %lu ok %d) per glyph:", faces[i], as[j], sw.cx, sa.cx, sum, r, ok);
            for (k = 0; k < n && ok; k++) fprintf(f, " %d", w[k]);
            fprintf(f, " | indices"); for (k = 0; k < n; k++) fprintf(f, " %04x", gi[k]);
            { INT cw; fprintf(f, " | GetCharWidth32W"); for (k = 0; k < n; k++) { GetCharWidth32W(dc, ws[j][k], ws[j][k], &cw); fprintf(f, " %d", cw); } }
            fprintf(f, "\n");
        }
        SelectObject(dc, o); DeleteObject(h);
    }
    fclose(f); return 0;
}
