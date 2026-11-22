/* ablend.c - AlphaBlend(AC_SRC_ALPHA) of a premultiplied 32-bit DIB onto blue, as Gecko draws toolbar icons; also
 * whether Windows 98's StretchBlt/BitBlt between 32-bit DIBs keep the alpha byte -> C:\ABLEND.LOG */
#include <windows.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
typedef BOOL (WINAPI *T_AB)(HDC, int, int, int, int, HDC, int, int, int, int, BLENDFUNCTION);
static HBITMAP dib(HDC dc, DWORD **px) { BITMAPINFO bi; memset(&bi, 0, sizeof(bi)); bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
    bi.bmiHeader.biWidth = 4; bi.bmiHeader.biHeight = -1; bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
    return CreateDIBSection(dc, &bi, DIB_RGB_COLORS, (void **)px, NULL, 0); }
int main(void)
{
    FILE *f = fopen("C:\\ABLEND.LOG", "w"); HDC sc = GetDC(NULL), sd = CreateCompatibleDC(sc), dd = CreateCompatibleDC(sc);
    DWORD *s, *d; HBITMAP sb = dib(sc, &s), db = dib(sc, &d); int i; BLENDFUNCTION bf = {AC_SRC_OVER, 0, 255, 1};
    HMODULE m = LoadLibraryA("MSIMG32.DLL"); T_AB ab = (T_AB)GetProcAddress(m, "AlphaBlend"); char p[MAX_PATH] = "";
    GetModuleFileNameA(m, p, MAX_PATH);
    fprintf(f, "msimg32 %s AlphaBlend %p\n", p, (void *)ab);
    SelectObject(sd, sb); SelectObject(dd, db);
    s[0] = 0x00000000; s[1] = 0xFFFFFFFF; s[2] = 0x80800000; s[3] = 0x80FFFFFF;   /* transparent, white, half red (premult), INVALID: white rgb with alpha 128 */
    for (i = 0; i < 4; i++) d[i] = 0x000000FF;                                   /* blue */
    if (ab) fprintf(f, "AlphaBlend result %d\n", ab(dd, 0, 0, 4, 1, sd, 0, 0, 4, 1, bf));
    GdiFlush();
    fprintf(f, "dest after:  %08lx %08lx %08lx %08lx  (expect 000000ff ffffffff 008000ff-ish ...)\n", d[0], d[1], d[2], d[3]);
    for (i = 0; i < 4; i++) d[i] = 0x11223344;
    BitBlt(dd, 0, 0, 4, 1, sd, 0, 0, SRCCOPY); GdiFlush();
    fprintf(f, "BitBlt 32->32 copy:     %08lx %08lx %08lx %08lx (alpha kept?)\n", d[0], d[1], d[2], d[3]);
    for (i = 0; i < 4; i++) d[i] = 0x11223344;
    StretchBlt(dd, 0, 0, 4, 1, sd, 0, 0, 4, 1, SRCCOPY); GdiFlush();
    fprintf(f, "StretchBlt 32->32 copy: %08lx %08lx %08lx %08lx (alpha kept?)\n", d[0], d[1], d[2], d[3]);
    fclose(f); return 0;
}
