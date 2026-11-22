/* shot.c - SHOT.EXE <out.bmp>: the screen as Windows draws it (BitBlt of the desktop DC) - for when QEMU's own
 * screendump cannot show the display mode. A Windows 95 program: KernelEx/kexnt leave it alone. */
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    HDC s = GetDC(NULL), m = CreateCompatibleDC(s); int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
    BITMAPINFO bi; void *bits; HBITMAP b; FILE *o; BITMAPFILEHEADER fh; DWORD sz;
    memset(&bi, 0, sizeof(bi)); bi.bmiHeader.biSize = sizeof(bi.bmiHeader); bi.bmiHeader.biWidth = w; bi.bmiHeader.biHeight = h;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 24; bi.bmiHeader.biCompression = BI_RGB;
    b = CreateDIBSection(s, &bi, DIB_RGB_COLORS, &bits, NULL, 0); SelectObject(m, b);
    BitBlt(m, 0, 0, w, h, s, 0, 0, SRCCOPY); GdiFlush();
    sz = ((w * 3 + 3) & ~3) * h;
    memset(&fh, 0, sizeof(fh)); fh.bfType = 0x4D42; fh.bfOffBits = sizeof(fh) + sizeof(bi.bmiHeader); fh.bfSize = fh.bfOffBits + sz;
    o = fopen(argc > 1 ? argv[1] : "C:\\SHOT.BMP", "wb"); if (!o) return 1;
    fwrite(&fh, sizeof(fh), 1, o); fwrite(&bi.bmiHeader, sizeof(bi.bmiHeader), 1, o); fwrite(bits, 1, sz, o); fclose(o);
    return 0;
}
