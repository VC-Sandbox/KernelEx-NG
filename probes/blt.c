#include <windows.h>
#include <stdio.h>
static int test(DWORD rop, const char *name, FILE *o)
{
    HDC s = GetDC(NULL), m = CreateCompatibleDC(s); BITMAPINFO bi; void *bits; HBITMAP b; int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN), i, nz = 0; BOOL r;
    memset(&bi, 0, sizeof(bi)); bi.bmiHeader.biSize = sizeof(bi.bmiHeader); bi.bmiHeader.biWidth = w; bi.bmiHeader.biHeight = -h; bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
    b = CreateDIBSection(s, &bi, DIB_RGB_COLORS, &bits, NULL, 0); SelectObject(m, b);
    SetLastError(0); r = BitBlt(m, 0, 0, w, h, s, 0, 0, rop);
    for (i = 0; i < w * h; i++) if (((DWORD *)bits)[i] & 0xFFFFFF) nz++;
    fprintf(o, "%-22s rop %08lx: BitBlt %d err %lu, non-black %d of %d\n", name, rop, r, GetLastError(), nz, w * h);
    DeleteDC(m); DeleteObject(b); ReleaseDC(NULL, s); return r;
}
int main(void)
{
    FILE *o = fopen("C:\\BLT.TXT", "w");
    test(SRCCOPY, "SRCCOPY", o);
    test(SRCCOPY | CAPTUREBLT, "SRCCOPY|CAPTUREBLT", o);
    test(SRCCOPY | 0x80000000, "SRCCOPY|NOMIRROR", o);
    {   HDC s = GetDC(NULL); HDC d = CreateDCA("DISPLAY", NULL, NULL, NULL); fprintf(o, "GetDC(NULL) %p CreateDC(DISPLAY) %p\n", s, d); }
    fclose(o); return 0;
}
