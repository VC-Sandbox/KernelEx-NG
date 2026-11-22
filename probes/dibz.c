/* dibz.c - is the memory of a new CreateDIBSection zero-filled (NT: always)? -> C:\DIBZ.LOG.
 * Dirties DIBs, frees them, makes new ones of the same size and counts non-zero bytes. */
#include <windows.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
static HBITMAP mk(HDC dc, int w, int h, BYTE **p) { BITMAPINFO bi; memset(&bi, 0, sizeof(bi)); bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
    bi.bmiHeader.biWidth = w; bi.bmiHeader.biHeight = -h; bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
    return CreateDIBSection(dc, &bi, DIB_RGB_COLORS, (void **)p, NULL, 0); }
int main(void)
{
    FILE *f = fopen("C:\\DIBZ.LOG", "w"); HDC dc = GetDC(NULL); int round, sizes[] = {16, 24, 64, 256}, k;
    for (k = 0; k < 4; k++) {
        int w = sizes[k], nz = 0, i; BYTE *p; HBITMAP b;
        for (round = 0; round < 8; round++) { b = mk(dc, w, w, &p); if (p) memset(p, 0xA5, w * w * 4); DeleteObject(b); }
        b = mk(dc, w, w, &p);
        for (i = 0; p && i < w * w * 4; i++) if (p[i]) nz++;
        fprintf(f, "%dx%d new DIB after dirty ones: %d of %d bytes non-zero (first %02x)\n", w, w, nz, w * w * 4, p ? p[0] : 0);
        DeleteObject(b);
    }
    fclose(f); return 0;
}
