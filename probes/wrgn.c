/* wrgn.c <hex hwnd> - window rect, client rect and window region (bounding box, rectangles) -> C:\WRGN.LOG */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv)
{
    FILE *f = fopen("C:\\WRGN.LOG", "w"); HWND h = (HWND)strtoul(argc > 1 ? argv[1] : "0", NULL, 16);
    RECT w, c, b; HRGN r = CreateRectRgn(0, 0, 0, 0); int t; DWORD n; RGNDATA *d; POINT p = {0, 0};
    GetWindowRect(h, &w); GetClientRect(h, &c); ClientToScreen(h, &p);
    fprintf(f, "window %p rect %ld,%ld-%ld,%ld client %ldx%ld at %ld,%ld style %08lx ex %08lx\n", (void *)h, w.left, w.top, w.right, w.bottom,
            c.right, c.bottom, p.x, p.y, GetWindowLongA(h, GWL_STYLE), GetWindowLongA(h, GWL_EXSTYLE));
    t = GetWindowRgn(h, r); GetRgnBox(r, &b);
    fprintf(f, "region type %d box %ld,%ld-%ld,%ld\n", t, b.left, b.top, b.right, b.bottom);
    n = GetRegionData(r, 0, NULL);
    if (n && (d = (RGNDATA *)malloc(n)) && GetRegionData(r, n, d)) {
        RECT *rc = (RECT *)d->Buffer; DWORD i;
        for (i = 0; i < d->rdh.nCount && i < 20; i++) fprintf(f, "  rect %ld,%ld-%ld,%ld\n", rc[i].left, rc[i].top, rc[i].right, rc[i].bottom);
    }
    fclose(f); return 0;
}
