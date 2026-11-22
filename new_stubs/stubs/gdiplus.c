/* gdiplus.dll for Windows 98 SE (build 125) - a small GDI+: start-up, bitmaps from PNG/BMP files and streams,
 * HBITMAP export, clone, dispose. Written from the GDI+ flat API documentation and the PNG / zlib (RFC 1950/1951)
 * specifications; no Microsoft code. Installed by KEXSETUP only when Windows has no gdiplus.dll.
 * Why: WiX Burn's standard bootstrapper UI (wixstdba.dll - Visual C++ 2013-2022 redistributables, many other
 * setups) imports GDI+ statically to load its PNG logo; without gdiplus.dll the setup cannot start its UI.
 * Everything else in GDI+ is missing on purpose: programs that need real GDI+ drawing will see missing exports. */
#include <windows.h>
#include <objidl.h>

typedef int GpStatus;
enum { Ok = 0, GenericError = 1, InvalidParameter = 2, OutOfMemory = 3, NotImplemented = 6, Win32Error = 7,
       FileNotFound = 10, UnknownImageFormat = 13 };
#define IMG_MAGIC 0x4B58494DUL   /* "MIXK" */
typedef struct { DWORD magic; UINT w, h; DWORD *px; } KIMG;   /* px: w*h premultiplied BGRA, top row first */

static void *zalloc(SIZE_T n) { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n); }
static void zfree(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }
static void cpy(void *d, const void *s, SIZE_T n) { BYTE *a = (BYTE *)d; const BYTE *b = (const BYTE *)s; while (n--) *a++ = *b++; }

/* ---------------- inflate (RFC 1951) ---------------- */
typedef struct { const BYTE *in; SIZE_T inlen, inpos; DWORD bitbuf; int bitcnt; BYTE *out; SIZE_T outlen, outpos; int err; } INF;
static int getbit(INF *s)
{
    if (!s->bitcnt) { if (s->inpos >= s->inlen) { s->err = 1; return 0; } s->bitbuf = s->in[s->inpos++]; s->bitcnt = 8; }
    { int b = s->bitbuf & 1; s->bitbuf >>= 1; s->bitcnt--; return b; }
}
static DWORD getbits(INF *s, int n) { DWORD v = 0; int i; for (i = 0; i < n; i++) v |= (DWORD)getbit(s) << i; return v; }
typedef struct { short count[16]; short sym[320]; } HUFF;
static int build(HUFF *h, const BYTE *len, int n)
{
    short offs[16]; int i;
    for (i = 0; i < 16; i++) h->count[i] = 0;
    for (i = 0; i < n; i++) h->count[len[i]]++;
    h->count[0] = 0; offs[1] = 0;
    for (i = 1; i < 15; i++) offs[i + 1] = offs[i] + h->count[i];
    for (i = 0; i < n; i++) if (len[i]) h->sym[offs[len[i]]++] = (short)i;
    return 0;
}
static int decode(INF *s, const HUFF *h)
{
    int code = 0, first = 0, index = 0, len;
    for (len = 1; len < 16; len++) {
        int c;
        code |= getbit(s); c = h->count[len];
        if (code - c < first) return h->sym[index + (code - first)];
        index += c; first += c; first <<= 1; code <<= 1;
        if (s->err) return -1;
    }
    s->err = 1; return -1;
}
static void put(INF *s, BYTE b) { if (s->outpos < s->outlen) s->out[s->outpos++] = b; else s->err = 2; }
static const short lbase[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
static const short lext[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
static const short dbase[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
static const short dext[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
static void codes(INF *s, const HUFF *lc, const HUFF *dc)
{
    for (;;) {
        int sym = decode(s, lc);
        if (s->err || sym < 0) { s->err = 1; return; }
        if (sym < 256) put(s, (BYTE)sym);
        else if (sym == 256) return;
        else {
            int len, d; SIZE_T dist;
            sym -= 257; if (sym >= 29) { s->err = 1; return; }
            len = lbase[sym] + (int)getbits(s, lext[sym]);
            d = decode(s, dc); if (d < 0 || d >= 30) { s->err = 1; return; }
            dist = (SIZE_T)dbase[d] + getbits(s, dext[d]);
            if (dist > s->outpos) { s->err = 1; return; }
            while (len--) { put(s, s->out[s->outpos - dist]); if (s->err) return; }
        }
    }
}
static int inflate_raw(INF *s)
{
    int last;
    do {
        int type;
        last = getbit(s); type = (int)getbits(s, 2);
        if (s->err) return -1;
        if (type == 0) {
            unsigned len;
            s->bitcnt = 0;
            if (s->inpos + 4 > s->inlen) return -1;
            len = s->in[s->inpos] | (s->in[s->inpos + 1] << 8); s->inpos += 4;
            if (s->inpos + len > s->inlen) return -1;
            while (len--) put(s, s->in[s->inpos++]);
        } else if (type == 1 || type == 2) {
            HUFF lc, dc; BYTE lens[320]; int i;
            if (type == 1) {
                for (i = 0; i < 144; i++) lens[i] = 8;
                for (; i < 256; i++) lens[i] = 9;
                for (; i < 280; i++) lens[i] = 7;
                for (; i < 288; i++) lens[i] = 8;
                build(&lc, lens, 288);
                for (i = 0; i < 30; i++) lens[i] = 5;
                build(&dc, lens, 30);
            } else {
                static const BYTE ord[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
                int nlen = (int)getbits(s, 5) + 257, ndist = (int)getbits(s, 5) + 1, ncode = (int)getbits(s, 4) + 4, idx = 0;
                HUFF cc;
                if (nlen > 286 || ndist > 30) return -1;
                for (i = 0; i < 19; i++) lens[i] = 0;
                for (i = 0; i < ncode; i++) lens[ord[i]] = (BYTE)getbits(s, 3);
                build(&cc, lens, 19);
                while (idx < nlen + ndist) {
                    int sym = decode(s, &cc), rep = 0; BYTE v = 0;
                    if (sym < 0 || s->err) return -1;
                    if (sym < 16) { lens[idx++] = (BYTE)sym; continue; }
                    if (sym == 16) { if (!idx) return -1; v = lens[idx - 1]; rep = 3 + (int)getbits(s, 2); }
                    else if (sym == 17) rep = 3 + (int)getbits(s, 3);
                    else rep = 11 + (int)getbits(s, 7);
                    if (idx + rep > nlen + ndist) return -1;
                    while (rep--) lens[idx++] = v;
                }
                build(&lc, lens, nlen);
                build(&dc, lens + nlen, ndist);
            }
            codes(s, &lc, &dc);
        } else return -1;
        if (s->err) return -1;
    } while (!last);
    return 0;
}

/* ---------------- PNG ---------------- */
static DWORD be32(const BYTE *p) { return ((DWORD)p[0] << 24) | ((DWORD)p[1] << 16) | ((DWORD)p[2] << 8) | p[3]; }
static int paeth(int a, int b, int c) { int p = a + b - c, pa = p > a ? p - a : a - p, pb = p > b ? p - b : b - p, pc = p > c ? p - c : c - p;
    return (pa <= pb && pa <= pc) ? a : (pb <= pc ? b : c); }
static KIMG *png_decode(const BYTE *d, SIZE_T n)
{
    UINT w = 0, h = 0, depth = 0, ctype = 0, inter = 0, x, y; SIZE_T pos = 8, idlen = 0, stride, need; BYTE *idat = NULL, *raw = NULL;
    BYTE pal[256][4]; int npal = 0, i, bpp, chans; KIMG *img = NULL; INF s;
    for (i = 0; i < 256; i++) { pal[i][0] = pal[i][1] = pal[i][2] = 0; pal[i][3] = 255; }
    if (n < 8 || d[0] != 0x89 || d[1] != 'P' || d[2] != 'N' || d[3] != 'G') return NULL;
    idat = (BYTE *)zalloc(n);
    if (!idat) return NULL;
    while (pos + 12 <= n) {
        DWORD len = be32(d + pos); const BYTE *t = d + pos + 4, *c = d + pos + 8;
        if (len > n - pos - 12) break;
        if (!memcmp(t, "IHDR", 4) && len >= 13) { w = be32(c); h = be32(c + 4); depth = c[8]; ctype = c[9]; inter = c[12]; }
        else if (!memcmp(t, "PLTE", 4)) { npal = (int)(len / 3); if (npal > 256) npal = 256; for (i = 0; i < npal; i++) { pal[i][0] = c[i*3]; pal[i][1] = c[i*3+1]; pal[i][2] = c[i*3+2]; } }
        else if (!memcmp(t, "tRNS", 4) && ctype == 3) { for (i = 0; i < (int)len && i < 256; i++) pal[i][3] = c[i]; }
        else if (!memcmp(t, "IDAT", 4)) { cpy(idat + idlen, c, len); idlen += len; }
        else if (!memcmp(t, "IEND", 4)) break;
        pos += 12 + len;
    }
    chans = ctype == 2 ? 3 : ctype == 4 ? 2 : ctype == 6 ? 4 : 1;
    if (!w || !h || w > 16384 || h > 16384 || inter || idlen < 2 ||
        !(depth == 8 || depth == 16 || (ctype == 3 && depth <= 8) || (ctype == 0 && depth <= 8))) goto out;
    bpp = (int)((chans * depth + 7) / 8);
    stride = ((SIZE_T)w * chans * depth + 7) / 8;
    need = (stride + 1) * h;
    raw = (BYTE *)zalloc(need + 16);
    if (!raw) goto out;
    s.in = idat + 2; s.inlen = idlen - 2; s.inpos = 0; s.bitbuf = 0; s.bitcnt = 0;   /* skip the zlib header */
    s.out = raw; s.outlen = need; s.outpos = 0; s.err = 0;
    if (inflate_raw(&s) || s.outpos < need) goto out;
    for (y = 0; y < h; y++) {                       /* undo the filters in place */
        BYTE *row = raw + y * (stride + 1), f = row[0], *cur = row + 1, *prev = y ? raw + (y - 1) * (stride + 1) + 1 : NULL;
        SIZE_T k;
        for (k = 0; k < stride; k++) {
            int a = k >= (SIZE_T)bpp ? cur[k - bpp] : 0, b = prev ? prev[k] : 0, c = (prev && k >= (SIZE_T)bpp) ? prev[k - bpp] : 0;
            switch (f) { case 1: cur[k] += a; break; case 2: cur[k] += b; break; case 3: cur[k] += (a + b) / 2; break;
                         case 4: cur[k] += paeth(a, b, c); break; default: break; }
        }
    }
    img = (KIMG *)zalloc(sizeof(KIMG));
    if (!img || !(img->px = (DWORD *)zalloc((SIZE_T)w * h * 4))) { zfree(img); img = NULL; goto out; }
    img->magic = IMG_MAGIC; img->w = w; img->h = h;
    for (y = 0; y < h; y++) {
        const BYTE *r = raw + y * (stride + 1) + 1;
        for (x = 0; x < w; x++) {
            int R, G, B, A = 255;
            if (depth == 16) {
                const BYTE *p = r + x * chans * 2;
                if (chans >= 3) { R = p[0]; G = p[2]; B = p[4]; if (chans == 4) A = p[6]; }
                else { R = G = B = p[0]; if (chans == 2) A = p[2]; }
            } else if (depth == 8) {
                const BYTE *p = r + x * chans;
                if (ctype == 3) { R = pal[p[0]][0]; G = pal[p[0]][1]; B = pal[p[0]][2]; A = pal[p[0]][3]; }
                else if (chans >= 3) { R = p[0]; G = p[1]; B = p[2]; if (chans == 4) A = p[3]; }
                else { R = G = B = p[0]; if (chans == 2) A = p[1]; }
            } else {                                  /* 1/2/4-bit palette or grey */
                int per = 8 / depth, v = (r[x / per] >> ((per - 1 - (int)(x % per)) * depth)) & ((1 << depth) - 1);
                if (ctype == 3) { R = pal[v][0]; G = pal[v][1]; B = pal[v][2]; A = pal[v][3]; }
                else { R = G = B = v * 255 / ((1 << depth) - 1); }
            }
            R = R * A / 255; G = G * A / 255; B = B * A / 255;   /* premultiplied, as AlphaBlend wants */
            img->px[y * w + x] = ((DWORD)A << 24) | ((DWORD)R << 16) | ((DWORD)G << 8) | (DWORD)B;
        }
    }
out:
    zfree(idat); zfree(raw);
    return img;
}

/* BMP and the other formats Windows 98 itself can read (LoadImage): through a temporary file */
static KIMG *gdi_decode(const BYTE *d, SIZE_T n)
{
    char tmp[MAX_PATH], dir[MAX_PATH]; HANDLE f; DWORD wr; HBITMAP hb; BITMAP bm; KIMG *img = NULL; HDC dc; BITMAPINFO bi;
    if (n < 2 || d[0] != 'B' || d[1] != 'M') return NULL;
    if (!GetTempPathA(MAX_PATH, dir) || !GetTempFileNameA(dir, "kgp", 0, tmp)) return NULL;
    f = CreateFileA(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return NULL;
    WriteFile(f, d, (DWORD)n, &wr, NULL); CloseHandle(f);
    hb = (HBITMAP)LoadImageA(NULL, tmp, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION);
    DeleteFileA(tmp);
    if (!hb) return NULL;
    if (GetObjectA(hb, sizeof(bm), &bm) && bm.bmWidth > 0 && bm.bmHeight > 0 && (img = (KIMG *)zalloc(sizeof(KIMG))) &&
        (img->px = (DWORD *)zalloc((SIZE_T)bm.bmWidth * bm.bmHeight * 4))) {
        UINT i;
        img->magic = IMG_MAGIC; img->w = (UINT)bm.bmWidth; img->h = (UINT)bm.bmHeight;
        ZeroMemory(&bi, sizeof(bi)); bi.bmiHeader.biSize = sizeof(bi.bmiHeader); bi.bmiHeader.biWidth = bm.bmWidth;
        bi.bmiHeader.biHeight = -bm.bmHeight; bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
        dc = GetDC(NULL);
        GetDIBits(dc, hb, 0, (UINT)bm.bmHeight, img->px, &bi, DIB_RGB_COLORS);
        ReleaseDC(NULL, dc);
        for (i = 0; i < img->w * img->h; i++) img->px[i] |= 0xFF000000UL;   /* BMPs are opaque */
    } else if (img) { zfree(img); img = NULL; }
    DeleteObject(hb);
    return img;
}
static KIMG *decode_any(const BYTE *d, SIZE_T n) { KIMG *i = png_decode(d, n); return i ? i : gdi_decode(d, n); }

/* ---------------- exports ---------------- */
typedef struct { UINT32 ver; void *debug; BOOL nothread; BOOL nocodecs; } GSI;
typedef struct { void *hook; void *unhook; } GSO;
static GpStatus WINAPI hook_proc(ULONG_PTR *t) { if (t) *t = 0; return Ok; }
static void WINAPI unhook_proc(ULONG_PTR t) { (void)t; }
GpStatus WINAPI GdiplusStartup(ULONG_PTR *token, const GSI *in, GSO *out)
{
    if (!token || !in || in->ver < 1 || in->ver > 3) return InvalidParameter;
    *token = 1;
    if (in->nothread) { if (!out) return InvalidParameter; out->hook = (void *)hook_proc; out->unhook = (void *)unhook_proc; }
    return Ok;
}
VOID WINAPI GdiplusShutdown(ULONG_PTR token) { (void)token; }
void *WINAPI GdipAlloc(SIZE_T n) { return zalloc(n ? n : 1); }
void WINAPI GdipFree(void *p) { zfree(p); }

GpStatus WINAPI GdipCreateBitmapFromStream(IStream *st, KIMG **out)
{
    BYTE *buf = NULL; SIZE_T cap = 0, len = 0; ULONG got; HRESULT hr;
    if (!st || !out) return InvalidParameter;
    *out = NULL;
    for (;;) {
        if (len + 65536 > cap) { BYTE *nb = (BYTE *)zalloc(cap = (cap ? cap * 2 : 131072)); if (!nb) { zfree(buf); return OutOfMemory; }
                                  if (buf) { cpy(nb, buf, len); zfree(buf); } buf = nb; }
        got = 0; hr = st->lpVtbl->Read(st, buf + len, 65536, &got);
        len += got;
        if (FAILED(hr) || !got) break;
        if (len > (64u << 20)) { zfree(buf); return OutOfMemory; }
    }
    *out = decode_any(buf, len);
    zfree(buf);
    return *out ? Ok : UnknownImageFormat;
}
GpStatus WINAPI GdipCreateBitmapFromFile(const WCHAR *path, KIMG **out)
{
    HANDLE f; DWORD n, got = 0; BYTE *buf; char a[MAX_PATH];
    if (!path || !out) return InvalidParameter;
    *out = NULL;
    if (!WideCharToMultiByte(CP_ACP, 0, path, -1, a, MAX_PATH, NULL, NULL)) return InvalidParameter;
    f = CreateFileA(a, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return FileNotFound;
    n = GetFileSize(f, NULL);
    if (n == INVALID_FILE_SIZE || n > (64u << 20) || !(buf = (BYTE *)zalloc(n + 1))) { CloseHandle(f); return OutOfMemory; }
    ReadFile(f, buf, n, &got, NULL); CloseHandle(f);
    *out = decode_any(buf, got);
    zfree(buf);
    return *out ? Ok : UnknownImageFormat;
}
GpStatus WINAPI GdipLoadImageFromStream(IStream *st, KIMG **out) { return GdipCreateBitmapFromStream(st, out); }
GpStatus WINAPI GdipLoadImageFromFile(const WCHAR *p, KIMG **out) { return GdipCreateBitmapFromFile(p, out); }
static BOOL valid(const KIMG *i) { return i && !IsBadReadPtr(i, sizeof(*i)) && i->magic == IMG_MAGIC; }
GpStatus WINAPI GdipDisposeImage(KIMG *i) { if (!valid(i)) return InvalidParameter; i->magic = 0; zfree(i->px); zfree(i); return Ok; }
GpStatus WINAPI GdipCloneImage(KIMG *i, KIMG **out)
{
    KIMG *c;
    if (!valid(i) || !out) return InvalidParameter;
    if (!(c = (KIMG *)zalloc(sizeof(KIMG))) || !(c->px = (DWORD *)zalloc((SIZE_T)i->w * i->h * 4))) { zfree(c); return OutOfMemory; }
    c->magic = IMG_MAGIC; c->w = i->w; c->h = i->h; cpy(c->px, i->px, (SIZE_T)i->w * i->h * 4);
    *out = c; return Ok;
}
GpStatus WINAPI GdipGetImageWidth(KIMG *i, UINT *w) { if (!valid(i) || !w) return InvalidParameter; *w = i->w; return Ok; }
GpStatus WINAPI GdipGetImageHeight(KIMG *i, UINT *h) { if (!valid(i) || !h) return InvalidParameter; *h = i->h; return Ok; }
/* 32-bit top-down DIB section. Background with alpha 0: pixels as they are (premultiplied alpha kept);
 * otherwise blended onto the background colour, opaque. */
GpStatus WINAPI GdipCreateHBITMAPFromBitmap(KIMG *i, HBITMAP *out, DWORD argb)
{
    BITMAPINFO bi; void *bits = NULL; HBITMAP hb; UINT k, n; DWORD *p;
    if (!valid(i) || !out) return InvalidParameter;
    ZeroMemory(&bi, sizeof(bi)); bi.bmiHeader.biSize = sizeof(bi.bmiHeader); bi.bmiHeader.biWidth = (LONG)i->w;
    bi.bmiHeader.biHeight = -(LONG)i->h; bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
    hb = CreateDIBSection(NULL, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    if (!hb || !bits) { if (hb) DeleteObject(hb); return Win32Error; }
    n = i->w * i->h; p = (DWORD *)bits;
    for (k = 0; k < n; k++) {
        DWORD s = i->px[k], a = s >> 24;
        if (argb >> 24) {
            DWORD br = (argb >> 16) & 255, bg = (argb >> 8) & 255, bb = argb & 255;
            p[k] = 0xFF000000UL | ((((s >> 16) & 255) + br * (255 - a) / 255) << 16) |
                   ((((s >> 8) & 255) + bg * (255 - a) / 255) << 8) | ((s & 255) + bb * (255 - a) / 255);
        } else p[k] = s;
    }
    *out = hb;
    return Ok;
}
