/* CHRVAR.EXE - start Chromium in one of the test modes (Windows 98's command line is too short for these).
 *   CHRVAR 1   GPU: ANGLE on OpenGL (SoftGPU)                    = the usual GPU command
 *   CHRVAR 2   GPU, but web pages rasterised by the CPU          (--disable-gpu-rasterization)
 *   CHRVAR 3   ANGLE on SwiftShader (Chrome's own software GL)   - same Chrome code, no SoftGPU
 *   CHRVAR 4   no GPU at all                                     (--disable-gpu)
 *   CHRVAR 5   = 2 with the profiler off for this run            (build 55 A/B, baseline)
 *   CHRVAR 6   = 1 with the profiler off for this run            (build 55b: GPU raster too)
 *   CHRVAR 7   = 5 with KexNG\GLPresent=1: frames reach the screen through GDI, not the driver's swap (build 57)
 *   CHRVAR 8   = 4 WITHOUT --single-process (build 71): helpers (Save As, image decoder, unzip ...) run as their own
 *              processes, so one long-lived helper no longer blocks the others. Network service and GPU stay in
 *              the browser process and at most one renderer process is used, to save memory.
 *              build 72: the build-71 run had 9 renderer processes in 90 s (spare renderer, prerender, site
 *              isolation) and free memory fell from 200 MB to 1 MB -> fewer processes: --process-per-site,
 *              --disable-site-isolation-trials, SitePerProcess/SpareRenderer/Prerender2/NoStatePrefetch off.
 *              build 73: network service inside the browser (NetworkServiceInProcess2); profiler stays on.
 *              build 77: --enable-low-end-device-mode (Chromium's documented low-memory mode: smaller V8 heaps and
 *              caches), --disable-back-forward-cache (no old pages kept alive in extra renderers),
 *              --disable-background-networking (no background fetches while browsing).
 *   CHRVAR 9   = 8 + --js-flags=--single-threaded (build 96 A/B test: V8 compiles scripts on the page's own thread
 *              only, no background script streaming/compile threads - do Discord's "SyntaxError"s go away?)
 *              Build 96 result: yes (no SyntaxError, Discord's login app loaded). Build 97 splits it:
 *   CHRVAR 10  = 8 + --js-flags=--single-threaded-gc            (only V8's garbage collector on one thread)
 *   CHRVAR 11  = 8 + V8's background/concurrent COMPILERS off      (sparkplug, maglev, turbofan, lazy compile tasks)
 *   CHRVAR 12  = 8 + --js-flags=--no-script-streaming           (scripts not parsed on a background thread)
 *              Build 97 result: 10 and 11 still had the SyntaxErrors (108 / 240), 12 had none - background script
 *              streaming is what garbles them - but 12's page stayed white too. Build 98 splits the rest:
 *   CHRVAR 13  = 12 + --single-threaded-gc                       (streaming off AND the GC on one thread)
 *   CHRVAR 14  = 12 + every background COMPILE task off           (streaming off AND compilers/code-cache loading
 *              on the page's thread; GC threads still on)
 * CHRVAR sets KexNG\GLDirect = 0 for every mode (build 55 test switch, finished). Modes 5 and 6 switch
 * KexNG\Profile off, wait for Chrome to end and put the old value back.
 * Build 55b: Chrome's metrics files left by a crashed run (C:\CHRUD\BrowserMetrics*) are deleted first - a
 * reused, half-written one stopped Chrome at start (persistent_sample_map.cc NOTREACHED, corrupt=1).
 * Each mode logs to C:\CHRLOG<n>.TXT (downloads logged in detail). Chrome is looked for at
 * C:\WINDOWS\DESKTOP\CHROME-WIN\CHROME.EXE, or give its full path as the second argument. */
#include <winsock.h>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include "../kexng_build.h"

/* ---------------------------------------------------------------------------------------------------------------
 * Build 99: where do Discord's scripts get damaged? CHRVAR8 also writes Chrome's own network log (documented
 * switches --log-net-log / --net-log-capture-mode=Everything: it records every response body exactly as the
 * network stack hands it on, after the HTTP cache and after decompression). When Chrome has closed, this reads that
 * log back and checks each script body: length, NUL bytes, invalid UTF-8. C:\NETCHECK.TXT gets the result for every
 * script that Chrome reported as "SyntaxError" in C:\CHRLOG8.TXT, and the bodies of up to 20 of them are saved to
 * C:\KEXBAD\ for comparison.
 *   bodies clean  -> the bytes were right when they left the network stack: the damage happens on the way to the
 *                    page (shared-memory data pipe / renderer process)
 *   bodies broken -> the damage is in the HTTP cache or the network stack (file I/O)  */
static FILE *g_cdplog; static void compare_v8(FILE *o);
static char *nl_line(FILE *f, char **buf, size_t *cap)
{
    size_t len = 0;
    if (!*buf) { *cap = 1 << 16; *buf = (char *)malloc(*cap); if (!*buf) return NULL; }
    for (;;) {
        if (!fgets(*buf + len, (int)(*cap - len), f)) return len ? *buf : NULL;
        len += strlen(*buf + len);
        if (len && (*buf)[len - 1] == '\n') return *buf;
        if (*cap - len < 2) { char *nb = (char *)realloc(*buf, *cap * 2); if (!nb) return *buf; *buf = nb; *cap *= 2; }
    }
}
static long nl_num_after(const char *s, const char *key)
{
    const char *p = strstr(s, key);
    if (!p) return -1;
    p += strlen(key);
    while (*p == ' ' || *p == ':') p++;
    return strtol(p, NULL, 10);
}
static int nl_b64(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}
typedef struct { long id; char url[300]; int bad; unsigned long len, nul, badutf; int need, saved, seen; unsigned char head[48]; FILE *out; } NLREQ;
#define NLMAX 3000
static NLREQ *g_nl; static int g_nnl;
static NLREQ *nl_find(long id) { int i; for (i = g_nnl - 1; i >= 0; i--) if (g_nl[i].id == id) return &g_nl[i]; return NULL; }
static void nl_bytes(NLREQ *r, const unsigned char *b, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        unsigned c = b[i];
        if (r->len < sizeof(r->head)) r->head[r->len] = (unsigned char)c;
        r->len++;
        if (!c) r->nul++;
        if (r->need) { if ((c & 0xC0) == 0x80) r->need--; else { r->badutf++; r->need = 0; } }
        else if (c >= 0x80) {
            if ((c & 0xE0) == 0xC0 && c >= 0xC2) r->need = 1;
            else if ((c & 0xF0) == 0xE0) r->need = 2;
            else if ((c & 0xF8) == 0xF0 && c <= 0xF4) r->need = 3;
            else r->badutf++;
        }
    }
    if (r->out) fwrite(b, 1, (size_t)n, r->out);
}
static void netcheck(const char *netlog, const char *chrlog)
{
    FILE *f, *o, *cl; char *buf = NULL; size_t cap = 0; long t_start = -1, t_fbr = -1; char *line;
    static char badurls[400][200]; int nbad = 0, i, saved = 0, found_bad = 0, clean_bad = 0, broken_bad = 0, total_js = 0, broken_js = 0;
    o = fopen("C:\\NETCHECK.TXT", "w");
    if (!o) return;
    fprintf(o, "NETCHECK (CHRVAR build %d): script bodies as Chrome's network stack handed them on\n\n", KEXNG_BUILD);
    if ((cl = fopen(chrlog, "r"))) {               /* the scripts Chrome called broken */
        char l[4096];
        while (fgets(l, sizeof(l), cl) && nbad < 400) {
            char *p = strstr(l, "SyntaxError"), *u, *e;
            if (!p || !(u = strstr(p, "source: "))) continue;
            u += 8; e = u; while (*e && *e != ' ' && *e != '\r' && *e != '\n') e++;
            if (e - u <= 0 || e - u >= 199) continue;
            *e = 0;
            for (i = 0; i < nbad && strcmp(badurls[i], u); i++) ;
            if (i == nbad) strcpy(badurls[nbad++], u);
        }
        fclose(cl);
    }
    fprintf(o, "scripts with \"SyntaxError\" in %s: %d\n", chrlog, nbad);
    if (!(f = fopen(netlog, "r"))) { fprintf(o, "no network log %s (Chrome did not write it)\n", netlog); fclose(o); return; }
    g_nl = (NLREQ *)calloc(NLMAX, sizeof(NLREQ)); g_nnl = 0;
    if (!g_nl) { fclose(f); fclose(o); return; }
    CreateDirectoryA("C:\\KEXBAD", NULL);
    while ((line = nl_line(f, &buf, &cap))) {
        if (t_start < 0 && strstr(line, "\"logEventTypes\"")) {
            t_start = nl_num_after(line, "\"URL_REQUEST_START_JOB\"");
            t_fbr = nl_num_after(line, "\"URL_REQUEST_JOB_FILTERED_BYTES_READ\"");
            fprintf(o, "network log event numbers: start %ld, body bytes %ld\n", t_start, t_fbr);
            continue;
        }
        if (t_start < 0) continue;
        {
            const char *src = strstr(line, "\"source\""), *tp; long id, type;
            if (!src) continue;
            id = nl_num_after(src, "\"id\"");
            tp = strstr(line, "},\"time\"");             /* the event's own "type" comes after the source block */
            if (!tp) tp = strstr(src, "}");
            type = tp ? nl_num_after(tp, "\"type\"") : -1;
            if (type == t_start) {
                const char *u = strstr(line, "\"url\":\""); char url[300]; int k = 0;
                if (!u) continue;
                u += 7; while (u[k] && u[k] != '"' && k < 299) { url[k] = u[k]; k++; } url[k] = 0;
                if (!strstr(url, ".js") || g_nnl >= NLMAX) continue;
                {   NLREQ *r = &g_nl[g_nnl++]; memset(r, 0, sizeof(*r)); r->id = id; strcpy(r->url, url);
                    for (i = 0; i < nbad; i++) if (!strcmp(badurls[i], url)) { r->bad = 1; break; }
                    if (r->bad && saved < 80) {
                        int already = 0, j; const char *nm = strrchr(url, '/'); char path[MAX_PATH];
                        for (j = 0; j < g_nnl - 1; j++) if (g_nl[j].saved && !strcmp(g_nl[j].url, url)) already = 1;
                        if (!already && nm) { sprintf(path, "C:\\KEXBAD\\%.60s", nm + 1); r->out = fopen(path, "wb"); if (r->out) { r->saved = 1; saved++; } }
                    }
                }
            } else if (type == t_fbr) {
                NLREQ *r = nl_find(id); const char *b; unsigned char dec[3 * 1024]; int q = 0, acc = 0, nb = 0, v;
                if (!r || !(b = strstr(line, "\"bytes\":\""))) continue;
                r->seen = 1;
                for (b += 9; *b && *b != '"'; b++) {
                    if ((v = nl_b64((unsigned char)*b)) < 0) continue;
                    acc = (acc << 6) | v; nb += 6;
                    if (nb >= 8) { nb -= 8; dec[q++] = (unsigned char)(acc >> nb); acc &= (1 << nb) - 1; }
                    if (q == sizeof(dec)) { nl_bytes(r, dec, q); q = 0; }
                }
                if (q) nl_bytes(r, dec, q);
            }
        }
    }
    fclose(f);
    for (i = 0; i < g_nnl; i++) {
        NLREQ *r = &g_nl[i]; int broken;
        if (r->out) fclose(r->out);
        if (!r->seen) continue;
        broken = r->nul || r->badutf || r->need;
        total_js++; if (broken) broken_js++;
        if (r->bad) { found_bad++; if (broken) broken_bad++; else clean_bad++; }
        if (r->bad || broken) {
            int k;
            fprintf(o, "%s %s\n    %lu bytes, NUL bytes %lu, invalid UTF-8 %lu%s; starts: ", broken ? "BROKEN" : "clean ", r->url,
                    r->len, r->nul, r->badutf + (r->need ? 1 : 0), r->bad ? "  (Chrome said SyntaxError)" : "");
            for (k = 0; k < 48 && (unsigned long)k < r->len; k++) { unsigned c = r->head[k]; fputc(c >= 32 && c < 127 ? (int)c : '.', o); }
            fputc('\n', o);
        }
    }
    fprintf(o, "\n%d script bodies in the log, %d of them broken (NUL / invalid UTF-8)\n", total_js, broken_js);
    fprintf(o, "SyntaxError scripts found in the log: %d - broken there %d, clean there %d\n", found_bad, broken_bad, clean_bad);
    if (found_bad && !broken_bad)
        fprintf(o, "VERDICT: the network stack handed on CLEAN bytes for every script Chrome later called broken -\n"
                   "         the damage happens between the network service and the page (data pipe / renderer).\n");
    else if (broken_bad)
        fprintf(o, "VERDICT: the bytes were ALREADY BROKEN in the network stack (HTTP cache / file I/O / decoding).\n");
    else
        fprintf(o, "VERDICT: none of the broken scripts were in the log (no SyntaxError this run, or the log is incomplete).\n");
    compare_v8(o);
    if (g_cdplog) { fclose(g_cdplog); g_cdplog = NULL; }
    {   FILE *l = fopen("C:\\KEXBAD\\CDP.TXT", "r"); char t[600]; int k = 0;      /* DevTools events, first lines */
        if (l) { fprintf(o, "\nDevTools log (first 60 lines):\n"); while (k++ < 60 && fgets(t, sizeof(t), l)) fprintf(o, "  %s", t); fclose(l); }
    }
    fclose(o);
    free(g_nl); free(buf);
}

/* ---------------------------------------------------------------------------------------------------------------
 * Build 100: what did V8 actually get? Build 99's NETCHECK proved the network stack handed on CLEAN bytes for all
 * 75 scripts Chrome then called "SyntaxError". CHRVAR8 now also starts Chrome with its documented remote-debugging
 * port and listens on the DevTools protocol (127.0.0.1:9222, this computer only): for every script that fails to
 * parse, V8 reports Debugger.scriptFailedToParse; CHRVAR asks Debugger.getScriptSource for that script and saves the
 * exact text V8 parsed as C:\KEXBAD\<name>.v8. After Chrome closes, each .v8 is compared byte for byte with the
 * clean network copy C:\KEXBAD\<name> (NETCHECK.TXT: length, first difference, both texts around it). */
static SOCKET g_cdp = INVALID_SOCKET; static volatile LONG g_cdp_stop; static int g_cdp_saved, g_cdp_failed_events, g_cdp_attached;
static int tcp_connect(void)
{
    struct sockaddr_in a; SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return -1;
    memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_port = htons(9222); a.sin_addr.s_addr = htonl(0x7F000001);
    if (connect(s, (struct sockaddr *)&a, sizeof(a))) { closesocket(s); return -1; }
    g_cdp = s; return 0;
}
static int send_all(const char *b, int n) { while (n > 0) { int k = send(g_cdp, b, n, 0); if (k <= 0) return -1; b += k; n -= k; } return 0; }
static int recv_all(char *b, int n) { while (n > 0) { int k = recv(g_cdp, b, n, 0); if (k <= 0) return -1; b += k; n -= k; } return 0; }
static int ws_send(const char *txt)
{
    int n = (int)strlen(txt), h = 0; unsigned char hd[14];
    hd[h++] = 0x81;
    if (n < 126) hd[h++] = (unsigned char)(0x80 | n);
    else { hd[h++] = 0x80 | 126; hd[h++] = (unsigned char)(n >> 8); hd[h++] = (unsigned char)n; }
    hd[h++] = 0; hd[h++] = 0; hd[h++] = 0; hd[h++] = 0;           /* mask key 0: payload unchanged */
    return send_all((char *)hd, h) || send_all(txt, n) ? -1 : 0;
}
/* one whole message (continuations joined) into *buf; returns its length or -1 */
static long ws_recv(char **buf, size_t *cap)
{
    size_t len = 0;
    for (;;) {
        unsigned char hd[2], ext[8]; unsigned long long n; int op, fin, i;
        if (recv_all((char *)hd, 2)) return -1;
        fin = hd[0] & 0x80; op = hd[0] & 0x0F; n = hd[1] & 0x7F;
        if (n == 126) { if (recv_all((char *)ext, 2)) return -1; n = ((unsigned)ext[0] << 8) | ext[1]; }
        else if (n == 127) { if (recv_all((char *)ext, 8)) return -1; n = 0; for (i = 0; i < 8; i++) n = (n << 8) | ext[i]; }
        if (hd[1] & 0x80) { if (recv_all((char *)ext, 4)) return -1; }   /* servers do not mask; skip if they did */
        if (n > (64u << 20)) return -1;
        if (len + (size_t)n + 1 > *cap) { size_t nc = (len + (size_t)n + 1) * 2; char *nb = (char *)realloc(*buf, nc); if (!nb) return -1; *buf = nb; *cap = nc; }
        if (n && recv_all(*buf + len, (int)n)) return -1;
        if (op == 9) {                                             /* ping -> pong */
            unsigned char pg[6] = { 0x8A, 0x80, 0, 0, 0, 0 }; send_all((char *)pg, 6); continue;
        }
        if (op == 8) return -1;
        len += (size_t)n;
        if (fin) { (*buf)[len] = 0; return (long)len; }
    }
}
/* copy the JSON string value of "key" (first match after p) into out (raw, still escaped) */
static int jstr(const char *p, const char *key, char *out, int cb)
{
    char k[64]; const char *q; int i = 0;
    sprintf(k, "\"%s\":", key);                     /* /json/version is pretty-printed: "key": "value" */
    if (!(q = strstr(p, k))) return 0;
    q += strlen(k);
    while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
    if (*q != '"') return 0;
    q++;
    while (*q && *q != '"' && i < cb - 1) { if (*q == '\\' && q[1]) out[i++] = *q++; out[i++] = *q++; }
    out[i] = 0; return 1;
}
/* JSON string (escaped, starting after the opening quote) -> UTF-8 file */
static void junescape_to(FILE *f, const char *q)
{
    while (*q && *q != '"') {
        if (*q != '\\') { fputc(*q++, f); continue; }
        q++;
        switch (*q) {
        case 'n': fputc('\n', f); q++; break; case 'r': fputc('\r', f); q++; break; case 't': fputc('\t', f); q++; break;
        case 'b': fputc('\b', f); q++; break; case 'f': fputc('\f', f); q++; break;
        case 'u': {
            unsigned c = (unsigned)strtoul((char[]){ q[1], q[2], q[3], q[4], 0 }, NULL, 16); q += 5;
            if (c >= 0xD800 && c < 0xDC00 && q[0] == '\\' && q[1] == 'u') {
                unsigned d = (unsigned)strtoul((char[]){ q[2], q[3], q[4], q[5], 0 }, NULL, 16);
                if (d >= 0xDC00 && d < 0xE000) { c = 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00); q += 6; }
            }
            if (c < 0x80) fputc((int)c, f);
            else if (c < 0x800) { fputc(0xC0 | (c >> 6), f); fputc(0x80 | (c & 63), f); }
            else if (c < 0x10000) { fputc(0xE0 | (c >> 12), f); fputc(0x80 | ((c >> 6) & 63), f); fputc(0x80 | (c & 63), f); }
            else { fputc(0xF0 | (c >> 18), f); fputc(0x80 | ((c >> 12) & 63), f); fputc(0x80 | ((c >> 6) & 63), f); fputc(0x80 | (c & 63), f); }
            break; }
        default: if (*q) fputc(*q++, f); break;
        }
    }
}
typedef struct { int id; char url[300]; } CDPREQ;
/* build 103: what does the PAGE do? Every console message, uncaught exception and browser log entry of each page goes
 * to C:\KEXBAD\PAGE.TXT, and every 15 s each page's state (address, readyState, how much is in Discord's #app-mount)
 * plus a screenshot from Chrome's own renderer (C:\KEXBAD\SHOTnn.JPG): a white window with a full screenshot means
 * the page is there and only drawing it to the screen fails; a white screenshot means the page itself is empty. */
static FILE *g_page; static char g_psess[16][80]; static int g_npsess; static int g_shot_id[64], g_nshot, g_shots;
static void page_line(const char *tag, const char *json, long n)
{
    SYSTEMTIME st;
    if (!g_page) return;
    GetLocalTime(&st);
    fprintf(g_page, "%02d:%02d:%02d %s %.*s\n", st.wHour, st.wMinute, st.wSecond, tag, (int)(n > 3000 ? 3000 : n), json);
    fflush(g_page);
}
/* build 109: the back/forward/reload buttons are NOT views - Chrome 159 draws them in a WebUI page,
 * chrome://webui-toolbar.top-chrome/ (a DevTools target of type "browser_ui", seen in build 108's PAGE.TXT).
 * Build 108 only resumed such targets; now every browser_ui target gets Runtime + Log (its console messages and
 * script errors go to PAGE.TXT like a page's), and 25 s and 70 s after start the toolbar page is asked for every
 * element (shadow roots included): tag, id, class, box, display/visibility/opacity/colour/fill/mask, SVG sizes,
 * plus a screenshot of the toolbar page itself -> C:\KEXBAD\TOOLBAR.TXT and SHOTnn.JPG (PAGE.TXT says which). */
static char g_tbsess[80]; static int g_tb_id[4], g_ntb;
static const char *TB_PROBE =
    "(function(){try{var out=[],n=0,NL=String.fromCharCode(10);"
    "function cs(e){var s=getComputedStyle(e);return [s.display,s.visibility,s.opacity,s.color,s.fill,s.backgroundColor,"
    "(s.webkitMaskImage||'').slice(0,80),(s.backgroundImage||'').slice(0,80),s.width,s.height].join('|')}"
    "function walk(r,d){var k=r.children||[];for(var i=0;i<k.length&&n<500;i++){var e=k[i];n++;var b=e.getBoundingClientRect();"
    "var t=e.tagName.toLowerCase();var c=(typeof e.className=='string')?e.className:(e.getAttribute('class')||'');"
    "var l=d+t+(e.id?'#'+e.id:'')+(c?'.'+c.split(' ').join('.'):'')+(e.hidden?' HIDDEN':'')+(e.hasAttribute('disabled')?' DISABLED':'')"
    "+(e.getAttribute('icon')?' icon='+e.getAttribute('icon'):'')+(e.getAttribute('iron-icon')?' iron-icon='+e.getAttribute('iron-icon'):'')"
    "+' ['+Math.round(b.x)+','+Math.round(b.y)+' '+Math.round(b.width)+'x'+Math.round(b.height)+'] '+cs(e);"
    "if(t=='path')l+=' d='+(e.getAttribute('d')||'').slice(0,50);"
    "if(t=='svg'||t=='g')l+=' viewBox='+e.getAttribute('viewBox')+' inner='+e.innerHTML.length;"
    "out.push(l);if(e.shadowRoot)walk(e.shadowRoot,d+'  #shadow ');walk(e,d+'  ')}}"
    "walk(document,'');"
    "return JSON.stringify({rs:document.readyState,toolbar_app:!!customElements.get('toolbar-app'),"
    "cr_icon:!!customElements.get('cr-icon'),w:innerWidth,h:innerHeight,dpr:devicePixelRatio,elements:n,"
    "res:performance.getEntriesByType('resource').length,fonts:document.fonts.size})+NL+out.join(NL)}"
    "catch(x){return 'probe failed: '+x}})()";
/* build 110: what is ON SCREEN in the toolbar strip. Build 109's TOOLBAR.TXT and its toolbar screenshot show Chrome's
 * toolbar page drawing the back / forward / reload icons correctly (grey on transparent); the browser window does not
 * show them. Each toolbar probe also copies the top 160 pixels of Chrome's biggest visible window from the screen
 * (GDI BitBlt of the screen DC) -> C:\KEXBAD\WINTOPn.BMP, so the two pictures can be compared directly. */
static DWORD g_chrome_pid; static HWND g_best; static LONG g_best_area;
static BOOL CALLBACK find_chrome(HWND h, LPARAM l)
{
    DWORD pid = 0; RECT r; char cls[64];
    (void)l;
    GetWindowThreadProcessId(h, &pid);
    if (pid != g_chrome_pid || !IsWindowVisible(h) || !GetWindowRect(h, &r)) return TRUE;
    GetClassNameA(h, cls, sizeof(cls));
    if (strncmp(cls, "Chrome_WidgetWin", 16)) return TRUE;
    if ((r.right - r.left) * (r.bottom - r.top) > g_best_area) { g_best_area = (r.right - r.left) * (r.bottom - r.top); g_best = h; }
    return TRUE;
}
static void grab_wintop(void)
{
    static int n; RECT r; HDC sdc, mdc; HBITMAP bm; BITMAPINFO bi; BYTE *bits = NULL; int w, h; char path[MAX_PATH]; FILE *f;
    g_best = NULL; g_best_area = 0;
    if (!g_chrome_pid) return;
    EnumWindows(find_chrome, 0);
    if (!g_best || !GetWindowRect(g_best, &r)) { page_line("WINTOP", "no visible Chrome window found", 30); return; }
    w = r.right - r.left; h = 160; if (w <= 0 || w > 4096) return;
    memset(&bi, 0, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(bi.bmiHeader); bi.bmiHeader.biWidth = w; bi.bmiHeader.biHeight = h;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 24; bi.bmiHeader.biCompression = BI_RGB;
    sdc = GetDC(NULL); mdc = CreateCompatibleDC(sdc);
    bm = CreateDIBSection(sdc, &bi, DIB_RGB_COLORS, (void **)&bits, NULL, 0);
    if (bm && bits) {
        HGDIOBJ old = SelectObject(mdc, bm);
        BitBlt(mdc, 0, 0, w, h, sdc, r.left, r.top, SRCCOPY);
        GdiFlush();
        sprintf(path, "C:\\KEXBAD\\WINTOP%d.BMP", n++);
        if ((f = fopen(path, "wb"))) {
            DWORD stride = ((DWORD)w * 3 + 3) & ~3u, img = stride * h; BITMAPFILEHEADER fh;
            fh.bfType = 0x4D42; fh.bfSize = sizeof(fh) + sizeof(bi.bmiHeader) + img; fh.bfReserved1 = fh.bfReserved2 = 0;
            fh.bfOffBits = sizeof(fh) + sizeof(bi.bmiHeader);
            fwrite(&fh, sizeof(fh), 1, f); fwrite(&bi.bmiHeader, sizeof(bi.bmiHeader), 1, f); fwrite(bits, img, 1, f); fclose(f);
        }
        {   char t[400]; sprintf(t, "%s = screen at window %p (%ld,%ld %ldx%ld), top 160 px", path, (void *)g_best, r.left, r.top, (long)w, (long)(r.bottom - r.top));
            page_line("WINTOP", t, (long)strlen(t)); }
        SelectObject(mdc, old);
    }
    if (bm) DeleteObject(bm);
    DeleteDC(mdc); ReleaseDC(NULL, sdc);
}
static int g_in_id[64]; static DWORD g_in_t[64]; static int g_nin;
static int in_reply(const char *buf)          /* build 116: reply to a DevTools mouse move */
{
    int id = atoi(buf + 6), q;
    for (q = 0; q < 64 && q < g_nin; q++) if (g_in_id[q] == id) {
        char t[200]; sprintf(t, "id %d: acknowledged after %lu ms %s", id, (unsigned long)(GetTickCount() - g_in_t[q]), strstr(buf, "\"error\"") ? "ERROR" : "ok");
        page_line("INPUT-ACK", t, (long)strlen(t)); g_in_id[q] = -1; return 1;
    }
    return 0;
}
static void tb_probe(int *nextid)
{
    char req[4096];
    grab_wintop();
    if (!g_tbsess[0] || g_ntb >= 4) return;
    g_tb_id[g_ntb++] = *nextid;
    {   /* the expression as a JSON string: it has no double quote or backslash, so it goes in as it is */
        sprintf(req, "{\"id\":%d,\"method\":\"Runtime.evaluate\",\"params\":{\"returnByValue\":true,\"expression\":\"%s\"},\"sessionId\":\"%s\"}",
                (*nextid)++, TB_PROBE, g_tbsess);
        ws_send(req);
    }
    if (g_nshot < 64) {
        g_shot_id[g_nshot++] = *nextid;
        page_line("TOOLBAR-SHOT", "next screenshot is the toolbar page", 35);
        sprintf(req, "{\"id\":%d,\"method\":\"Page.captureScreenshot\",\"params\":{\"format\":\"jpeg\",\"quality\":90},\"sessionId\":\"%s\"}", (*nextid)++, g_tbsess);
        ws_send(req);
    }
}
static int tb_reply(const char *buf)
{
    int id = atoi(buf + 6), k; const char *v; FILE *f;
    for (k = 0; k < g_ntb; k++) if (g_tb_id[k] == id) break;
    if (k == g_ntb) return 0;
    g_tb_id[k] = -1;
    if ((f = fopen("C:\\KEXBAD\\TOOLBAR.TXT", "a"))) {
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(f, "===== %02d:%02d:%02d chrome://webui-toolbar.top-chrome/ (back / forward / reload)\n", st.wHour, st.wMinute, st.wSecond);
        if ((v = strstr(buf, "\"value\":\""))) junescape_to(f, v + 9);
        else fprintf(f, "%.3000s", buf);
        fprintf(f, "\n\n");
        fclose(f);
    }
    return 1;
}

/* build 113: do the user's clicks reach the page? (build 112: Discord scrolled and showed hover, but no button
 * reacted). Every page gets listeners (capture on document, bubble on window) for pointer/mouse down/up, click and
 * pointercancel that write "KEXCLICK ..." console lines -> PAGE.TXT: event, position, button, target element,
 * isTrusted, and at the end whether the page cancelled it. Test launcher only; Chrome's own code is untouched. */
static const char *CLICK_PROBE = "(function(){if(window.__kexclk)return;window.__kexclk=1;window.__kexcnt={mv:0,mv1:0,wh:0,kd:0,pd:0,md:0,raf:0,lat:0,last:''};(function f(){window.__kexcnt.raf++;window.__kexcnt.rafat=Math.round(performance.now());requestAnimationFrame(f)})();['mousemove','wheel','keydown','pointerdown','mousedown'].forEach(function(t){window.addEventListener(t,function(e){var c=window.__kexcnt,l=Math.round(performance.now()-e.timeStamp);if(l>c.lat)c.lat=l;if(t=='mousemove'&&e.clientX==1&&e.clientY==1)c.mv1++;else if(t=='mousemove')c.mv++;else if(t=='wheel')c.wh++;else if(t=='keydown')c.kd++;else if(t=='pointerdown')c.pd++;else c.md++;c.last=t+'@'+Math.round(performance.now())},true)});function d(p){try{return (p.tagName||'')+(p.id?'#'+p.id:'')+(typeof p.className=='string'&&p.className?'.'+p.className.split(' ')[0]:'')}catch(x){return '?'}}['pointerdown','mousedown','pointerup','mouseup','click','pointercancel'].forEach(function(t){document.addEventListener(t,function(e){console.debug('KEXCLICK '+t+' at '+e.clientX+','+e.clientY+' button '+e.button+' target '+d(e.target)+' trusted '+e.isTrusted)},true);window.addEventListener(t,function(e){console.debug('KEXCLICK-END '+t+' prevented '+e.defaultPrevented)},false)})})()";
/* build 127: CHRVAR15 probe - the same counters plus local times (to match KEXTL_*.LOG), "frames stopped while the
 * main thread runs" vs "main thread could not run" (KEXGAP / KEXLATE), long tasks and Event Timing per click */
static const char *CLICK_PROBE2 = "(function(){if(window.__kexclk)return;window.__kexclk=2;function T(){var d=new Date();function p(n,w){n=''+n;while(n.length<w)n='0'+n;return n}return p(d.getHours(),2)+':'+p(d.getMinutes(),2)+':'+p(d.getSeconds(),2)+'.'+p(d.getMilliseconds(),3)}window.__kexcnt={mv:0,mv1:0,wh:0,kd:0,pd:0,md:0,raf:0,lat:0,last:''};var lf=performance.now(),st=0,li=performance.now();(function f(){var n=performance.now();window.__kexcnt.raf++;window.__kexcnt.rafat=Math.round(n);if(n-lf>1000)console.debug('KEXGAP '+T()+' frames resumed after '+Math.round(n-lf)+' ms');lf=n;requestAnimationFrame(f)})();setInterval(function(){var n=performance.now();if(n-li>1500)console.debug('KEXLATE '+T()+' page main thread could not run for '+Math.round(n-li-500)+' ms');li=n;if(n-lf>2000&&!st){st=1;console.debug('KEXGAP '+T()+' no frame for '+Math.round(n-lf)+' ms while the page main thread runs (visibility '+document.visibilityState+')')}if(n-lf<=2000)st=0},500);['mousemove','wheel','keydown','pointerdown','mousedown'].forEach(function(t){window.addEventListener(t,function(e){var c=window.__kexcnt,l=Math.round(performance.now()-e.timeStamp);if(l>c.lat)c.lat=l;if(t=='mousemove'&&e.clientX==1&&e.clientY==1)c.mv1++;else if(t=='mousemove')c.mv++;else if(t=='wheel')c.wh++;else if(t=='keydown')c.kd++;else if(t=='pointerdown')c.pd++;else c.md++;c.last=t+'@'+Math.round(performance.now())},true)});function d(p){try{return (p.tagName||'')+(p.id?'#'+p.id:'')+(typeof p.className=='string'&&p.className?'.'+p.className.split(' ')[0]:'')}catch(x){return '?'}}['pointerdown','mousedown','pointerup','mouseup','click','pointercancel'].forEach(function(t){document.addEventListener(t,function(e){console.debug('KEXCLICK '+T()+' '+t+' at '+e.clientX+','+e.clientY+' button '+e.button+' target '+d(e.target)+' trusted '+e.isTrusted+' reached the page '+Math.round(performance.now()-e.timeStamp)+' ms after input')},true);window.addEventListener(t,function(e){console.debug('KEXCLICK-END '+t+' prevented '+e.defaultPrevented)},false)});try{new PerformanceObserver(function(l){l.getEntries().forEach(function(e){if(e.duration>300)console.debug('KEXLONG '+T()+' long task '+Math.round(e.duration)+' ms')})}).observe({type:'longtask'})}catch(x){}try{new PerformanceObserver(function(l){l.getEntries().forEach(function(e){if(e.name=='pointerdown'||e.name=='mousedown'||e.name=='click')console.debug('KEXEVT '+T()+' '+e.name+' input delay '+Math.round(e.processingStart-e.startTime)+' ms, handlers '+Math.round(e.processingEnd-e.processingStart)+' ms, until next frame '+Math.round(e.duration)+' ms')})}).observe({type:'event',durationThreshold:16,buffered:true})}catch(x){}console.debug('KEXPROBE '+T()+' click probe 2 installed in '+location.href.slice(0,80))})()";
static int g_mode;
static DWORD WINAPI cdp_thread(LPVOID unused)
{
    char *buf = NULL; size_t cap = 0; char req[2048], ws[300], sess[80]; int i, nextid = 10, nreq = 0; DWORD t0 = GetTickCount();
    static CDPREQ pend[200]; static char seen[200][300]; int nseen = 0;
    WSADATA wd; WSAStartup(MAKEWORD(1, 1), &wd);
    /* 1. the browser's DevTools address (Chrome needs a few seconds to open the port) */
    ws[0] = 0;
    while (!g_cdp_stop && GetTickCount() - t0 < 90000) {
        if (!tcp_connect()) {
            char r[4096]; int got = 0, k;
            send_all("GET /json/version HTTP/1.1\r\nHost: 127.0.0.1:9222\r\n\r\n", 52);
            while (got < (int)sizeof(r) - 1 && (k = recv(g_cdp, r + got, sizeof(r) - 1 - got, 0)) > 0) { got += k; r[got] = 0; if (strstr(r, "}")) break; }
            closesocket(g_cdp); g_cdp = INVALID_SOCKET;
            if (got > 0 && jstr(r, "webSocketDebuggerUrl", ws, sizeof(ws))) break;
        }
        Sleep(500);
    }
    if (!ws[0] || g_cdp_stop) { if (g_cdplog) fprintf(g_cdplog, "DevTools port not reachable\n"); return 0; }
    if (g_cdplog) fprintf(g_cdplog, "DevTools: %s\n", ws);
    /* 2. WebSocket to the browser target */
    {   const char *path = strstr(ws, "/devtools/"); char hs[600]; char r[1024]; int got = 0, k;
        if (!path || tcp_connect()) return 0;
        sprintf(hs, "GET %s HTTP/1.1\r\nHost: 127.0.0.1:9222\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", path);
        send_all(hs, (int)strlen(hs));
        while (got < (int)sizeof(r) - 1 && (k = recv(g_cdp, r + got, 1, 0)) > 0) { got += k; r[got] = 0; if (strstr(r, "\r\n\r\n")) break; }
        if (!strstr(r, " 101")) { if (g_cdplog) fprintf(g_cdplog, "WebSocket refused: %.200s\n", r); closesocket(g_cdp); return 0; }
    }
    ws_send("{\"id\":1,\"method\":\"Target.setAutoAttach\",\"params\":{\"autoAttach\":true,\"waitForDebuggerOnStart\":true,\"flatten\":true}}");
    /* build 105: every target created / changed / destroyed / crashed (a tab's renderer that goes away shows here) */
    ws_send("{\"id\":2,\"method\":\"Target.setDiscoverTargets\",\"params\":{\"discover\":true}}");
    /* 3. events */
    {   DWORD last_probe = GetTickCount();
    while (!g_cdp_stop) {
        long n; const char *m;
        {   fd_set rs; struct timeval tv; int k;
            FD_ZERO(&rs); FD_SET(g_cdp, &rs); tv.tv_sec = 1; tv.tv_usec = 0;
            k = select(0, &rs, NULL, NULL, &tv);
            {   static int ui_done; DWORD el = GetTickCount() - t0;
                if ((ui_done == 0 && el >= 25000) || (ui_done == 1 && el >= 70000) || (ui_done == 2 && el >= 180000)) { ui_done++; tb_probe(&nextid); }
            }
            if (GetTickCount() - last_probe >= 15000) {          /* every 15 s: page state + screenshot */
                last_probe = GetTickCount();
                for (i = 0; i < g_npsess; i++) {
                    sprintf(req, "{\"id\":%d,\"method\":\"Runtime.evaluate\",\"params\":{\"returnByValue\":true,\"expression\":"
                                 "\"(function(){var a=document.getElementById('app-mount');return JSON.stringify({u:location.href,rs:document.readyState,"
                                 "t:document.title,body:document.body?document.body.innerHTML.length:-1,app:a?a.innerHTML.length:-1,"
                                 "head:a?a.innerHTML.slice(0,600):'',vis:document.visibilityState,disc:document.wasDiscarded,w:innerWidth,h:innerHeight,clickprobe:!!window.__kexclk,now:Math.round(performance.now()),cnt:window.__kexcnt||null,focus:document.hasFocus(),act:document.activeElement?document.activeElement.tagName:''})})()\"},\"sessionId\":\"%s\"}",
                            nextid++, g_psess[i]);
                    ws_send(req);
                    {   static char big[8192];   /* build 114: (re)install the click probe in whatever document is there now */
                        sprintf(big, "{\"id\":%d,\"method\":\"Runtime.evaluate\",\"params\":{\"expression\":\"%s\"},\"sessionId\":\"%s\"}", nextid++, g_mode == 15 ? CLICK_PROBE2 : CLICK_PROBE, g_psess[i]); ws_send(big);
                    }
                    {   /* build 116: a DevTools mouse move to (1,1) - enters at RenderWidgetHost, not at the window. The
                         * reply comes when the renderer acknowledged it; the page counts it as mv1. */
                        g_in_id[g_nin % 64] = nextid; g_in_t[g_nin % 64] = GetTickCount(); g_nin++;
                        sprintf(req, "{\"id\":%d,\"method\":\"Input.dispatchMouseEvent\",\"params\":{\"type\":\"mouseMoved\",\"x\":1,\"y\":1},\"sessionId\":\"%s\"}", nextid++, g_psess[i]);
                        ws_send(req);
                    }
                    {   int q; for (q = 0; q < 64 && q < g_nin; q++) if (g_in_id[q] > 0 && GetTickCount() - g_in_t[q] > 14000) {
                            char t[120]; sprintf(t, "id %d: no acknowledgement after %lu ms", g_in_id[q], (unsigned long)(GetTickCount() - g_in_t[q]));
                            page_line("INPUT-ACK", t, (long)strlen(t)); g_in_id[q] = -1; } }
                    if (i == g_npsess - 1 && g_shots < 60 && g_nshot < 64) {   /* build 110: the newest page only */
                        g_shot_id[g_nshot++] = nextid;
                        sprintf(req, "{\"id\":%d,\"method\":\"Page.captureScreenshot\",\"params\":{\"format\":\"jpeg\",\"quality\":40},\"sessionId\":\"%s\"}",
                                nextid++, g_psess[i]);
                        ws_send(req);
                    }
                }
            }
            if (k <= 0) continue;
        }
        n = ws_recv(&buf, &cap);
        if (n < 0) break;
        if (strstr(buf, "\"method\":\"Runtime.consoleAPICalled\"")) page_line("CONSOLE", buf, n);
        else if (strstr(buf, "\"method\":\"Runtime.exceptionThrown\"")) page_line("EXCEPTION", buf, n);
        else if (strstr(buf, "\"method\":\"Log.entryAdded\"")) page_line("LOG", buf, n);
        else if (strstr(buf, "\"method\":\"Target.detachedFromTarget\"") || strstr(buf, "\"method\":\"Inspector.targetCrashed\"") ||
                 strstr(buf, "\"method\":\"Target.targetCrashed\"") || strstr(buf, "\"method\":\"Target.targetDestroyed\"") ||
                 strstr(buf, "\"method\":\"Target.targetCreated\"") || strstr(buf, "\"method\":\"Target.targetInfoChanged\"")) page_line("TARGET", buf, n);
        else if (!strncmp(buf, "{\"id\":", 6) && in_reply(buf)) continue;
        else if (!strncmp(buf, "{\"id\":", 6) && tb_reply(buf)) continue;
        else if (!strncmp(buf, "{\"id\":", 6) && strstr(buf, "\"result\":{\"result\":{\"type\":\"string\"")) page_line("STATE", buf, n);
        else if (!strncmp(buf, "{\"id\":", 6) && strstr(buf, "\"result\":{\"data\":\"")) {
            int id = atoi(buf + 6), k2;
            for (k2 = 0; k2 < g_nshot; k2++) if (g_shot_id[k2] == id) {
                char path[MAX_PATH]; FILE *f; const char *b = strstr(buf, "\"data\":\"") + 8; int acc = 0, nb = 0, v;
                sprintf(path, "C:\\KEXBAD\\SHOT%02d.JPG", g_shots++);
                if ((f = fopen(path, "wb"))) {
                    for (; *b && *b != '"'; b++) {
                        if ((v = nl_b64((unsigned char)*b)) < 0) continue;
                        acc = (acc << 6) | v; nb += 6;
                        if (nb >= 8) { nb -= 8; fputc((acc >> nb) & 0xFF, f); acc &= (1 << nb) - 1; }
                    }
                    fclose(f);
                }
                { char t[400]; SYSTEMTIME st; GetLocalTime(&st); sprintf(t, "screenshot %s", path); page_line("SHOT", t, (long)strlen(t)); }
                g_shot_id[k2] = -1;
            }
            continue;
        }
        else if (!strncmp(buf, "{\"id\":", 6) && strstr(buf, "\"error\"")) page_line("ERROR-REPLY", buf, n);
        if ((m = strstr(buf, "\"method\":\"Target.detachedFromTarget\""))) {   /* build 110: stop probing a closed page */
            char ds[80] = ""; int k3;
            jstr(m, "sessionId", ds, sizeof(ds));
            for (k3 = 0; k3 < g_npsess; k3++) if (!strcmp(g_psess[k3], ds)) { memmove(g_psess[k3], g_psess[k3 + 1], (size_t)(g_npsess - k3 - 1) * 80); g_npsess--; break; }
        }
        if ((m = strstr(buf, "\"method\":\"Target.attachedToTarget\""))) {
            char type[40] = ""; sess[0] = 0;
            jstr(buf, "sessionId", sess, sizeof(sess)); jstr(buf, "type", type, sizeof(type));
            g_cdp_attached++;
            if (g_cdplog) fprintf(g_cdplog, "attached %s %s\n", type, sess);
            if (!strcmp(type, "browser_ui")) {          /* build 109: Chrome's own WebUI (toolbar, omnibox popup, ...) */
                char url[300] = ""; const char *ti = strstr(buf, "\"targetInfo\"");
                if (ti) jstr(ti, "url", url, sizeof(url));
                if (g_cdplog) fprintf(g_cdplog, "  browser_ui %s\n", url);
                sprintf(req, "{\"id\":%d,\"method\":\"Runtime.enable\",\"params\":{},\"sessionId\":\"%s\"}", nextid++, sess); ws_send(req);
                sprintf(req, "{\"id\":%d,\"method\":\"Log.enable\",\"params\":{},\"sessionId\":\"%s\"}", nextid++, sess); ws_send(req);
                if (strstr(url, "webui-toolbar")) strcpy(g_tbsess, sess);
            }
            if (!strcmp(type, "page") || !strcmp(type, "iframe")) {
                if (g_mode != 15) { sprintf(req, "{\"id\":%d,\"method\":\"Debugger.enable\",\"params\":{},\"sessionId\":\"%s\"}", nextid++, sess); ws_send(req); }   /* build 127: not in 15 (slows every script) */
                sprintf(req, "{\"id\":%d,\"method\":\"Runtime.enable\",\"params\":{},\"sessionId\":\"%s\"}", nextid++, sess); ws_send(req);
                sprintf(req, "{\"id\":%d,\"method\":\"Log.enable\",\"params\":{},\"sessionId\":\"%s\"}", nextid++, sess); ws_send(req);
                if (!strcmp(type, "page") && g_npsess < 16) strcpy(g_psess[g_npsess++], sess);
                if (!strcmp(type, "page")) {
                    static char big[8192];
                    sprintf(big, "{\"id\":%d,\"method\":\"Page.addScriptToEvaluateOnNewDocument\",\"params\":{\"source\":\"%s\"},\"sessionId\":\"%s\"}", nextid++, g_mode == 15 ? CLICK_PROBE2 : CLICK_PROBE, sess); ws_send(big);
                    sprintf(big, "{\"id\":%d,\"method\":\"Runtime.evaluate\",\"params\":{\"expression\":\"%s\"},\"sessionId\":\"%s\"}", nextid++, g_mode == 15 ? CLICK_PROBE2 : CLICK_PROBE, sess); ws_send(big);
                }
                sprintf(req, "{\"id\":%d,\"method\":\"Target.setAutoAttach\",\"params\":{\"autoAttach\":true,\"waitForDebuggerOnStart\":true,\"flatten\":true},\"sessionId\":\"%s\"}", nextid++, sess); ws_send(req);
            }
            sprintf(req, "{\"id\":%d,\"method\":\"Runtime.runIfWaitingForDebugger\",\"params\":{},\"sessionId\":\"%s\"}", nextid++, sess); ws_send(req);
        } else if ((m = strstr(buf, "\"method\":\"Debugger.scriptFailedToParse\""))) {
            char url[300] = "", sid[40] = ""; int dup = 0;
            sess[0] = 0; jstr(buf, "sessionId", sess, sizeof(sess)); jstr(m, "scriptId", sid, sizeof(sid)); jstr(m, "url", url, sizeof(url));
            g_cdp_failed_events++;
            if (g_cdplog) fprintf(g_cdplog, "failed to parse: %s length %ld hash %.70s\n", url, strstr(m, "\"length\"") ? strtol(strstr(m, "\"length\"") + 9, NULL, 10) : -1L,
                                  strstr(m, "\"hash\":\"") ? strstr(m, "\"hash\":\"") + 8 : "?");
            for (i = 0; i < nseen; i++) if (!strcmp(seen[i], url)) dup = 1;
            if (!dup && url[0] && nseen < 200 && nreq < 200 && g_cdp_saved < 80) {
                strcpy(seen[nseen++], url);
                pend[nreq].id = nextid; strcpy(pend[nreq].url, url); nreq++;
                sprintf(req, "{\"id\":%d,\"method\":\"Debugger.getScriptSource\",\"params\":{\"scriptId\":\"%s\"},\"sessionId\":\"%s\"}", nextid++, sid, sess);
                ws_send(req);
            }
        } else if (!strncmp(buf, "{\"id\":", 6)) {
            int id = atoi(buf + 6); const char *src = strstr(buf, "\"scriptSource\":\"");
            for (i = 0; i < nreq; i++) if (pend[i].id == id && src) {
                const char *nm = strrchr(pend[i].url, '/'); char path[MAX_PATH]; FILE *f;
                sprintf(path, "C:\\KEXBAD\\%.60s.v8", nm ? nm + 1 : "script");
                if ((f = fopen(path, "wb"))) { junescape_to(f, src + 16); fclose(f); g_cdp_saved++; }
                pend[i].id = -1;
            }
        }
    }
    }
    if (g_cdp != INVALID_SOCKET) closesocket(g_cdp);
    free(buf);
    return 0;
}
/* after the run: each saved .v8 (what V8 parsed) against the network copy */
static void compare_v8(FILE *o)
{
    WIN32_FIND_DATAA fd; HANDLE fh; int pairs = 0, same = 0;
    fprintf(o, "\nWHAT V8 PARSED vs WHAT THE NETWORK DELIVERED (DevTools: %d pages/frames attached, %d parse failures reported, %d texts saved)\n",
            g_cdp_attached, g_cdp_failed_events, g_cdp_saved);
    if ((fh = FindFirstFileA("C:\\KEXBAD\\*.v8", &fd)) == INVALID_HANDLE_VALUE) { fprintf(o, "  (no V8 texts saved)\n"); return; }
    do {
        char pv[MAX_PATH], pn[MAX_PATH]; FILE *a, *b; static unsigned char x[4 << 20], y[4 << 20]; long nx, ny, k, d = -1;
        sprintf(pv, "C:\\KEXBAD\\%s", fd.cFileName); strcpy(pn, pv); pn[strlen(pn) - 3] = 0;
        if (!(a = fopen(pv, "rb"))) continue;
        nx = (long)fread(x, 1, sizeof(x), a); fclose(a);
        if (!(b = fopen(pn, "rb"))) { fprintf(o, "  %s: %ld bytes as V8 got it, no network copy to compare\n", fd.cFileName, nx); continue; }
        ny = (long)fread(y, 1, sizeof(y), b); fclose(b);
        pairs++;
        for (k = 0; k < nx && k < ny; k++) if (x[k] != y[k]) { d = k; break; }
        if (d < 0 && nx != ny) d = nx < ny ? nx : ny;
        if (d < 0) { same++; fprintf(o, "  %s: IDENTICAL (%ld bytes) - V8 got the right text\n", pn + 10, nx); continue; }
        fprintf(o, "  %s: V8 %ld bytes, network %ld bytes, FIRST DIFFERENCE at byte %ld\n", pn + 10, nx, ny, d);
        {   long s = d > 24 ? d - 24 : 0, e;
            fprintf(o, "      V8 :"); for (e = s; e < nx && e < d + 40; e++) fprintf(o, e == d ? " [%02x" : " %02x", x[e]); fprintf(o, "\n");
            fprintf(o, "      net:"); for (e = s; e < ny && e < d + 40; e++) fprintf(o, e == d ? " [%02x" : " %02x", y[e]); fprintf(o, "\n");
        }
    } while (FindNextFileA(fh, &fd));
    FindClose(fh);
    fprintf(o, "  %d compared, %d identical, %d different\n", pairs, same, pairs - same);
}

int main(int argc, char **argv)
{
    static const char *mode[16] = { "",
        "--use-angle=gl --use-gl=angle --ignore-gpu-blocklist --disable-direct-composition",
        "--use-angle=gl --use-gl=angle --ignore-gpu-blocklist --disable-direct-composition --disable-gpu-rasterization",
        "--use-angle=swiftshader --use-gl=angle --ignore-gpu-blocklist --disable-direct-composition",
        "--disable-gpu",
        "--use-angle=gl --use-gl=angle --ignore-gpu-blocklist --disable-direct-composition --disable-gpu-rasterization",
        "--use-angle=gl --use-gl=angle --ignore-gpu-blocklist --disable-direct-composition",
        "--use-angle=gl --use-gl=angle --ignore-gpu-blocklist --disable-direct-composition --disable-gpu-rasterization",
        /* build 118: CHRVAR8 without --renderer-process-limit=1 - Discord's renderer ran out of its 2 GB address
         * space (build 116), every page shared that one process; now each site gets its own 2 GB */
        "--disable-gpu --in-process-gpu --process-per-site --disable-site-isolation-trials "
        "--enable-low-end-device-mode --disable-back-forward-cache --disable-background-networking",
        "--disable-gpu --in-process-gpu --renderer-process-limit=1 --process-per-site --disable-site-isolation-trials "
        "--enable-low-end-device-mode --disable-back-forward-cache --disable-background-networking --js-flags=--single-threaded",
        "--disable-gpu --in-process-gpu --renderer-process-limit=1 --process-per-site --disable-site-isolation-trials "
        "--enable-low-end-device-mode --disable-back-forward-cache --disable-background-networking --js-flags=--single-threaded-gc",
        "--disable-gpu --in-process-gpu --renderer-process-limit=1 --process-per-site --disable-site-isolation-trials "
        "--enable-low-end-device-mode --disable-back-forward-cache --disable-background-networking --js-flags=\"--no-concurrent-recompilation --no-concurrent-sparkplug --no-concurrent-maglev --no-lazy-compile-dispatcher --no-parallel-compile-tasks-for-lazy --no-parallel-compile-tasks-for-eager-toplevel\"",
        "--disable-gpu --in-process-gpu --renderer-process-limit=1 --process-per-site --disable-site-isolation-trials "
        "--enable-low-end-device-mode --disable-back-forward-cache --disable-background-networking --js-flags=--no-script-streaming",
        "--disable-gpu --in-process-gpu --renderer-process-limit=1 --process-per-site --disable-site-isolation-trials "
        "--enable-low-end-device-mode --disable-back-forward-cache --disable-background-networking --js-flags=\"--no-script-streaming --single-threaded-gc\"",
        "--disable-gpu --in-process-gpu --renderer-process-limit=1 --process-per-site --disable-site-isolation-trials "
        "--enable-low-end-device-mode --disable-back-forward-cache --disable-background-networking --js-flags=\"--no-script-streaming --no-concurrent-cache-deserialization --no-concurrent-recompilation --no-concurrent-sparkplug --no-concurrent-maglev --no-concurrent-osr --no-concurrent-builtin-generation --no-lazy-compile-dispatcher --no-parallel-compile-tasks-for-lazy --no-parallel-compile-tasks-for-eager-toplevel\"",
        /* build 127: CHRVAR15 = 8's switches, for the Discord click diagnosis: NO network log (it wrote every response
         * body to C:\NETLOG.JSON) and no DevTools Debugger domain (it slows every script); profiler on for the run
         * (per-second timeline KEXTL_*.LOG next to chrome.exe); page probe with local times (C:\KEXBAD\PAGE.TXT) */
        "--disable-gpu --in-process-gpu --process-per-site --disable-site-isolation-trials "
        "--enable-low-end-device-mode --disable-back-forward-cache --disable-background-networking" };
    const char *exe = argc > 2 ? argv[2] : "C:\\WINDOWS\\DESKTOP\\CHROME-WIN\\CHROME.EXE";
    char cmd[2048]; int n = argc > 1 ? atoi(argv[1]) : 0, asked = n;
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    HKEY k = NULL; DWORD gld, prof_old = 0, t, sz = sizeof(prof_old), zero = 0; int had_prof = 0;
    char logn[32];
    /* build 127: CHRVAR8.BAT now runs the click diagnosis (15): same Chrome switches, logs still C:\CHRLOG8.TXT.
     * The network log / script check of 8 (builds 99-125) is finished - it wrote every response body to disk. */
    if (n == 8) n = 15;
    if (n < 1 || n > 15) {
        MessageBoxA(NULL, "Use CHRVAR1.BAT ... CHRVAR8.BAT (or: CHRVAR <1-8> [path of chrome.exe]).\n\n"
                    "1 = GPU (SoftGPU OpenGL)\n2 = GPU, pages drawn by the CPU\n3 = Chrome's own software GL (SwiftShader)\n4 = no GPU\n"
                    "5 = 2, profiler off\n6 = 1, profiler off\n7 = 5, frames drawn through GDI (GLPresent)\n8 = 4 in several processes (no --single-process)\n9 = 8, V8 single-threaded (test)\n10 = 8, V8 garbage collector single-threaded\n11 = 8, V8 compilers single-threaded\n12 = 8, no background script streaming",
                    "CHRVAR", MB_OK);
        return 1;
    }
    /* build 65: with --single-process, Chromium runs every "utility process" as a thread and lets only ONE of them
     * live at a time (content/utility/in_process_utility_thread.cc: a global lock held for the thread's whole life).
     * A long-lived one (audio service, video-capture service) keeps it; every later one - the "Windows Utilities"
     * service that shows Save As - waits forever (build-64 dump: 4 utility threads parked on that lock, the Save As
     * thread idle). These two documented feature switches keep those services in the browser process.
     * build 67: the component updater is the next holder (dump 200-203: 1 utility thread idle holding the lock from
     * the puffin-patch / 202 MB CRX unpack started at 13:35, 2 more parked in InProcessUtilityThread::Init, Save As
     * owner window disabled). --disable-component-update (documented) stops those downloads and their utilities.
     * build 68: next in the queue was the on-device AI model service (FATAL services.cc:373 WasPreSandboxInitCalled,
     * service-name on_device_model.mojom.OnDeviceModelService) - it can only run in its own sandboxed process.
     * The on-device AI / Gemini features are switched off, plus the documented enterprise policies below.
     * build 69: it still started, exactly 3 minutes after launch every run: PerformanceClassifier (optimization
     * guide) starts that service to benchmark the machine unless the class is given on the command line
     * (chrome.dll 131ab9e9: switch "optimization-guide-performance-class", values 1-9; 2 = very low). */
    sprintf(cmd, "\"%s\" %s--no-sandbox %s --no-first-run --enable-logging --v=0 "
                 "--disable-features=%sAudioServiceOutOfProcess,Glic,LogOnDeviceMetricsOnStartup,OnDeviceModelBackgroundDownload,"
                 "AIPromptAPI,AIWriterAPI,AIRewriterAPI,AISummarizationAPI,AIProofreaderAPI,AILanguageModel --enable-features=RunVideoCaptureServiceInBrowserProcess%s --disable-component-update --optimization-guide-performance-class=2 "
                 "--vmodule=*download*=20,base_file*=20,*select_file*=20,navigation_request=1,render_process_host_impl=2,web_contents_impl=1,page_discarding_helper=3,tab_lifecycle_unit=3,render_frame_host_manager=1 --log-file=C:\\CHRLOG%d.TXT --user-data-dir=C:\\CHRUD%s",
            exe, n >= 8 ? "" : "--single-process ", mode[n], n >= 8 ? "SitePerProcess,SpareRenderer,Prerender2,NoStatePrefetch,SpeculativeServiceWorkerWarmUp," : "", n >= 8 ? ",NetworkServiceInProcess2" : "", asked,
            n == 8 ? " --log-net-log=C:\\NETLOG.JSON --net-log-capture-mode=Everything --remote-debugging-port=9222" : n == 15 ? " --remote-debugging-port=9222" : "");
    sprintf(logn, "C:\\CHRLOG%d.TXT", asked);
    DeleteFileA(logn);
    if (n == 8) {                                       /* build 99: last run's network check */
        WIN32_FIND_DATAA fd; HANDLE fh; char p[MAX_PATH];
        DeleteFileA("C:\\NETLOG.JSON"); DeleteFileA("C:\\NETCHECK.TXT");
        if ((fh = FindFirstFileA("C:\\KEXBAD\\*", &fd)) != INVALID_HANDLE_VALUE) {
            do { if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) { sprintf(p, "C:\\KEXBAD\\%s", fd.cFileName); DeleteFileA(p); } }
            while (FindNextFileA(fh, &fd));
            FindClose(fh);
        }
    }
    gld = 0;
    {   /* metrics files of earlier (crashed) runs */
        WIN32_FIND_DATAA fd; HANDLE fh; char p[MAX_PATH];
        DeleteFileA("C:\\CHRUD\\BrowserMetrics-spare.pma");
        if ((fh = FindFirstFileA("C:\\CHRUD\\BrowserMetrics\\*.pma", &fd)) != INVALID_HANDLE_VALUE) {
            do { sprintf(p, "C:\\CHRUD\\BrowserMetrics\\%s", fd.cFileName); SetFileAttributesA(p, FILE_ATTRIBUTE_NORMAL); DeleteFileA(p); }
            while (FindNextFileA(fh, &fd));
            FindClose(fh);
        }
    }
    {   /* documented Chromium policies: 1 = do not download / use the on-device AI model; 1 = Gemini in Chrome off */
        HKEY pk; DWORD one = 1;
        if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Policies\\Chromium", &pk) == ERROR_SUCCESS) {
            RegSetValueExA(pk, "GenAILocalFoundationalModelSettings", 0, REG_DWORD, (BYTE *)&one, sizeof(one));
            RegSetValueExA(pk, "GeminiSettings", 0, REG_DWORD, (BYTE *)&one, sizeof(one));
            {   /* build 75: documented policy TabDiscardingExceptions - pages matching "*" are never thrown away. Chrome
                 * sees "critical" memory pressure on Windows 98 all the time and blanked pages every 5 s
                 * ("Discarding multiple pages", white page until reload). */
                HKEY tk;
                if (RegCreateKeyA(pk, "TabDiscardingExceptions", &tk) == ERROR_SUCCESS) {
                    RegSetValueExA(tk, "1", 0, REG_SZ, (const BYTE *)"*", 2);
                    RegCloseKey(tk);
                }
            }
            RegCloseKey(pk);
        }
    }
    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", &k) == ERROR_SUCCESS) {
        RegSetValueExA(k, "GLDirect", 0, REG_DWORD, (BYTE *)&gld, sizeof(gld));
        { DWORD gp = n == 7; RegSetValueExA(k, "GLPresent", 0, REG_DWORD, (BYTE *)&gp, sizeof(gp)); }
        if (n >= 5 && n <= 7) {
            had_prof = RegQueryValueExA(k, "Profile", NULL, &t, (BYTE *)&prof_old, &sz) == ERROR_SUCCESS && t == REG_DWORD;
            RegSetValueExA(k, "Profile", 0, REG_DWORD, (BYTE *)&zero, sizeof(zero));
        }
        if (n == 15) {                                  /* build 127: the timeline needs the profiler */
            DWORD one = 1;
            had_prof = RegQueryValueExA(k, "Profile", NULL, &t, (BYTE *)&prof_old, &sz) == ERROR_SUCCESS && t == REG_DWORD;
            if (!had_prof) prof_old = 0;
            had_prof = 1;
            RegSetValueExA(k, "Profile", 0, REG_DWORD, (BYTE *)&one, sizeof(one));
        }
    } else k = NULL;
    {   /* build 73: CHROME.EXE processes left over from a frozen run keep C:\CHRUD and C:\CHRLOG<n>.TXT open
         * (Windows 98 then says the files are "write-protected" / in use) - end them first */
        HANDLE sn = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); PROCESSENTRY32 pe; int killed = 0;
        if (sn != INVALID_HANDLE_VALUE) {
            pe.dwSize = sizeof(pe);
            if (Process32First(sn, &pe)) do {
                const char *b = pe.szExeFile, *q;
                for (q = pe.szExeFile; *q; q++) if (*q == '\\') b = q + 1;
                if (!lstrcmpiA(b, "CHROME.EXE") && pe.th32ProcessID != GetCurrentProcessId()) {
                    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (h) { if (TerminateProcess(h, 1)) killed++; CloseHandle(h); }
                }
            } while (Process32Next(sn, &pe));
            CloseHandle(sn);
        }
        if (killed) Sleep(1500);
        SetFileAttributesA(logn, FILE_ATTRIBUTE_NORMAL); DeleteFileA(logn);
    }
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) g_chrome_pid = pi.dwProcessId;
    else {
        char m[2300]; sprintf(m, "Could not start Chrome (error %lu):\n%s", GetLastError(), cmd);
        MessageBoxA(NULL, m, "CHRVAR", MB_OK); return 2;
    }
    CloseHandle(pi.hThread);
    {   HANDLE ct = NULL;                               /* build 100: DevTools listener for CHRVAR8 */
        g_mode = n;
        if (n == 15) {                                  /* build 127: old timelines away, so every line is this run's */
            char dir[MAX_PATH], pat[MAX_PATH], *sl; WIN32_FIND_DATAA fd; HANDLE fh;
            lstrcpynA(dir, exe, MAX_PATH); if ((sl = strrchr(dir, '\\'))) sl[1] = 0;
            sprintf(pat, "%sKEXTL_*.LOG", dir);
            if ((fh = FindFirstFileA(pat, &fd)) != INVALID_HANDLE_VALUE) {
                do { char f2[MAX_PATH]; sprintf(f2, "%s%s", dir, fd.cFileName); DeleteFileA(f2); } while (FindNextFileA(fh, &fd));
                FindClose(fh);
            }
        }
        if (n == 8 || n == 15) {
            CreateDirectoryA("C:\\KEXBAD", NULL);
            g_cdplog = fopen("C:\\KEXBAD\\CDP.TXT", "w");
            g_page = fopen("C:\\KEXBAD\\PAGE.TXT", "w");
            DeleteFileA("C:\\KEXBAD\\UITREE.TXT"); DeleteFileA("C:\\KEXBAD\\TOOLBAR.TXT"); { int q; char wp[40]; for (q = 0; q < 8; q++) { sprintf(wp, "C:\\KEXBAD\\WINTOP%d.BMP", q); DeleteFileA(wp); } }
            ct = CreateThread(NULL, 0, cdp_thread, NULL, 0, NULL);
        }
        if (n == 8 || n == 15) {
            WaitForSingleObject(pi.hProcess, INFINITE);
            InterlockedExchange(&g_cdp_stop, 1);
            if (g_cdp != INVALID_SOCKET) closesocket(g_cdp);
            if (ct) { WaitForSingleObject(ct, 10000); CloseHandle(ct); }
            if (g_cdplog) fflush(g_cdplog);
            if (g_page) { fclose(g_page); g_page = NULL; }
        }
    }
    if (((n >= 5 && n <= 7) || n == 15) && k) {       /* put the profiler setting back once Chrome has ended */
        WaitForSingleObject(pi.hProcess, INFINITE);
        if (had_prof) RegSetValueExA(k, "Profile", 0, REG_DWORD, (BYTE *)&prof_old, sizeof(prof_old));
        if (n == 7) { DWORD gp = 0; RegSetValueExA(k, "GLPresent", 0, REG_DWORD, (BYTE *)&gp, sizeof(gp)); }
    }
    if (n == 8) {                                       /* build 99: check the script bodies once Chrome has closed */
        WaitForSingleObject(pi.hProcess, INFINITE);
        Sleep(2000);                                    /* the network log is finished by the browser at exit */
        netcheck("C:\\NETLOG.JSON", logn);
    }
    if (k) RegCloseKey(k);
    CloseHandle(pi.hProcess);
    return 0;
}
