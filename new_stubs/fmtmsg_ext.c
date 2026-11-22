/* fmtmsg_ext.c - FormatMessageW with NT's insert formatting (build 125).
 *
 * Measured in the test VM (FMSG.EXE, an NT program through KernelEx/kexnt on Windows 98):
 *   "n=%1!u!"           -> "n=42"      but GetLastError 87 after a SUCCESSFUL call
 *   "n=%1!I64u! KB"     -> "n=I64u KB" (64-bit printf specifier not understood) and error 87
 * Visual Studio 2010's SetupUi.dll formats sizes with "%1!I64u!" through FormatMessageW(FROM_STRING |
 * ALLOCATE_BUFFER), calls SetLastError(0) first and treats any last error afterwards as E_OUTOFMEMORY -> the
 * Visual C++ 2010 setup ended silently when Install was pressed (DBG.EXE: CAtlException 8007000E, format "I64u").
 * Here FormatMessageW formats the inserts itself, as NT does: %1..%99 with optional !printf-spec! (s S c C d i u
 * x X o p with flags, width, precision, '*', h l ll I64 I32 sizes; default !s!), %0 %% %n %r %t %b %. %! %space,
 * arguments from a va_list or FORMAT_MESSAGE_ARGUMENT_ARRAY (4-byte slots, a 64-bit value takes two), and
 * FORMAT_MESSAGE_MAX_WIDTH_MASK (line breaks of the text become spaces). Messages from a module or the system
 * are fetched with IGNORE_INSERTS from the previous implementation and formatted here. The last error is left
 * alone on success. IGNORE_INSERTS calls go to the previous implementation unchanged. */
#include "kexnt_common.h"

FARPROC kex_prev_impl(const char *dll, const char *name);
typedef DWORD (WINAPI *T_FMW)(DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list *);

typedef struct { WCHAR *p; DWORD n, cap; int oom; } FBUF;
static void put(FBUF *o, WCHAR c)
{
    if (o->n + 2 > o->cap) {
        DWORD nc = o->cap ? o->cap * 2 : 256; WCHAR *np = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, nc * sizeof(WCHAR));
        if (!np) { o->oom = 1; return; }
        if (o->p) { CopyMemory(np, o->p, o->n * sizeof(WCHAR)); HeapFree(GetProcessHeap(), 0, o->p); }
        o->p = np; o->cap = nc;
    }
    o->p[o->n++] = c;
}

/* one printf conversion of a 64-bit value / string into o */
static void conv(FBUF *o, const WCHAR *spec, int slen, const DWORD *args, int nargs, int *ix)
{
    int left = 0, plus = 0, space = 0, alt = 0, zero = 0, width = -1, prec = -1, size = 0, i = 0; WCHAR t;
    WCHAR tmp[80]; int tn = 0; ULONGLONG v = 0; int neg = 0;
    #define ARG() (*ix < nargs ? args[(*ix)++] : 0)
    for (; i < slen; i++) {
        if (spec[i] == '-') left = 1; else if (spec[i] == '+') plus = 1; else if (spec[i] == ' ') space = 1;
        else if (spec[i] == '#') alt = 1; else if (spec[i] == '0') zero = 1; else break;
    }
    if (i < slen && spec[i] == '*') { width = (int)ARG(); i++; } else { while (i < slen && spec[i] >= '0' && spec[i] <= '9') width = (width < 0 ? 0 : width * 10) + (spec[i++] - '0'); }
    if (i < slen && spec[i] == '.') { i++; prec = 0; if (i < slen && spec[i] == '*') { prec = (int)ARG(); i++; } else while (i < slen && spec[i] >= '0' && spec[i] <= '9') prec = prec * 10 + (spec[i++] - '0'); }
    for (;;) {
        if (i + 2 < slen && spec[i] == 'I' && spec[i + 1] == '6' && spec[i + 2] == '4') { size = 64; i += 3; }
        else if (i + 2 < slen && spec[i] == 'I' && spec[i + 1] == '3' && spec[i + 2] == '2') { i += 3; }
        else if (i < slen && spec[i] == 'I') { i++; }
        else if (i + 1 < slen && spec[i] == 'l' && spec[i + 1] == 'l') { size = 64; i += 2; }
        else if (i < slen && (spec[i] == 'l' || spec[i] == 'h' || spec[i] == 'w')) { if (spec[i] == 'h') size = 16; i++; }
        else break;
    }
    t = i < slen ? spec[i] : 's';
    if (t == 's' || t == 'S') {
        const void *s = (const void *)(ULONG_PTR)ARG(); int wide = (t == 's') ^ (size == 16), len = 0, k;
        WCHAR *ws = NULL; char *as = NULL;
        if (!s) { s = L"(null)"; wide = 1; }
        if (wide) { ws = (WCHAR *)s; if (IsBadStringPtrW(ws, 0x7FFF)) ws = L"(bad)"; while (ws[len] && (prec < 0 || len < prec)) len++; }
        else { as = (char *)s; if (IsBadStringPtrA(as, 0x7FFF)) as = "(bad)"; while (as[len] && (prec < 0 || len < prec)) len++; }
        if (!left) for (k = len; k < width; k++) put(o, ' ');
        if (wide) for (k = 0; k < len; k++) put(o, ws[k]);
        else { WCHAR c; for (k = 0; k < len; k++) { MultiByteToWideChar(CP_ACP, 0, as + k, IsDBCSLeadByte((BYTE)as[k]) && as[k + 1] ? 2 : 1, &c, 1);
                                                   if (IsDBCSLeadByte((BYTE)as[k]) && as[k + 1]) k++; put(o, c); } }
        if (left) for (k = len; k < width; k++) put(o, ' ');
        return;
    }
    if (t == 'c' || t == 'C') {
        DWORD c = ARG(); WCHAR w = (WCHAR)c; int k;
        if ((t == 'c') ^ (size == 16)) w = (WCHAR)c; else { char a = (char)c; MultiByteToWideChar(CP_ACP, 0, &a, 1, &w, 1); }
        if (!left) for (k = 1; k < width; k++) put(o, ' ');
        put(o, w);
        if (left) for (k = 1; k < width; k++) put(o, ' ');
        return;
    }
    if (size == 64) { DWORD lo = ARG(), hi = ARG(); v = ((ULONGLONG)hi << 32) | lo; }
    else { DWORD d = ARG(); if (size == 16) d &= 0xFFFF; v = d;
           if ((t == 'd' || t == 'i') && (size == 16 ? (d & 0x8000) != 0 : (LONG)d < 0)) v = (ULONGLONG)(LONGLONG)(size == 16 ? (LONG)(SHORT)d : (LONG)d); }
    if (t == 'd' || t == 'i') { if ((LONGLONG)v < 0) { neg = 1; v = (ULONGLONG)(-(LONGLONG)v); } }
    {   int base = (t == 'x' || t == 'X' || t == 'p') ? 16 : t == 'o' ? 8 : 10, k, digits; const char *dg = t == 'X' ? "0123456789ABCDEF" : "0123456789abcdef";
        WCHAR pre[4]; int pn = 0;
        if (t == 'p') { prec = size == 64 ? 16 : 8; }
        if (!v && prec == 0) tn = 0; else do { tmp[tn++] = (WCHAR)dg[v % base]; v /= base; } while (v && tn < 70);
        digits = tn;
        if (neg) pre[pn++] = '-'; else if (plus && (t == 'd' || t == 'i')) pre[pn++] = '+'; else if (space && (t == 'd' || t == 'i')) pre[pn++] = ' ';
        if (alt && base == 16 && digits) { pre[pn++] = '0'; pre[pn++] = (WCHAR)(t == 'X' ? 'X' : 'x'); }
        if (alt && base == 8) { pre[pn++] = '0'; }
        {   int zeros = prec > digits ? prec - digits : 0, total = pn + zeros + digits;
            if (zero && !left && prec < 0 && width > total) { zeros += width - total; total = width; }
            if (!left) for (k = total; k < width; k++) put(o, ' ');
            for (k = 0; k < pn; k++) put(o, pre[k]);
            for (k = 0; k < zeros; k++) put(o, '0');
            while (tn) put(o, tmp[--tn]);
            if (left) for (k = total; k < width; k++) put(o, ' ');
        }
    }
    #undef ARG
}

static BOOL format(const WCHAR *tmpl, DWORD flags, const DWORD *args, FBUF *o)
{
    const WCHAR *p = tmpl; int maxw = (flags & 0xFF) == 0xFF;
    while (*p && !o->oom) {
        if (*p == '%') {
            p++;
            if (*p >= '1' && *p <= '9') {
                int n = *p++ - '0', ix; const WCHAR *spec = L"s"; int slen = 1;
                if (*p >= '0' && *p <= '9') n = n * 10 + (*p++ - '0');
                if (*p == '!') { const WCHAR *e = p + 1; while (*e && *e != '!') e++; if (*e) { spec = p + 1; slen = (int)(e - p - 1); p = e + 1; } }
                if (!args) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
                ix = n - 1;
                conv(o, spec, slen, args, 99 + 2, &ix);
            } else if (*p == '0') break;
            else if (*p == 'n') { put(o, '\r'); put(o, '\n'); p++; }
            else if (*p == 'r') { put(o, '\r'); p++; }
            else if (*p == 't') { put(o, '\t'); p++; }
            else if (*p == 'b') { put(o, ' '); p++; }
            else if (*p) put(o, *p++);           /* %% %. %! %space and anything else: the character itself */
        } else if (maxw && (*p == '\r' || *p == '\n')) {
            if (*p == '\r' && p[1] == '\n') p++;
            put(o, ' '); p++;
        } else put(o, *p++);
    }
    return !o->oom;
}

DWORD KEXAPI kex_FormatMessageW(DWORD flags, LPCVOID src, DWORD msgid, DWORD lang, LPWSTR buf, DWORD size, va_list *args)
{
    static T_FMW prev;
    WCHAR *tmpl = NULL, *fetched = NULL; FBUF o = { 0 }; const DWORD *slots = NULL; DWORD le = GetLastError(), n;
    if (!prev) prev = (T_FMW)(void *)kex_prev_impl("KERNEL32.DLL", "FormatMessageW");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    if (flags & FORMAT_MESSAGE_IGNORE_INSERTS) return prev(flags, src, msgid, lang, buf, size, args);
    if (flags & FORMAT_MESSAGE_FROM_STRING) {
        tmpl = (WCHAR *)src;
        if (!tmpl || IsBadStringPtrW(tmpl, 0x7FFF)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    } else {
        DWORD f2 = (flags & ~(FORMAT_MESSAGE_ARGUMENT_ARRAY | 0xFF)) | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER;
        if (!prev(f2, src, msgid, lang, (LPWSTR)&fetched, 0, NULL) || !fetched) return 0;
        tmpl = fetched;
    }
    if (args) slots = (flags & FORMAT_MESSAGE_ARGUMENT_ARRAY) ? (const DWORD *)args : (const DWORD *)*args;
    if (!format(tmpl, flags, slots, &o)) {
        if (fetched) LocalFree(fetched);
        if (o.p) HeapFree(GetProcessHeap(), 0, o.p);
        if (o.oom) SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    if (fetched) LocalFree(fetched);
    n = o.n;
    if (flags & FORMAT_MESSAGE_ALLOCATE_BUFFER) {
        WCHAR *r = (WCHAR *)LocalAlloc(LMEM_FIXED, ((n + 1 > size ? n + 1 : size) ) * sizeof(WCHAR));
        if (!buf || IsBadWritePtr(buf, sizeof(WCHAR *))) { if (r) LocalFree(r); if (o.p) HeapFree(GetProcessHeap(), 0, o.p); SetLastError(ERROR_INVALID_PARAMETER); return 0; }
        if (!r) { if (o.p) HeapFree(GetProcessHeap(), 0, o.p); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
        if (n) CopyMemory(r, o.p, n * sizeof(WCHAR));
        r[n] = 0; *(WCHAR **)buf = r;
    } else {
        if (!buf || n + 1 > size) { if (o.p) HeapFree(GetProcessHeap(), 0, o.p); SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
        if (n) CopyMemory(buf, o.p, n * sizeof(WCHAR));
        buf[n] = 0;
    }
    if (o.p) HeapFree(GetProcessHeap(), 0, o.p);
    SetLastError(le);
    return n;
}
