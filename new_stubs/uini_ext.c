/*
 * uini_ext.c - Unicode (UTF-16LE) INI files for the W profile functions, as on NT (KernelEx-NG build 126).
 *
 * Measured (Mypal 29 / Firefox 52 setups = Unicode NSIS 3, MUI1 + InstallOptions): NSIS extracts its page
 * description ioSpecial.ini as UTF-16LE with a byte-order mark and reads/writes it with GetPrivateProfileStringW,
 * GetPrivateProfileIntW and WritePrivateProfileStringW. NT keeps such a file in UTF-16. Windows 98's profile code
 * (reached through W->A wrappers) cannot read the UTF-16 part and APPENDS new ANSI sections to the end: the file
 * in the test VM held "[Settings] NumFields=3 / [Field 1] Type=bitmap ..." in UTF-16 followed by ANSI
 * "[Field 1] Text=...modern-wizard.bmp". InstallOptions then found fields without a type -> the Welcome and the
 * Finish pages were skipped (the "installer complete" window with the Finish button never appeared).
 *
 * Here: when the file exists and starts with FF FE, kexnt reads and writes it itself, in UTF-16, with NT's rules
 * (sections and keys compared without case, values with leading/trailing blanks removed, a value in matching
 * quotes loses them, NULL section -> list of sections, NULL key -> list of keys, NULL value -> key deleted, NULL
 * key on write -> section deleted). Every other file goes to the previous implementation unchanged.
 */
#include "kexnt_common.h"

FARPROC kex_prev_impl(const char *dll, const char *name);
DWORD KEXAPI kex_GetPrivateProfileStringW(LPCWSTR app, LPCWSTR key, LPCWSTR def, LPWSTR buf, DWORD size, LPCWSTR file);

static CRITICAL_SECTION g_cs; static volatile LONG g_cs_init;
static void lock(void)
{
    if (g_cs_init != 2) {
        if (InterlockedCompareExchange(&g_cs_init, 1, 0) == 0) { InitializeCriticalSection(&g_cs); InterlockedExchange(&g_cs_init, 2); }
        else while (g_cs_init != 2) Sleep(0);
    }
    EnterCriticalSection(&g_cs);
}
static void unlock(void) { LeaveCriticalSection(&g_cs); }

/* profile file name -> full ANSI path (a name without a path lives in the Windows folder, as the profile API does) */
static BOOL ini_path(LPCWSTR file, char *out)
{
    char a[MAX_PATH]; const WCHAR *p; BOOL has_dir = FALSE;
    if (!file || IsBadStringPtrW(file, MAX_PATH)) return FALSE;
    for (p = file; *p; p++) if (*p == L'\\' || *p == L'/' || *p == L':') has_dir = TRUE;
    if (!WideCharToMultiByte(CP_ACP, 0, file, -1, a, MAX_PATH, NULL, NULL)) return FALSE;
    if (has_dir) { lstrcpynA(out, a, MAX_PATH); return TRUE; }
    if (!GetWindowsDirectoryA(out, MAX_PATH - 16) || lstrlenA(out) + lstrlenA(a) + 2 > MAX_PATH) return FALSE;
    if (out[lstrlenA(out) - 1] != '\\') lstrcatA(out, "\\");
    lstrcatA(out, a);
    return TRUE;
}
/* whole file as UTF-16 without the mark; NULL if it is not a UTF-16LE file with FF FE */
static WCHAR *load(const char *path, DWORD *chars)
{
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DWORD size, got = 0; BYTE *b; WCHAR *w = NULL;
    if (f == INVALID_HANDLE_VALUE) return NULL;
    size = GetFileSize(f, NULL);
    if (size < 2 || size == 0xFFFFFFFF || size > 16 * 1024 * 1024) { CloseHandle(f); return NULL; }
    b = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size + 4);
    if (b && ReadFile(f, b, size, &got, NULL) && got == size && b[0] == 0xFF && b[1] == 0xFE) {
        w = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, size + 2);
        if (w) { memcpy(w, b + 2, size - 2); *chars = (size - 2) / 2; w[*chars] = 0; }
    }
    if (b) HeapFree(GetProcessHeap(), 0, b);
    CloseHandle(f);
    return w;
}
static BOOL is_uini(LPCWSTR file, char *path)
{
    BYTE m[2]; DWORD got = 0; HANDLE f;
    if (!ini_path(file, path)) return FALSE;
    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    ReadFile(f, m, 2, &got, NULL); CloseHandle(f);
    return got == 2 && m[0] == 0xFF && m[1] == 0xFE;
}

static WCHAR up(WCHAR c) { return (c >= L'a' && c <= L'z') ? (WCHAR)(c - 32) : c; }
static BOOL same(const WCHAR *a, int na, const WCHAR *b)          /* a[0..na) vs b, no case */
{
    int i;
    for (i = 0; i < na; i++) if (!b[i] || up(a[i]) != up(b[i])) return FALSE;
    return b[na] == 0;
}
static BOOL blank(WCHAR c) { return c == L' ' || c == L'\t'; }

/* one parsed line */
typedef struct { const WCHAR *s; int n;                    /* the whole line (no CR/LF) */
                 int kind;                                 /* 0 other, 1 section, 2 key */
                 const WCHAR *name; int nn; const WCHAR *val; int nv; } LINE;
static const WCHAR *next_line(const WCHAR *p, const WCHAR *end, LINE *l)
{
    const WCHAR *e = p, *a, *b;
    while (e < end && *e != L'\r' && *e != L'\n') e++;
    l->s = p; l->n = (int)(e - p); l->kind = 0; l->name = l->val = NULL; l->nn = l->nv = 0;
    a = p; while (a < e && blank(*a)) a++;
    if (a < e && *a == L'[') {
        b = a + 1; while (b < e && *b != L']') b++;
        if (b < e) { l->kind = 1; l->name = a + 1; l->nn = (int)(b - a - 1); }
    } else if (a < e && *a != L';') {
        const WCHAR *eq = a; while (eq < e && *eq != L'=') eq++;
        if (eq < e) {
            const WCHAR *ke = eq; while (ke > a && blank(ke[-1])) ke--;
            l->kind = 2; l->name = a; l->nn = (int)(ke - a);
            a = eq + 1; while (a < e && blank(*a)) a++;
            b = e; while (b > a && blank(b[-1])) b--;
            if (b - a >= 2 && ((*a == L'"' && b[-1] == L'"') || (*a == L'\'' && b[-1] == L'\''))) { a++; b--; }
            l->val = a; l->nv = (int)(b - a);
        }
    }
    if (e < end && *e == L'\r') e++;
    if (e < end && *e == L'\n') e++;
    return e;
}

/* copy a list of names (double-zero terminated) with NT's truncation rule */
static DWORD put_list(LPWSTR buf, DWORD size, const WCHAR *const *names, const int *lens, int count)
{
    DWORD pos = 0; int i, k;
    if (size < 2) { if (size) buf[0] = 0; return 0; }
    for (i = 0; i < count; i++) {
        for (k = 0; k < lens[i]; k++) {
            if (pos >= size - 2) { buf[size - 2] = 0; buf[size - 1] = 0; return size - 2; }
            buf[pos++] = names[i][k];
        }
        if (pos >= size - 2) { buf[size - 2] = 0; buf[size - 1] = 0; return size - 2; }
        buf[pos++] = 0;
    }
    buf[pos] = 0;
    if (!count) { buf[0] = buf[1] = 0; return 0; }
    return pos;
}

static DWORD uini_get(const WCHAR *txt, DWORD n, LPCWSTR app, LPCWSTR key, LPCWSTR def, LPWSTR buf, DWORD size)
{
    const WCHAR *p = txt, *end = txt + n; LINE l; BOOL in = FALSE; DWORD r, i;
    static const WCHAR *names[1024]; static int lens[1024]; int cnt = 0;   /* used under lock */
    while (p < end) {
        p = next_line(p, end, &l);
        if (l.kind == 1) { in = app && same(l.name, l.nn, app);
                           if (!app && cnt < 1024) { names[cnt] = l.name; lens[cnt] = l.nn; cnt++; } continue; }
        if (!app || !in || l.kind != 2) continue;
        if (!key) { if (cnt < 1024) { names[cnt] = l.name; lens[cnt] = l.nn; cnt++; } continue; }
        if (same(l.name, l.nn, key)) {
            r = (DWORD)l.nv < size - 1 ? (DWORD)l.nv : size - 1;
            for (i = 0; i < r; i++) buf[i] = l.val[i];
            buf[r] = 0;
            return r;
        }
    }
    if (!app || !key) return put_list(buf, size, names, lens, cnt);
    r = 0;
    if (def && !IsBadStringPtrW(def, 32767)) { r = (DWORD)lstrlenW(def); while (r && def[r - 1] == L' ') r--; }
    if (r > size - 1) r = size - 1;
    for (i = 0; i < r; i++) buf[i] = def[i];
    buf[r] = 0;
    return r;
}

/* rewrite the file with one key set / deleted, or one section deleted */
static BOOL uini_put(const char *path, const WCHAR *txt, DWORD n, LPCWSTR app, LPCWSTR key, LPCWSTR val)
{
    const WCHAR *p = txt, *end = txt + n; LINE l; BOOL in = FALSE, seen_sec = FALSE, done = FALSE;
    DWORD cap = n + (key ? lstrlenW(key) : 0) + (val ? lstrlenW(val) : 0) + lstrlenW(app) + 64, pos = 0, w;
    WCHAR *o = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (cap + 2) * sizeof(WCHAR)); HANDLE f; BOOL ok;
#define PUT(s, k) do { int _i; for (_i = 0; _i < (int)(k); _i++) o[pos++] = (s)[_i]; } while (0)
#define PUTZ(s) PUT(s, lstrlenW(s))
    if (!o) return FALSE;
    o[pos++] = 0xFEFF;
    while (p < end) {
        const WCHAR *ls = p;
        p = next_line(p, end, &l);
        if (l.kind == 1) {
            if (in && !done && key && val) { PUTZ(key); o[pos++] = L'='; PUTZ(val); PUT(L"\r\n", 2); done = TRUE; }  /* add at section end */
            in = same(l.name, l.nn, app); if (in) seen_sec = TRUE;
        }
        if (in && !key) continue;                                       /* deleting the whole section */
        if (in && l.kind == 2 && same(l.name, l.nn, key)) {
            if (!done && val) { PUTZ(key); o[pos++] = L'='; PUTZ(val); PUT(L"\r\n", 2); }
            done = TRUE; continue;
        }
        PUT(ls, p - ls);
        if (p >= end && (p == ls || (p[-1] != L'\n'))) PUT(L"\r\n", 2);   /* last line without a line end */
    }
    if (key && val && !done) {
        if (!seen_sec) { o[pos++] = L'['; PUTZ(app); o[pos++] = L']'; PUT(L"\r\n", 2); }
        PUTZ(key); o[pos++] = L'='; PUTZ(val); PUT(L"\r\n", 2);
    }
#undef PUT
#undef PUTZ
    f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { HeapFree(GetProcessHeap(), 0, o); return FALSE; }
    ok = WriteFile(f, o, pos * sizeof(WCHAR), &w, NULL) && w == pos * sizeof(WCHAR);
    CloseHandle(f);
    HeapFree(GetProcessHeap(), 0, o);
    return ok;
}

/* ---------------------------------------------------------------- the API */
DWORD KEXAPI kex_uini_GetPrivateProfileStringW(LPCWSTR app, LPCWSTR key, LPCWSTR def, LPWSTR buf, DWORD size, LPCWSTR file);
DWORD KEXAPI kex_uini_GetPrivateProfileStringW(LPCWSTR app, LPCWSTR key, LPCWSTR def, LPWSTR buf, DWORD size, LPCWSTR file)
{
    char path[MAX_PATH]; WCHAR *t; DWORD n, r;
    if (!buf || !size || !file || !is_uini(file, path)) return (DWORD)-2;          /* not ours */
    lock();
    t = load(path, &n);
    r = t ? uini_get(t, n, app, key, def, buf, size) : (DWORD)-2;
    unlock();
    if (t) HeapFree(GetProcessHeap(), 0, t);
    if (r != (DWORD)-2) SetLastError(ERROR_SUCCESS);
    return r;
}

/* build 132: GetPrivateProfileSectionW. Measured (.NET Framework 3.5 SP1 setup, probes/sdbread.c on its UTF-16 setup.sdb):
 * GetPrivateProfileStringW read it, GetPrivateProfileSectionW returned 0 -> "LoadSetupDatabase(): The .sdb file is
 * either missing, corrupt, or the signature portion is missing". NT returns every line of the section as stored, one
 * per string (blanks around the line removed; "key=value" with blanks around the '=' removed, the value as written,
 * quotes kept); comment lines (';') and empty lines are left out; double zero at the end; when the buffer is too
 * small the result is cut and size - 2 returned. */
typedef DWORD (WINAPI *T_GPPSW)(LPCWSTR, LPWSTR, DWORD, LPCWSTR);
DWORD KEXAPI kex_GetPrivateProfileSectionW(LPCWSTR app, LPWSTR buf, DWORD size, LPCWSTR file)
{
    static T_GPPSW prev; char path[MAX_PATH]; WCHAR *t; DWORD n, pos = 0;
    if (app && buf && size && file && is_uini(file, path)) {
        lock();
        t = load(path, &n);
        if (t) {
            const WCHAR *p = t, *end = t + n; LINE l; BOOL in = FALSE, cut = FALSE;
            while (p < end && !cut) {
                const WCHAR *a, *b, *eq; int k;
                p = next_line(p, end, &l);
                if (l.kind == 1) { if (in) break; in = same(l.name, l.nn, app); continue; }
                if (!in) continue;
                a = l.s; b = l.s + l.n; while (a < b && blank(*a)) a++; while (b > a && blank(b[-1])) b--;
                if (a == b || *a == L';') continue;
#define OUTC(c) do { if (pos >= size - 2) { cut = TRUE; break; } buf[pos++] = (c); } while (0)
                if (l.kind == 2) {
                    for (k = 0; k < l.nn && !cut; k++) OUTC(l.name[k]);
                    if (!cut) OUTC(L'=');
                    eq = l.name + l.nn; while (eq < b && *eq != L'=') eq++;
                    if (eq < b) eq++;
                    while (eq < b && blank(*eq)) eq++;
                    for (; eq < b && !cut; eq++) OUTC(*eq);
                } else for (; a < b && !cut; a++) OUTC(*a);
                if (!cut) OUTC(0);
#undef OUTC
            }
            if (cut) { if (size >= 2) { buf[size - 2] = 0; buf[size - 1] = 0; } pos = size >= 2 ? size - 2 : 0; }
            else { buf[pos] = 0; if (pos == 0 && size > 1) buf[1] = 0; }
            HeapFree(GetProcessHeap(), 0, t);
            unlock();
            SetLastError(ERROR_SUCCESS);
            return pos;
        }
        unlock();
    }
    if (!prev) prev = (T_GPPSW)(void *)kex_prev_impl("KERNEL32.DLL", "GetPrivateProfileSectionW");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); if (buf && size) buf[0] = 0; return 0; }
    return prev(app, buf, size, file);
}

typedef UINT (WINAPI *T_GPPIW)(LPCWSTR, LPCWSTR, INT, LPCWSTR);
UINT KEXAPI kex_GetPrivateProfileIntW(LPCWSTR app, LPCWSTR key, INT def, LPCWSTR file)
{
    static T_GPPIW prev; char path[MAX_PATH];
    if (app && key && file && is_uini(file, path)) {
        WCHAR v[64]; const WCHAR *p = v; DWORD r = kex_uini_GetPrivateProfileStringW(app, key, L"", v, 64, file); int neg = 0, any = 0; UINT x = 0;
        if (r == (DWORD)-2 || !v[0]) return (UINT)def;
        while (blank(*p)) p++;
        if (*p == L'-') { neg = 1; p++; } else if (*p == L'+') p++;
        while (*p >= L'0' && *p <= L'9') { x = x * 10 + (UINT)(*p - L'0'); p++; any = 1; }
        if (!any) return 0;                                             /* NT: a value that is not a number -> 0 */
        return neg ? (UINT)(-(INT)x) : x;
    }
    if (!prev) prev = (T_GPPIW)(void *)kex_prev_impl("KERNEL32.DLL", "GetPrivateProfileIntW");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return (UINT)def; }
    return prev(app, key, def, file);
}

typedef BOOL (WINAPI *T_WPPSW)(LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
BOOL KEXAPI kex_WritePrivateProfileStringW(LPCWSTR app, LPCWSTR key, LPCWSTR val, LPCWSTR file)
{
    static T_WPPSW prev; char path[MAX_PATH];
    if (app && file && !IsBadStringPtrW(app, 32767) && (!key || !IsBadStringPtrW(key, 32767)) && (!val || !IsBadStringPtrW(val, 32767)) &&
        is_uini(file, path)) {
        WCHAR *t; DWORD n; BOOL ok = FALSE;
        lock();
        if ((t = load(path, &n))) { ok = uini_put(path, t, n, app, key, val); HeapFree(GetProcessHeap(), 0, t); }
        unlock();
        if (!ok) SetLastError(ERROR_ACCESS_DENIED);
        return ok;
    }
    if (!prev) prev = (T_WPPSW)(void *)kex_prev_impl("KERNEL32.DLL", "WritePrivateProfileStringW");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return prev(app, key, val, file);
}
