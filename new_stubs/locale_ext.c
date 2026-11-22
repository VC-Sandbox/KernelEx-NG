/*
 * locale_ext.c - KernelEx-NG Phase 3b: Vista+ "locale name" NLS APIs for Windows 98 SE.
 *
 * Win98 identifies locales by LCID only and every *W NLS export of its kernel32 is a stub.
 * Strategy:
 *   - name <-> LCID through the static table in locale_names.h ([MS-LCID] names)
 *   - CompareStringW / LCMapStringW: taken from KernelEx's own api libraries (kexbases has the
 *     Wine Unicode collation/case tables) by walking their get_api_table(); when KernelEx is
 *     not present (kextest standalone) we fall back to the ANSI function in the locale's code page
 *   - GetLocaleInfo / Get*Format: the ANSI Win98 function in the locale's ANSI code page, result
 *     converted to UTF-16 (KernelEx's GetNumberFormatW etc. reject lpFormat == NULL, so not used)
 *   - NT6 LCTYPEs Win98 does not know (SNAME, SPARENT, SNAN, IREADINGLAYOUT, SSHORTTIME, ...)
 *     are computed here.
 * Known limit of the ANSI fallback: characters outside the locale's ANSI code page are lost.
 */
#include "kexnt_common.h"
#include "locale_names.h"

#ifndef LOCALE_NAME_MAX_LENGTH
#define LOCALE_NAME_MAX_LENGTH 85
#endif
#define KEX_LOCALE_INVARIANT 0x007F
#define NLOC (sizeof(kex_locnames) / sizeof(kex_locnames[0]))
#define NNEU (sizeof(kex_neutral_extra) / sizeof(kex_neutral_extra[0]))

/* ============================== small helpers ============================== */
static void *xalloc(SIZE_T n) { return HeapAlloc(GetProcessHeap(), 0, n ? n : 1); }
static void  xfree(void *p)   { if (p) HeapFree(GetProcessHeap(), 0, p); }

static int wlen(LPCWSTR s) { int n = 0; while (s[n]) n++; return n; }

static WCHAR lowerw(WCHAR c) { return (c >= 'A' && c <= 'Z') ? (WCHAR)(c + 32) : c; }

/* Case-insensitive compare of a UTF-16 name with an ASCII table name (n chars, or whole if n<0). */
static BOOL name_eq(LPCWSTR w, const char *a, int n)
{
    int i;
    for (i = 0; n < 0 || i < n; i++) {
        WCHAR c = (n >= 0 && a[i] == 0) ? 0 : (WCHAR)(unsigned char)a[i];
        if (lowerw(w[i]) != lowerw(c)) return FALSE;
        if (!c) return TRUE;
    }
    return w[i] == 0;
}

static int prefix_len(const char *name) { int n = 0; while (name[n] && name[n] != '-') n++; return n; }

static LCID default_lcid(LCID lcid)
{
    if (lcid == LOCALE_USER_DEFAULT || lcid == 0) return GetUserDefaultLCID();
    if (lcid == LOCALE_SYSTEM_DEFAULT) return GetSystemDefaultLCID();
    return lcid;
}

static const kex_locname *find_lcid(WORD langid)
{
    unsigned i;
    for (i = 0; i < NLOC; i++) if (kex_locnames[i].lcid == langid) return &kex_locnames[i];
    return NULL;
}

/* LCID -> name. Neutral LCIDs give "de"; 0x7F gives "". Returns chars written (no NUL) or -1. */
static int lcid_name(LCID lcid, char *out, BOOL allow_neutral)
{
    WORD lang = LANGIDFROMLCID(default_lcid(lcid));
    const kex_locname *e;
    unsigned i;
    int n;
    if (lang == KEX_LOCALE_INVARIANT) { out[0] = 0; return 0; }
    if (SUBLANGID(lang) == 0 || lang >= 0x7C00) {               /* neutral */
        if (!allow_neutral) lang = MAKELANGID(PRIMARYLANGID(lang), SUBLANG_DEFAULT);
        else {
            for (i = 0; i < NNEU; i++)
                if (kex_neutral_extra[i].lcid == lang) { lstrcpyA(out, kex_neutral_extra[i].name); return lstrlenA(out); }
            if (!(e = find_lcid(MAKELANGID(PRIMARYLANGID(lang), SUBLANG_DEFAULT)))) return -1;
            n = prefix_len(e->name);
            lstrcpynA(out, e->name, n + 1);
            return n;
        }
    }
    if (!(e = find_lcid(lang))) return -1;
    lstrcpyA(out, e->name);
    return lstrlenA(out);
}

/* name -> LCID (neutral LCID for "de" when allow_neutral, else the SUBLANG_DEFAULT one); 0 = unknown. */
static LCID name_lcid(LPCWSTR name, BOOL allow_neutral)
{
    unsigned i;
    if (!name) return GetUserDefaultLCID();                                   /* LOCALE_NAME_USER_DEFAULT */
    if (!name[0]) return KEX_LOCALE_INVARIANT;                                /* LOCALE_NAME_INVARIANT */
    if (name_eq(name, "!x-sys-default-locale", -1)) return GetSystemDefaultLCID();
    for (i = 0; i < NLOC; i++) if (name_eq(name, kex_locnames[i].name, -1)) return kex_locnames[i].lcid;
    for (i = 0; i < NNEU; i++)
        if (name_eq(name, kex_neutral_extra[i].name, -1)) {
            WORD l = kex_neutral_extra[i].lcid;
            if (allow_neutral) return l;
            /* zh-Hans -> zh-CN, zh-Hant -> zh-TW, no -> nb-NO, hr -> hr-HR, sr -> sr-Latn-RS */
            return l == 0x0004 ? 0x0804 : l == 0x7C04 ? 0x0404 : l == 0x7C1A ? 0x241A : MAKELANGID(PRIMARYLANGID(l), SUBLANG_DEFAULT);
        }
    for (i = 0; i < NLOC; i++) {                                              /* "de" -> de-DE */
        const kex_locname *e = &kex_locnames[i];
        if (SUBLANGID(e->lcid) == SUBLANG_DEFAULT && name_eq(name, e->name, prefix_len(e->name)))
            return allow_neutral ? PRIMARYLANGID(e->lcid) : e->lcid;
    }
    return 0;
}

/* LCID usable with the Win98 ANSI NLS functions (no neutral, no invariant). */
static LCID api_lcid(LCID lcid)
{
    WORD lang = LANGIDFROMLCID(default_lcid(lcid));
    if (lang == KEX_LOCALE_INVARIANT) return 0x0409;
    if (lang == 0x0004) return 0x0804;
    if (lang == 0x7C04) return 0x0404;
    if (SUBLANGID(lang) == 0 || lang >= 0x7C00) lang = MAKELANGID(PRIMARYLANGID(lang), SUBLANG_DEFAULT);
    return MAKELCID(lang, SORT_DEFAULT) | (lcid & 0x000F0000);   /* keep the sort id (es tradnl, de phonebook) */
}

static UINT lcid_cp(LCID lcid, DWORD flags)
{
    char b[8];
    UINT cp = 0;
    int i;
    if (flags & LOCALE_USE_CP_ACP) return CP_ACP;
    if (GetLocaleInfoA(lcid, LOCALE_IDEFAULTANSICODEPAGE, b, sizeof(b)))
        for (i = 0; b[i] >= '0' && b[i] <= '9'; i++) cp = cp * 10 + (b[i] - '0');
    return (cp && IsValidCodePage(cp)) ? cp : CP_ACP;
}

/* UTF-16 -> heap ANSI string (NUL-terminated). *alen = chars without NUL. */
static char *w2a(UINT cp, LPCWSTR w, int wl, int *alen)
{
    int n;
    char *a;
    if (wl < 0) wl = wlen(w);
    n = wl ? WideCharToMultiByte(cp, 0, w, wl, NULL, 0, NULL, NULL) : 0;
    if (wl && !n) { cp = CP_ACP; n = WideCharToMultiByte(cp, 0, w, wl, NULL, 0, NULL, NULL); }
    if (!(a = xalloc(n + 1))) return NULL;
    if (n) WideCharToMultiByte(cp, 0, w, wl, a, n, NULL, NULL);
    a[n] = 0;
    if (alen) *alen = n;
    return a;
}

/* ANSI (al chars, or -1 = through NUL) -> caller's UTF-16 buffer with Win32 size semantics. */
static int out_w(UINT cp, const char *a, int al, LPWSTR dst, int cch)
{
    int need = MultiByteToWideChar(cp, 0, a, al, NULL, 0);
    if (!need && al != 0 && cp != CP_ACP) { cp = CP_ACP; need = MultiByteToWideChar(cp, 0, a, al, NULL, 0); }
    if (!need && al != 0) return 0;
    if (!cch) return need;
    if (need > cch) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
    return MultiByteToWideChar(cp, 0, a, al, dst, cch);
}

static int out_ascii(const char *s, LPWSTR dst, int cch) { return out_w(CP_ACP, s, -1, dst, cch); }

/* =================== KernelEx api libraries (Unicode NLS) =================== */
typedef struct { const char *name; unsigned long addr; } kx_named;
typedef struct { const char *lib; const kx_named *named; int nnamed; const void *ord; int nord; } kx_table;

static FARPROC kx_lookup(const char *dll, const char *api)
{
    HMODULE h = GetModuleHandleA(dll);
    const kx_table *(*get)(void);
    const kx_table *t;
    int i;
    if (!h || !(get = (const kx_table *(*)(void))(void *)GetProcAddress(h, "get_api_table"))) return NULL;
    for (t = get(); t && t->lib; t++) {
        if (lstrcmpiA(t->lib, "KERNEL32.DLL")) continue;
        for (i = 0; i < t->nnamed; i++)
            if (t->named[i].name && !lstrcmpA(t->named[i].name, api)) return (FARPROC)t->named[i].addr;
    }
    return NULL;
}

/* Later api libraries override earlier ones in core.ini contents=std,kexbases,kexbasen. */
static FARPROC kx_upstream(const char *api)
{
    FARPROC p = kx_lookup("KEXBASEN.DLL", api);
    return p ? p : kx_lookup("KEXBASES.DLL", api);
}

typedef int (WINAPI *CompareStringW_t)(LCID, DWORD, LPCWSTR, int, LPCWSTR, int);
typedef int (WINAPI *LCMapStringW_t)(LCID, DWORD, LPCWSTR, int, LPWSTR, int);
static CompareStringW_t g_cmpw;
static LCMapStringW_t   g_mapw;
static LONG             g_upstream_done;

static void upstream_init(void)
{
    if (g_upstream_done) return;
    g_cmpw = (CompareStringW_t)(void *)kx_upstream("CompareStringW");
    g_mapw = (LCMapStringW_t)(void *)kx_upstream("LCMapStringW");
    InterlockedExchange(&g_upstream_done, 1);
}

/* LCMapStringW / CompareStringW with LOCALE_INVARIANT (0x7F, Windows XP+): Windows 10 DLLs (DirectWrite)
 * lower/upper-case font and locale names with it; Windows 98's NLS does not know that LCID and failed the call,
 * which made DirectWrite's text layout fail (2026-11-02). The invariant locale is mapped to en-US. */
static LCID fix_lcid(LCID l) { return (LANGIDFROMLCID(l) == KEX_LOCALE_INVARIANT) ? 0x0409 : l; }
int KEXAPI kex_LCMapStringW(LCID l, DWORD f, LPCWSTR s, int n, LPWSTR d, int dn)
{
    upstream_init();
    if (!g_mapw) g_mapw = (LCMapStringW_t)(void *)kex_sysproc("KERNEL32.DLL", "LCMapStringW");
    return g_mapw ? g_mapw(fix_lcid(l), f, s, n, d, dn) : 0;
}
int KEXAPI kex_CompareStringW(LCID l, DWORD f, LPCWSTR a, int na, LPCWSTR b, int nb)
{
    upstream_init();
    if (!g_cmpw) g_cmpw = (CompareStringW_t)(void *)kex_sysproc("KERNEL32.DLL", "CompareStringW");
    return g_cmpw ? g_cmpw(fix_lcid(l), f, a, na, b, nb) : 0;
}

/* exported for kextest: 1 = KernelEx Unicode collation in use, 0 = ANSI fallback */
DWORD KEXAPI kex_KexNlsUnicodeBackend(void) { upstream_init(); return g_cmpw && g_mapw; }

/* =============================== name APIs =============================== */
int KEXAPI kex_LCIDToLocaleName(LCID lcid, LPWSTR name, int cch, DWORD flags)
{
    char b[LOCALE_NAME_MAX_LENGTH];
    if (cch < 0 || (cch && !name)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (lcid_name(lcid, b, (flags & LOCALE_ALLOW_NEUTRAL_NAMES) != 0) < 0) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return out_ascii(b, name, cch);
}

LCID KEXAPI kex_LocaleNameToLCID(LPCWSTR name, DWORD flags)
{
    LCID l = name_lcid(name, (flags & LOCALE_ALLOW_NEUTRAL_NAMES) != 0);
    if (!l) SetLastError(ERROR_INVALID_PARAMETER);
    return l;
}

int KEXAPI kex_GetUserDefaultLocaleName(LPWSTR name, int cch)
{
    return kex_LCIDToLocaleName(GetUserDefaultLCID(), name, cch, 0);
}

int KEXAPI kex_GetSystemDefaultLocaleName(LPWSTR name, int cch)
{
    return kex_LCIDToLocaleName(GetSystemDefaultLCID(), name, cch, 0);
}

BOOL KEXAPI kex_IsValidLocaleName(LPCWSTR name)
{
    return name && name_lcid(name, TRUE) != 0;
}

int KEXAPI kex_ResolveLocaleName(LPCWSTR name, LPWSTR out, int cch)
{
    LCID l = name ? name_lcid(name, FALSE) : 0;
    if (!l) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return kex_LCIDToLocaleName(l, out, cch, 0);
}

typedef BOOL (CALLBACK *kex_LOCALE_ENUMPROCEX)(LPWSTR, DWORD, LPARAM);
BOOL KEXAPI kex_EnumSystemLocalesEx(kex_LOCALE_ENUMPROCEX proc, DWORD flags, LPARAM lp, LPVOID reserved)
{
    WCHAR w[LOCALE_NAME_MAX_LENGTH];
    unsigned i;
    if (!proc || reserved) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (flags && !(flags & (LOCALE_WINDOWS | LOCALE_SPECIFICDATA))) return TRUE;   /* only specific Windows locales */
    for (i = 0; i < NLOC; i++) {
        if (!IsValidLocale(kex_locnames[i].lcid, LCID_SUPPORTED)) continue;
        if (!out_ascii(kex_locnames[i].name, w, LOCALE_NAME_MAX_LENGTH)) continue;
        if (!proc(w, LOCALE_WINDOWS | LOCALE_SPECIFICDATA, lp)) break;
    }
    return TRUE;
}

/* ============================ GetLocaleInfoEx ============================ */
static BOOL is_rtl(const char *name)
{
    static const char *const rtl[] = { "ar", "he", "fa", "ur", "ps", "syr", "dv", "yi", "ug", NULL };
    int i, n = prefix_len(name);
    for (i = 0; rtl[i]; i++) {
        int k = 0;
        while (k < n && rtl[i][k] == name[k]) k++;
        if (k == n && rtl[i][k] == 0) return TRUE;
    }
    return FALSE;
}

/* ANSI value of an LCTYPE Win98 knows; heap string or NULL. */
static char *get_a(LCID lcid, LCTYPE type)
{
    int n = GetLocaleInfoA(lcid, type, NULL, 0);
    char *a;
    if (n <= 0 || !(a = xalloc(n + 1))) return NULL;
    if (!GetLocaleInfoA(lcid, type, a, n)) { xfree(a); return NULL; }
    a[n] = 0;
    return a;
}

static int lcinfo_w(LCID name_l, LCTYPE type, LPWSTR buf, int cch)
{
    DWORD fl = type & (LOCALE_NOUSEROVERRIDE | LOCALE_USE_CP_ACP);
    LCTYPE base = type & ~(LOCALE_NOUSEROVERRIDE | LOCALE_USE_CP_ACP | LOCALE_RETURN_NUMBER | LOCALE_RETURN_GENITIVE_NAMES);
    LCID l = api_lcid(name_l);
    UINT cp = lcid_cp(l, fl);
    char nm[LOCALE_NAME_MAX_LENGTH], spec[LOCALE_NAME_MAX_LENGTH], *a = NULL;
    int ret, n;

    if (lcid_name(name_l, nm, TRUE) < 0) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    lcid_name(name_l, spec, FALSE);

    if (type & LOCALE_RETURN_NUMBER) {
        WCHAR tmp[32];
        DWORD v = 0;
        int i, hex = (base == LOCALE_ILANGUAGE || base == LOCALE_IDEFAULTLANGUAGE);
        if (!lcinfo_w(name_l, base | fl, tmp, 32)) return 0;
        for (i = 0; tmp[i]; i++) {
            WCHAR c = lowerw(tmp[i]);
            if (c >= '0' && c <= '9') v = v * (hex ? 16 : 10) + (c - '0');
            else if (hex && c >= 'a' && c <= 'f') v = v * 16 + (c - 'a' + 10);
            else break;
        }
        if (!cch) return 2;
        if (cch < 2) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
        *(DWORD *)buf = v;
        return 2;
    }

    switch (base) {
    case LOCALE_SNAME: case LOCALE_SSORTLOCALE:
        return out_ascii(nm, buf, cch);
    case LOCALE_SPARENT:          /* specific -> neutral, neutral -> invariant ("") */
        n = (lstrcmpA(nm, spec) == 0) ? prefix_len(nm) : 0;
        nm[n] = 0;
        return out_ascii(nm, buf, cch);
    case LOCALE_SISO639LANGNAME:
        nm[prefix_len(nm)] = 0;
        return out_ascii(nm, buf, cch);
    case LOCALE_SISO3166CTRYNAME: {
        const char *c = spec + lstrlenA(spec);
        while (c > spec && c[-1] != '-') c--;
        lstrcpynA(nm, c, 4);
        if (nm[0] >= 'a') nm[0] = 0;                /* no region part ("es-ES_tradnl" keeps ES below) */
        if (lstrlenA(c) > 3 && c[2] == '_') nm[2] = 0;
        return out_ascii(nm, buf, cch);
    }
    case 0x6C: {             /* LOCALE_SSCRIPTS: ISO 15924 scripts, each followed by ';' */
        static const char *const sc[][2] = { { "ja", "Hani;Hira;Kana;" }, { "zh", "Hani;" }, { "ko", "Hang;Hani;" },
            { "ru", "Cyrl;" }, { "uk", "Cyrl;" }, { "bg", "Cyrl;" }, { "sr", "Cyrl;Latn;" }, { "el", "Grek;" },
            { "ar", "Arab;" }, { "fa", "Arab;" }, { "ur", "Arab;" }, { "he", "Hebr;" }, { "th", "Thai;" },
            { "hi", "Deva;" }, { "ka", "Geor;" }, { "hy", "Armn;" }, { NULL, NULL } };
        int i; nm[prefix_len(nm)] = 0;
        for (i = 0; sc[i][0]; i++) if (!lstrcmpA(sc[i][0], nm)) return out_ascii(sc[i][1], buf, cch);
        return out_ascii("Latn;", buf, cch);
    }
    case 0x7A: {             /* LOCALE_SOPENTYPELANGUAGETAG */
        static const char *const ot[][2] = { { "en", "ENG " }, { "de", "DEU " }, { "fr", "FRA " }, { "es", "ESP " },
            { "it", "ITA " }, { "pt", "PTG " }, { "nl", "NLD " }, { "sv", "SVE " }, { "da", "DAN " }, { "nb", "NOR " },
            { "fi", "FIN " }, { "pl", "PLK " }, { "cs", "CSY " }, { "hu", "HUN " }, { "tr", "TRK " }, { "ru", "RUS " },
            { "uk", "UKR " }, { "el", "ELL " }, { "ja", "JAN " }, { "zh", "ZHS " }, { "ko", "KOR " }, { "ar", "ARA " },
            { "he", "IWR " }, { "th", "THA " }, { NULL, NULL } };
        int i; nm[prefix_len(nm)] = 0;
        for (i = 0; ot[i][0]; i++) if (!lstrcmpA(ot[i][0], nm)) return out_ascii(ot[i][1], buf, cch);
        return out_ascii("dflt", buf, cch);
    }
    case 0x1014: {           /* LOCALE_IDIGITSUBSTITUTION: 0 context, 1 none, 2 native (Windows 2000+) */
        nm[prefix_len(nm)] = 0;
        return out_ascii((!lstrcmpA(nm, "ar") || !lstrcmpA(nm, "fa")) ? "0" : "1", buf, cch);
    }
    case 0x1013:             /* LOCALE_SSORTNAME */
        return out_ascii("", buf, cch);
    case LOCALE_SNAN:         return out_ascii("NaN", buf, cch);
    case LOCALE_SPOSINFINITY: return out_ascii("Infinity", buf, cch);
    case LOCALE_SNEGINFINITY: return out_ascii("-Infinity", buf, cch);
    case LOCALE_SPERCENT:     return out_ascii("%", buf, cch);
    case LOCALE_SPERMILLE:
        if (!cch) return 2;
        if (cch < 2) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
        buf[0] = 0x2030; buf[1] = 0;
        return 2;
    case LOCALE_INEGATIVEPERCENT: return out_ascii("0", buf, cch);   /* "-# %" */
    case LOCALE_IPOSITIVEPERCENT: return out_ascii("0", buf, cch);   /* "# %" */
    case LOCALE_IREADINGLAYOUT:   return out_ascii(is_rtl(nm) ? "1" : "0", buf, cch);
    case LOCALE_INEUTRAL:         return out_ascii(lstrcmpA(nm, spec) ? "1" : "0", buf, cch);
    case LOCALE_SENGLISHDISPLAYNAME: case LOCALE_SNATIVEDISPLAYNAME: {
        char *lang = get_a(l, (base == LOCALE_SENGLISHDISPLAYNAME ? LOCALE_SENGLANGUAGE : LOCALE_SNATIVELANGNAME) | fl);
        char *ctry = get_a(l, (base == LOCALE_SENGLISHDISPLAYNAME ? LOCALE_SENGCOUNTRY : LOCALE_SNATIVECTRYNAME) | fl);
        if (lang && ctry && (a = xalloc(lstrlenA(lang) + lstrlenA(ctry) + 4))) {
            lstrcpyA(a, lang); lstrcatA(a, " ("); lstrcatA(a, ctry); lstrcatA(a, ")");
        }
        xfree(lang); xfree(ctry);
        break;
    }
    case LOCALE_SSHORTTIME:       /* STIMEFORMAT without the seconds field */
        if ((a = get_a(l, LOCALE_STIMEFORMAT | fl))) {
            char *s, *d;
            for (s = d = a; *s; ) {
                if (*s == 's') {                        /* drop "ss" and the separator before it */
                    while (*s == 's') s++;
                    while (d > a && d[-1] != 'm' && d[-1] != 'M' && d[-1] != 'h' && d[-1] != 'H') d--;
                } else *d++ = *s++;
            }
            *d = 0;
        }
        break;
    default:
        if (base >= LOCALE_SSHORTESTDAYNAME1 && base <= LOCALE_SSHORTESTDAYNAME1 + 6) {
            WCHAR day[64];
            /* first two characters of the abbreviated day name (what Windows ships for most locales) */
            if (!lcinfo_w(name_l, (LOCALE_SABBREVDAYNAME1 + (base - LOCALE_SSHORTESTDAYNAME1)) | fl, day, 64)) return 0;
            if (wlen(day) > 2) day[2] = 0;
            n = wlen(day) + 1;
            if (!cch) return n;
            if (cch < n) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
            { int i; for (i = 0; i < n; i++) buf[i] = day[i]; }
            return n;
        }
        a = get_a(l, base | fl);
        if (!a) { SetLastError(ERROR_INVALID_FLAGS); return 0; }
        break;
    }
    if (!a) { SetLastError(ERROR_INVALID_FLAGS); return 0; }
    ret = out_w(cp, a, -1, buf, cch);
    xfree(a);
    return ret;
}

int KEXAPI kex_GetLocaleInfoEx(LPCWSTR name, LCTYPE type, LPWSTR buf, int cch)
{
    LCID l = name_lcid(name, TRUE);
    if (!l || cch < 0 || (cch && !buf)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return lcinfo_w(l, type, buf, cch);
}

/* ========================== number / date formatting ========================== */
#define FMT_PROLOGUE(name)                                                         \
    LCID nl = name_lcid(name, TRUE), l;                                            \
    UINT cp;                                                                       \
    if (!nl || cch < 0 || (cch && !buf)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; } \
    l = api_lcid(nl);                                                              \
    cp = lcid_cp(l, flags);

/* Run an ANSI formatter twice (size, then data) and convert the result. */
#define FMT_RUN(call_with_buf_len)                                                 \
    do {                                                                           \
        LPSTR abuf = NULL; int alen = 0, an;                                       \
        result = 0;                                                                \
        an = (call_with_buf_len);                                                  \
        if (an > 0 && (abuf = xalloc(an + 1)) != NULL) {                           \
            alen = an;                                                             \
            if ((call_with_buf_len) > 0) result = out_w(cp, abuf, -1, buf, cch);   \
            xfree(abuf);                                                           \
        }                                                                          \
    } while (0)

int KEXAPI kex_GetNumberFormatEx(LPCWSTR name, DWORD flags, LPCWSTR value, const NUMBERFMTW *fmt, LPWSTR buf, int cch)
{
    NUMBERFMTA fa;
    char *va, *ds = NULL, *ts = NULL;
    int result = 0;
    FMT_PROLOGUE(name)
    if (!value) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    va = w2a(CP_ACP, value, -1, NULL);
    if (fmt) {
        fa.NumDigits = fmt->NumDigits; fa.LeadingZero = fmt->LeadingZero; fa.Grouping = fmt->Grouping;
        fa.NegativeOrder = fmt->NegativeOrder;
        fa.lpDecimalSep = ds = w2a(cp, fmt->lpDecimalSep ? fmt->lpDecimalSep : L"", -1, NULL);
        fa.lpThousandSep = ts = w2a(cp, fmt->lpThousandSep ? fmt->lpThousandSep : L"", -1, NULL);
    }
    flags &= ~LOCALE_USE_CP_ACP;
    if (va) FMT_RUN(GetNumberFormatA(l, flags, va, fmt ? &fa : NULL, abuf, alen));
    xfree(va); xfree(ds); xfree(ts);
    return result;
}

int KEXAPI kex_GetCurrencyFormatEx(LPCWSTR name, DWORD flags, LPCWSTR value, const CURRENCYFMTW *fmt, LPWSTR buf, int cch)
{
    CURRENCYFMTA fa;
    char *va, *ds = NULL, *ts = NULL, *cs = NULL;
    int result = 0;
    FMT_PROLOGUE(name)
    if (!value) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    va = w2a(CP_ACP, value, -1, NULL);
    if (fmt) {
        fa.NumDigits = fmt->NumDigits; fa.LeadingZero = fmt->LeadingZero; fa.Grouping = fmt->Grouping;
        fa.NegativeOrder = fmt->NegativeOrder; fa.PositiveOrder = fmt->PositiveOrder;
        fa.lpDecimalSep = ds = w2a(cp, fmt->lpDecimalSep ? fmt->lpDecimalSep : L"", -1, NULL);
        fa.lpThousandSep = ts = w2a(cp, fmt->lpThousandSep ? fmt->lpThousandSep : L"", -1, NULL);
        fa.lpCurrencySymbol = cs = w2a(cp, fmt->lpCurrencySymbol ? fmt->lpCurrencySymbol : L"", -1, NULL);
    }
    flags &= ~LOCALE_USE_CP_ACP;
    if (va) FMT_RUN(GetCurrencyFormatA(l, flags, va, fmt ? &fa : NULL, abuf, alen));
    xfree(va); xfree(ds); xfree(ts); xfree(cs);
    return result;
}

int KEXAPI kex_GetDateFormatEx(LPCWSTR name, DWORD flags, const SYSTEMTIME *st, LPCWSTR fmt, LPWSTR buf, int cch, LPCWSTR cal)
{
    char *fa = NULL;
    int result = 0;
    FMT_PROLOGUE(name)
    if (cal) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    /* Win98 knows SHORTDATE/LONGDATE/USE_ALT_CALENDAR/YEARMONTH; reading-order and Win10 flags dropped */
    if (flags & DATE_MONTHDAY) { flags &= ~(DATE_SHORTDATE | DATE_LONGDATE | DATE_MONTHDAY); if (!fmt) fmt = L"MMMM dd"; }
    flags &= ~(DATE_LTRREADING | DATE_RTLREADING | DATE_AUTOLAYOUT | LOCALE_USE_CP_ACP);
    if (fmt && !(fa = w2a(cp, fmt, -1, NULL))) return 0;
    FMT_RUN(GetDateFormatA(l, flags, st, fa, abuf, alen));
    if (!result && (flags & DATE_YEARMONTH) && !fa && GetLastError() == ERROR_INVALID_FLAGS) {
        /* older builds without DATE_YEARMONTH: use LOCALE_SYEARMONTH explicitly */
        fa = get_a(l, LOCALE_SYEARMONTH);
        flags &= ~DATE_YEARMONTH;
        if (fa) FMT_RUN(GetDateFormatA(l, flags, st, fa, abuf, alen));
    }
    xfree(fa);
    return result;
}

int KEXAPI kex_GetTimeFormatEx(LPCWSTR name, DWORD flags, const SYSTEMTIME *st, LPCWSTR fmt, LPWSTR buf, int cch)
{
    char *fa = NULL;
    int result = 0;
    FMT_PROLOGUE(name)
    flags &= ~LOCALE_USE_CP_ACP;
    if (fmt && !(fa = w2a(cp, fmt, -1, NULL))) return 0;
    FMT_RUN(GetTimeFormatA(l, flags, st, fa, abuf, alen));
    xfree(fa);
    return result;
}

/* ============================ collation / mapping ============================ */
static DWORD map_cmp_flags(DWORD f)
{
    if (f & LINGUISTIC_IGNORECASE) f |= NORM_IGNORECASE;
    if (f & LINGUISTIC_IGNOREDIACRITIC) f |= NORM_IGNORENONSPACE;
    return f & (NORM_IGNORECASE | NORM_IGNORENONSPACE | NORM_IGNORESYMBOLS | NORM_IGNOREKANATYPE |
                NORM_IGNOREWIDTH | SORT_STRINGSORT);
}

int KEXAPI kex_CompareStringEx(LPCWSTR name, DWORD flags, LPCWSTR s1, int l1, LPCWSTR s2, int l2,
                               LPVOID ver, LPVOID reserved, LPARAM lp)
{
    LCID nl = name_lcid(name, TRUE), l;
    char *a1, *a2;
    int n1, n2, r;
    UINT cp;
    if (!nl || !s1 || !s2 || reserved || lp) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    l = api_lcid(nl);
    flags = map_cmp_flags(flags);
    upstream_init();
    if (g_cmpw) return g_cmpw(l, flags, s1, l1, s2, l2);
    cp = lcid_cp(l, 0);
    a1 = w2a(cp, s1, l1, &n1); a2 = w2a(cp, s2, l2, &n2);
    r = (a1 && a2) ? CompareStringA(l, flags, a1, n1, a2, n2) : 0;
    xfree(a1); xfree(a2);
    return r;
}

int KEXAPI kex_LCMapStringEx(LPCWSTR name, DWORD flags, LPCWSTR src, int srclen, LPWSTR dst, int dstlen,
                             LPVOID ver, LPVOID reserved, LPARAM sorthandle)
{
    LCID nl = name_lcid(name, TRUE), l;
    char *a, *o;
    int an, on, r = 0;
    UINT cp;
    if (!nl || !src || !srclen || dstlen < 0 || reserved || sorthandle) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (flags & (LCMAP_SORTHANDLE | LCMAP_HASH)) { SetLastError(ERROR_INVALID_FLAGS); return 0; }
    flags &= ~LCMAP_LINGUISTIC_CASING;
    if (flags & LCMAP_SORTKEY) flags = (flags & ~(LINGUISTIC_IGNORECASE | LINGUISTIC_IGNOREDIACRITIC)) |
                                       map_cmp_flags(flags & ~LCMAP_SORTKEY) | LCMAP_SORTKEY;
    l = api_lcid(nl);
    upstream_init();
    if (g_mapw) return g_mapw(l, flags, src, srclen, dst, dstlen);

    cp = lcid_cp(l, 0);
    if (srclen < 0) srclen = wlen(src) + 1;                      /* keep the NUL like the W API */
    if (!(a = w2a(cp, src, srclen, &an))) return 0;
    if (flags & LCMAP_SORTKEY) {                                 /* output is bytes */
        r = LCMapStringA(l, flags, a, an, (LPSTR)dst, dstlen);
        xfree(a);
        return r;
    }
    on = LCMapStringA(l, flags, a, an, NULL, 0);
    if (on > 0 && (o = xalloc(on))) {
        on = LCMapStringA(l, flags, a, an, o, on);
        r = on > 0 ? out_w(cp, o, on, dst, dstlen) : 0;
        xfree(o);
    }
    xfree(a);
    return r;
}

/* ============================ UI languages ============================ */
/* Win98 has a single UI language: the one of the user default locale. */
static BOOL ui_langs(DWORD flags, PULONG num, PZZWSTR buf, PULONG cch)
{
    WCHAR one[LOCALE_NAME_MAX_LENGTH];
    LANGID lang = LANGIDFROMLCID(GetUserDefaultLCID());
    ULONG n, i;
    if (!num || !cch || (flags & MUI_LANGUAGE_ID && flags & MUI_LANGUAGE_NAME)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (flags & MUI_LANGUAGE_ID) {
        static const char hx[] = "0123456789ABCDEF";
        for (i = 0; i < 4; i++) one[i] = hx[(lang >> (12 - 4 * i)) & 15];
        one[4] = 0;
        n = 5;
    } else {
        n = kex_LCIDToLocaleName(lang, one, LOCALE_NAME_MAX_LENGTH, 0);
        if (!n) return FALSE;
    }
    *num = 1;
    if (!buf) { *cch = n + 1; return TRUE; }
    if (*cch < n + 1) { *cch = n + 1; SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    for (i = 0; i < n; i++) buf[i] = one[i];
    buf[n] = 0;                                                  /* double-NUL terminated list */
    *cch = n + 1;
    return TRUE;
}

BOOL KEXAPI kex_GetUserPreferredUILanguages(DWORD flags, PULONG num, PZZWSTR buf, PULONG cch)   { return ui_langs(flags, num, buf, cch); }
BOOL KEXAPI kex_GetSystemPreferredUILanguages(DWORD flags, PULONG num, PZZWSTR buf, PULONG cch) { return ui_langs(flags, num, buf, cch); }
BOOL KEXAPI kex_GetThreadPreferredUILanguages(DWORD flags, PULONG num, PZZWSTR buf, PULONG cch) { return ui_langs(flags, num, buf, cch); }
BOOL KEXAPI kex_GetProcessPreferredUILanguages(DWORD flags, PULONG num, PZZWSTR buf, PULONG cch) { return ui_langs(flags, num, buf, cch); }

/* Thread/process UI language overrides: accepted, Win98 cannot switch UI language per thread. */
BOOL KEXAPI kex_SetThreadPreferredUILanguages(DWORD flags, PCZZWSTR langs, PULONG num) { if (num) *num = 0; return TRUE; }
BOOL KEXAPI kex_SetProcessPreferredUILanguages(DWORD flags, PCZZWSTR langs, PULONG num) { if (num) *num = 0; return TRUE; }

/* ============================ CompareStringOrdinal ============================ */
/* Simple (1:1) uppercase mapping for Latin-1, Latin Extended-A, Greek and Cyrillic -
 * the ranges RtlUpcaseUnicodeChar covers for real-world identifiers and paths. */
static WCHAR upw(WCHAR c)
{
    if (c < 'a') return c;
    if (c <= 'z') return (WCHAR)(c - 32);
    if (c < 0xE0) return c == 0xB5 ? 0x39C : c;
    if (c <= 0xFE) return c == 0xF7 ? c : (WCHAR)(c - 32);
    if (c == 0xFF) return 0x178;
    if (c >= 0x100 && c <= 0x137) return (c & 1) ? (WCHAR)(c - 1) : c;
    if (c >= 0x139 && c <= 0x148) return (c & 1) ? c : (WCHAR)(c - 1);
    if (c >= 0x14A && c <= 0x177) return (c & 1) ? (WCHAR)(c - 1) : c;
    if (c >= 0x179 && c <= 0x17E) return (c & 1) ? c : (WCHAR)(c - 1);
    if (c >= 0x3B1 && c <= 0x3CB && c != 0x3C2) return (WCHAR)(c - 32);
    if (c == 0x3C2) return 0x3A3;
    if (c >= 0x430 && c <= 0x44F) return (WCHAR)(c - 32);
    if (c >= 0x450 && c <= 0x45F) return (WCHAR)(c - 80);
    if (c >= 0x460 && c <= 0x481) return (c & 1) ? (WCHAR)(c - 1) : c;
    if (c >= 0x48A && c <= 0x4BF) return (c & 1) ? (WCHAR)(c - 1) : c;
    if (c >= 0xFF41 && c <= 0xFF5A) return (WCHAR)(c - 32);   /* fullwidth a-z */
    return c;
}

int KEXAPI kex_CompareStringOrdinal(LPCWSTR s1, int l1, LPCWSTR s2, int l2, BOOL ignore_case)
{
    int i, n;
    if (!s1 || !s2) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (l1 < 0) l1 = wlen(s1);
    if (l2 < 0) l2 = wlen(s2);
    n = l1 < l2 ? l1 : l2;
    for (i = 0; i < n; i++) {
        WCHAR a = s1[i], b = s2[i];
        if (ignore_case) { a = upw(a); b = upw(b); }
        if (a != b) return a < b ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
    }
    return l1 < l2 ? CSTR_LESS_THAN : l1 > l2 ? CSTR_GREATER_THAN : CSTR_EQUAL;
}
