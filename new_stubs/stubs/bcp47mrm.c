/* bcp47mrm.dll stub (KernelEx-NG): GetDistanceOfClosestLanguageInList(language, list, separator, *distance).
 * Written from the public documentation: distance 1.0 = the language is in the list (compared without
 * case, also by its primary subtag, "en-US" ~ "en"), 0.0 = no match. */
#include <windows.h>
static int lower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }
static int same(const WCHAR *a, int na, const WCHAR *b, int nb)
{
    int i;
    if (na != nb) return 0;
    for (i = 0; i < na; i++) if (lower(a[i]) != lower(b[i])) return 0;
    return 1;
}
static int primary(const WCHAR *s, int n) { int i; for (i = 0; i < n && s[i] != '-' && s[i] != '_'; i++); return i; }
LONG WINAPI GetDistanceOfClosestLanguageInList(const WCHAR *lang, const WCHAR *list, WCHAR sep, double *dist)
{
    double best = 0.0; int nl = 0;
    if (!lang || !list || !dist) return (LONG)0x80070057UL;      /* E_INVALIDARG */
    while (lang[nl]) nl++;
    while (*list) {
        int n = 0;
        while (list[n] && list[n] != sep) n++;
        if (same(lang, nl, list, n)) best = 1.0;
        else if (best < 0.5 && same(lang, primary(lang, nl), list, primary(list, n))) best = 0.5;
        list += n; if (*list) list++;
    }
    *dist = best;
    return 0;
}
