/* bcrypt.dll for Windows 98 SE: the random number generator part of CNG (what most programs use).
 * Other algorithms report STATUS_NOT_FOUND so callers fall back. */
#include <windows.h>
__declspec(dllimport) BOOL WINAPI KexGenRandom(PVOID buf, SIZE_T len);
#define ST_OK        ((LONG)0)
#define ST_NOT_FOUND ((LONG)0xC0000225L)
#define ST_BADHANDLE ((LONG)0xC0000008L)
#define ST_BADPARAM  ((LONG)0xC000000DL)
static const char g_rng_tag[] = "KEXRNG";

static int is_rng(const WCHAR *a)
{
    static const WCHAR *names[] = { L"RNG", L"FIPS186DSARNG", L"DUALECRNG" };
    int i, j;
    if (!a) return 0;
    for (i = 0; i < 3; i++) {
        for (j = 0; names[i][j] && a[j] == names[i][j]; j++) ;
        if (!names[i][j] && !a[j]) return 1;
    }
    return 0;
}
LONG WINAPI BCryptOpenAlgorithmProvider(void **h, LPCWSTR alg, LPCWSTR impl, ULONG flags)
{
    if (!h) return ST_BADPARAM;
    *h = NULL;
    if (!is_rng(alg)) return ST_NOT_FOUND;
    *h = (void *)g_rng_tag; return ST_OK;
}
LONG WINAPI BCryptCloseAlgorithmProvider(void *h, ULONG flags) { return h == (void *)g_rng_tag ? ST_OK : ST_BADHANDLE; }
LONG WINAPI BCryptGenRandom(void *h, PUCHAR buf, ULONG len, ULONG flags)
{
    if (!(flags & 2 /*BCRYPT_USE_SYSTEM_PREFERRED_RNG*/) && h != (void *)g_rng_tag) return ST_BADHANDLE;
    if (!buf && len) return ST_BADPARAM;
    if (len) KexGenRandom(buf, len);
    return ST_OK;
}
