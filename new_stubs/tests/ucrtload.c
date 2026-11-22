/*
 * ucrtload.c - stage 1 test: load the GENUINE Windows 10 ucrtbase.dll on Windows 98 SE and call it.
 *
 * Does not depend on ucrtbase at load time (built against msvcrt), so it always starts and can log
 * exactly which step fails: LoadLibrary (imports / DllMain), GetProcAddress, or a call.
 * Put ucrtbase.dll (from Win10 SysWOW64) next to this program. Log: UCRTLOAD.LOG.
 * Exit code = number of failed checks (100 = ucrtbase.dll did not load).
 */
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

static FILE *g_log;
static int g_pass, g_fail;

static void LOG(const char *fmt, ...)
{
    va_list a;
    va_start(a, fmt); vprintf(fmt, a); va_end(a);
    if (g_log) { va_start(a, fmt); vfprintf(g_log, fmt, a); va_end(a); fflush(g_log); }
}
#define CHECK(c, ...) do { if (c) { g_pass++; LOG("  ok   "); } else { g_fail++; LOG("  FAIL "); } \
                           LOG(__VA_ARGS__); LOG("\n"); } while (0)

/* ---- ucrtbase exports (all __cdecl) ---- */
#define FN(ret, name, args) static ret (__cdecl *p_##name) args
FN(void *, malloc, (size_t));
FN(void *, calloc, (size_t, size_t));
FN(void *, realloc, (void *, size_t));
FN(void, free, (void *));
FN(void *, _aligned_malloc, (size_t, size_t));
FN(void, _aligned_free, (void *));
FN(size_t, strlen, (const char *));
FN(int, strcpy_s, (char *, size_t, const char *));
FN(size_t, wcslen, (const wchar_t *));
FN(int *, _errno, (void));
FN(int, __stdio_common_vsprintf, (unsigned __int64, char *, size_t, const char *, void *, va_list));
FN(int, __stdio_common_vsscanf, (unsigned __int64, const char *, size_t, const char *, void *, va_list));
FN(double, strtod, (const char *, char **));
FN(void, qsort, (void *, size_t, size_t, int (__cdecl *)(const void *, const void *)));
FN(char *, setlocale, (int, const char *));
FN(size_t, mbstowcs, (wchar_t *, const char *, size_t));
FN(__int64, _time64, (__int64 *));
FN(int, _localtime64_s, (struct tm *, const __int64 *));
FN(size_t, strftime, (char *, size_t, const char *, const struct tm *));
FN(FILE *, fopen, (const char *, const char *));
FN(size_t, fwrite, (const void *, size_t, size_t, FILE *));
FN(size_t, fread, (void *, size_t, size_t, FILE *));
FN(int, fclose, (FILE *));
FN(int, remove, (const char *));
FN(char *, getenv, (const char *));
FN(uintptr_t, _beginthreadex, (void *, unsigned, unsigned (__stdcall *)(void *), void *, unsigned, unsigned *));
FN(double, sqrt, (double));
FN(double, pow, (double, double));
FN(double, sin, (double));
FN(double, floor, (double));
FN(int, rand, (void));
FN(void, srand, (unsigned));
typedef void (__cdecl *inv_handler)(const wchar_t *, const wchar_t *, const wchar_t *, unsigned, uintptr_t);
FN(inv_handler, _set_invalid_parameter_handler, (inv_handler));
static volatile int g_inv_calls;
static void __cdecl on_invalid_param(const wchar_t *e, const wchar_t *f, const wchar_t *file, unsigned line, uintptr_t r)
{ g_inv_calls++; }

static int csprintf(char *b, size_t n, const char *fmt, ...)
{
    va_list a; int r;
    va_start(a, fmt);
    r = p___stdio_common_vsprintf(0, b, n, fmt, NULL, a);   /* options 0 = legacy-free C99 behaviour */
    va_end(a);
    return r;
}

static int csscanf(const char *s, const char *fmt, ...)
{
    va_list a; int r;
    va_start(a, fmt);
    r = p___stdio_common_vsscanf(0, s, (size_t)-1, fmt, NULL, a);
    va_end(a);
    return r;
}

static int __cdecl cmp_int(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }

static volatile LONG g_thread_ran;
static unsigned __stdcall thread_fn(void *arg)
{
    /* errno is per-thread ucrt data (FLS-backed): set it here, it must not leak to the main thread */
    char *m;
    *p__errno() = 1234;
    m = (char *)p_malloc(100);
    if (m) { p_strcpy_s(m, 100, "thread"); p_free(m); }
    InterlockedIncrement(&g_thread_ran);
    return (unsigned)(ULONG_PTR)arg;
}

int main(int argc, char **argv)
{
    char path[MAX_PATH], *bs, buf[256];
    HMODULE u;
    int missing = 0;
    (void)argc; (void)argv;

    g_log = fopen("ucrtload.log", "a");
    {
        OSVERSIONINFOA vi; vi.dwOSVersionInfoSize = sizeof(vi); GetVersionExA(&vi);
        LOG("ucrtload: host %lu.%lu.%lu platform %lu\n", vi.dwMajorVersion, vi.dwMinorVersion,
            vi.dwBuildNumber & 0xFFFF, vi.dwPlatformId);
    }
    GetModuleFileNameA(NULL, path, MAX_PATH);
    if ((bs = strrchr(path, '\\'))) bs[1] = 0; else path[0] = 0;
    strcat(path, "ucrtbase.dll");

    LOG("[load] %s\n", path);
    SetLastError(0);
    u = LoadLibraryA(path);
    if (!u) {
        LOG("  FAIL LoadLibrary error %lu (126 = a dependency is missing, 1114 = DllMain returned FALSE,\n"
            "       31/193 = not a valid image for this system)\n", GetLastError());
        if (g_log) fclose(g_log);
        return 100;
    }
    GetModuleFileNameA(u, buf, sizeof(buf));
    LOG("  ok   loaded at %08lx from %s\n", (unsigned long)(ULONG_PTR)u, buf);

    LOG("[exports]\n");
#define R(name) do { *(FARPROC *)&p_##name = GetProcAddress(u, #name); \
                     if (!p_##name) { LOG("  FAIL missing %s\n", #name); missing++; } } while (0)
    R(malloc); R(calloc); R(realloc); R(free); R(_aligned_malloc); R(_aligned_free);
    R(strlen); R(strcpy_s); R(wcslen); R(_errno); R(__stdio_common_vsprintf); R(__stdio_common_vsscanf);
    R(strtod); R(qsort); R(setlocale); R(mbstowcs); R(_time64); R(_localtime64_s); R(strftime);
    R(fopen); R(fwrite); R(fread); R(fclose); R(remove); R(getenv); R(_beginthreadex);
    R(sqrt); R(pow); R(sin); R(floor); R(rand); R(srand); R(_set_invalid_parameter_handler);
    if (missing) { LOG("%d exports missing\n", missing); if (g_log) fclose(g_log); return 101; }
    LOG("  ok   all exports found\n");

    LOG("[NT PEB emulation]\n");
    {
        typedef PVOID (WINAPI *pfnPeb)(PDWORD, PDWORD, PDWORD);
        HMODULE kx = GetModuleHandleA("kexnt.dll");
        pfnPeb getpeb = kx ? (pfnPeb)GetProcAddress(kx, "KexGetNtPeb") : NULL;
        CHECK(getpeb != NULL, "kexnt.dll loaded with KexGetNtPeb");
        if (getpeb) {
            DWORD mods = 0, sites = 0, unh = 0;
            BYTE *peb = (BYTE *)getpeb(&mods, &sites, &unh);
            BYTE *params = peb ? *(BYTE **)(peb + 0x10) : NULL;
            LOG("    patched %lu module(s), %lu fs:[30h] site(s), %lu unhandled form(s)\n", mods, sites, unh);
            CHECK(sites >= 5, "ucrtbase's 5 PEB reads were patched");
            CHECK(peb && *(DWORD *)(peb + 0xA4) >= 6, "PEB reports NT %lu.%lu.%u", peb ? *(DWORD *)(peb + 0xA4) : 0,
              peb ? *(DWORD *)(peb + 0xA8) : 0, peb ? *(WORD *)(peb + 0xAC) : 0);
            CHECK(params && *(DWORD *)(params + 0x08) == 1, "ProcessParameters present, Flags = NORMALIZED");
            CHECK(peb && *(HANDLE *)(peb + 0x18) == GetProcessHeap(), "PEB ProcessHeap == GetProcessHeap()");
        }
    }

    LOG("[heap]\n");
    {
        char *a = (char *)p_malloc(1000), *b;
        int *z = (int *)p_calloc(16, sizeof(int)), allzero = 1, i;
        void *al = p__aligned_malloc(100, 64);
        CHECK(a != NULL, "malloc(1000)");
        for (i = 0; z && i < 16; i++) if (z[i]) allzero = 0;
        CHECK(z && allzero, "calloc zeroed");
        if (a) { memset(a, 'x', 1000); b = (char *)p_realloc(a, 100000); CHECK(b && b[999] == 'x', "realloc keeps data"); p_free(b); }
        CHECK(al && ((ULONG_PTR)al & 63) == 0, "_aligned_malloc 64-byte alignment (%p)", al);
        p__aligned_free(al); p_free(z);
    }

    LOG("[strings / stdio formatting]\n");
    {
        char s[64]; int n, x = 0; double d = 0;
        CHECK(p_strlen("hello") == 5, "strlen");
        CHECK(p_strcpy_s(s, sizeof(s), "abc") == 0 && !strcmp(s, "abc"), "strcpy_s");
        /* NT behaviour: without a handler this terminates the process (c0000417), like on Windows 10 */
        p__set_invalid_parameter_handler(on_invalid_param);
        CHECK(p_strcpy_s(s, 2, "abc") != 0 && g_inv_calls == 1, "strcpy_s too-small buffer -> handler + error");
        CHECK(p_wcslen(L"wide") == 4, "wcslen");
        n = csprintf(s, sizeof(s), "%d|%5.2f|%s|%x|%lld", 42, 3.14159, "str", 255, 1234567890123LL);
        CHECK(n > 0 && !strcmp(s, "42| 3.14|str|ff|1234567890123"), "sprintf -> '%s'", s);
        CHECK(csscanf("17 2.5", "%d %lf", &x, &d) == 2 && x == 17 && d == 2.5, "sscanf");
        CHECK(p_strtod("3.25", NULL) == 3.25, "strtod");
    }

    LOG("[algorithms / math]\n");
    {
        int v[6] = { 5, 3, 9, 1, 7, 2 };
        p_qsort(v, 6, sizeof(int), cmp_int);
        CHECK(v[0] == 1 && v[5] == 9, "qsort");
        CHECK(p_sqrt(16.0) == 4.0, "sqrt");
        CHECK(p_pow(2.0, 10.0) == 1024.0, "pow");
        CHECK(p_floor(-1.5) == -2.0, "floor");
        CHECK(p_sin(0.0) == 0.0, "sin");
        p_srand(1); { int r1 = p_rand(); p_srand(1); CHECK(p_rand() == r1, "rand/srand reproducible"); }
    }

    LOG("[locale]\n");
    {
        char *l = p_setlocale(0 /* LC_ALL */, "C");
        wchar_t w[16];
        CHECK(l && !strcmp(l, "C"), "setlocale(LC_ALL, \"C\") -> %s", l ? l : "(null)");
        l = p_setlocale(0, "");
        CHECK(l != NULL, "setlocale(LC_ALL, \"\") user default -> %s", l ? l : "(null)");
        CHECK(p_mbstowcs(w, "abc", 16) == 3 && w[2] == L'c', "mbstowcs");
        p_setlocale(0, "C");
    }

    LOG("[time]\n");
    {
        __int64 t = p__time64(NULL);
        struct tm tm;
        char s[64] = "";
        CHECK(t > 1000000000LL, "_time64 = %I64d", t);
        CHECK(p__localtime64_s(&tm, &t) == 0 && tm.tm_year >= 100, "_localtime64_s year %d", tm.tm_year + 1900);
        CHECK(p_strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", &tm) == 19, "strftime '%s'", s);
    }

    LOG("[files]\n");
    {
        FILE *f = p_fopen("ucrttmp.txt", "wb");
        char r[32] = "";
        CHECK(f != NULL, "fopen write");
        if (f) { CHECK(p_fwrite("ucrt on win98", 1, 13, f) == 13, "fwrite"); p_fclose(f); }
        f = p_fopen("ucrttmp.txt", "rb");
        CHECK(f != NULL, "fopen read");
        if (f) { CHECK(p_fread(r, 1, 31, f) == 13 && !memcmp(r, "ucrt on win98", 13), "fread round trip"); p_fclose(f); }
        CHECK(p_remove("ucrttmp.txt") == 0, "remove");
        CHECK(p_getenv("PATH") != NULL, "getenv(PATH)");
    }

    LOG("[threads / per-thread CRT data]\n");
    {
        unsigned tid = 0, i;
        HANDLE h[4];
        *p__errno() = 0;
        for (i = 0; i < 4; i++) h[i] = (HANDLE)p__beginthreadex(NULL, 0, thread_fn, (void *)(ULONG_PTR)(i + 10), 0, &tid);
        CHECK(h[0] && h[1] && h[2] && h[3], "_beginthreadex x4");
        for (i = 0; i < 4; i++) if (h[i]) {
            DWORD code = 0;
            WaitForSingleObject(h[i], 10000);
            GetExitCodeThread(h[i], &code);
            CHECK(code == i + 10, "thread %u exit code %lu", i, code);
            CloseHandle(h[i]);
        }
        CHECK(g_thread_ran == 4, "all 4 threads ran");
        CHECK(*p__errno() == 0, "errno is per-thread (main thread still 0)");
    }

    LOG("[unload]\n");
    CHECK(FreeLibrary(u), "FreeLibrary(ucrtbase)");

    LOG("\n%d passed, %d failed\n", g_pass, g_fail);
    if (g_log) fclose(g_log);
    return g_fail;
}
