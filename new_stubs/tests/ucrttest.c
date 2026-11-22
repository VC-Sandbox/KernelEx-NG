/*
 * ucrttest.c - stage 2 test: an ordinary program linked like a Visual Studio 2015+ program.
 *
 * Built with the UCRT toolchain, so it imports api-ms-win-crt-*.dll (our forwarders -> the genuine
 * Windows 10 ucrtbase.dll) and its startup code runs inside ucrtbase (_initterm, argv, environment).
 * If Windows 98 shows a loader error box for this program, run UCRTLOAD.EXE for a step-by-step log.
 * Needs next to it: ucrtbase.dll (Win10 SysWOW64) + our api-ms-win-crt-*.dll. Log: UCRTTEST.LOG.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <process.h>

static FILE *g_log;
static int g_pass, g_fail;

#define LOG(...) do { printf(__VA_ARGS__); if (g_log) { fprintf(g_log, __VA_ARGS__); fflush(g_log); } } while (0)
#define CHECK(c, ...) do { if (c) { g_pass++; LOG("  ok   "); } else { g_fail++; LOG("  FAIL "); } \
                           LOG(__VA_ARGS__); LOG("\n"); } while (0)

static int ctor_ran;
__attribute__((constructor)) static void ctor(void) { ctor_ran = 1; }   /* runs via ucrtbase _initterm */

static int atexit_flag;
static void on_exit(void) { if (g_log) { fprintf(g_log, "atexit handler ran\n"); fclose(g_log); } }

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static volatile LONG g_done;
static unsigned __stdcall worker(void *arg)
{
    char *s;
    errno = 77;                                   /* per-thread */
    s = malloc(64);
    snprintf(s, 64, "worker %d", (int)(INT_PTR)arg);
    free(s);
    InterlockedIncrement(&g_done);
    return 0;
}

int main(int argc, char **argv)
{
    g_log = fopen("ucrttest.log", "a");
    atexit_flag = atexit(on_exit) == 0;
    {
        OSVERSIONINFOA vi; vi.dwOSVersionInfoSize = sizeof(vi); GetVersionExA(&vi);
        LOG("ucrttest: host %lu.%lu.%lu, ucrtbase at %p\n", vi.dwMajorVersion, vi.dwMinorVersion,
            vi.dwBuildNumber & 0xFFFF, (void *)GetModuleHandleA("ucrtbase.dll"));
    }

    LOG("[startup]\n");
    CHECK(ctor_ran, "static constructor ran (_initterm)");
    CHECK(argc >= 1 && argv[0] && strlen(argv[0]) > 0, "argv[0] = %s", argc >= 1 ? argv[0] : "(none)");
    CHECK(getenv("PATH") != NULL, "environment available");
    CHECK(atexit_flag, "atexit registered");

    LOG("[stdio / strings]\n");
    {
        char b[128];
        const char *names[] = { "pear", "apple", "fig" };
        snprintf(b, sizeof b, "%s %d %.3f %08X %zu %lld", "fmt", -5, 2.5, 0xBEEFu, (size_t)7, 1LL << 40);
        CHECK(!strcmp(b, "fmt -5 2.500 0000BEEF 7 1099511627776"), "snprintf -> '%s'", b);
        qsort((void *)names, 3, sizeof(char *), cmp_str);
        CHECK(!strcmp(names[0], "apple") && !strcmp(names[2], "pear"), "qsort strings");
        CHECK(fabs(strtod("1e-3", NULL) - 0.001) < 1e-12, "strtod exponent");
        CHECK(fabs(atan2(1.0, 1.0) * 4 - 3.14159265358979) < 1e-9, "atan2 (pi)");
    }

    LOG("[files]\n");
    {
        FILE *f = fopen("ucrt2tmp.txt", "w");
        char line[64] = "";
        CHECK(f != NULL, "fopen text write");
        if (f) { fprintf(f, "line one\nline two\n"); fclose(f); }
        f = fopen("ucrt2tmp.txt", "r");
        CHECK(f && fgets(line, sizeof line, f) && !strcmp(line, "line one\n"), "fgets text mode (CRLF translated)");
        if (f) fclose(f);
        CHECK(remove("ucrt2tmp.txt") == 0, "remove");
    }

    LOG("[locale / time]\n");
    {
        time_t t = time(NULL);
        struct tm *lt = localtime(&t);
        char ts[64];
        CHECK(setlocale(LC_ALL, "") != NULL, "setlocale user default: %s", setlocale(LC_ALL, NULL));
        CHECK(lt && strftime(ts, sizeof ts, "%A %d %B %Y", lt) > 0, "strftime '%s'", lt ? ts : "");
        setlocale(LC_ALL, "C");
    }

    LOG("[threads]\n");
    {
        HANDLE h[8]; int i, ok = 1;
        errno = 0;
        for (i = 0; i < 8; i++) { h[i] = (HANDLE)_beginthreadex(NULL, 0, worker, (void *)(INT_PTR)i, 0, NULL); if (!h[i]) ok = 0; }
        CHECK(ok, "_beginthreadex x8");
        for (i = 0; i < 8; i++) if (h[i]) { WaitForSingleObject(h[i], 10000); CloseHandle(h[i]); }
        CHECK(g_done == 8, "8 workers finished");
        CHECK(errno == 0, "errno per-thread");
    }

    LOG("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail;      /* exit() -> atexit handler -> ucrtbase teardown */
}
