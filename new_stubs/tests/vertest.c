/*
 * vertest.c - shows what Windows version THIS program is told, end to end through KernelEx.
 *
 * Pick a profile on VERTEST.EXE (Properties -> KernelEx tab -> e.g. "Windows 10 21H2 (KernelEx-NG)"),
 * run it, and compare with the expected values printed in README.TXT. Log: VERTEST.LOG.
 * Imports only functions every KernelEx mode resolves; version functions that some modes remove
 * (VerifyVersionInfoW, VerSetConditionMask, RtlGetVersion) are looked up with GetProcAddress,
 * which KernelEx routes with the same profile.
 * It also imports one api-ms-win-core function so the NT PEB emulation starts, and prints the PEB version.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdio.h>
#include <string.h>

static FILE *g_log;
#define LOG(...) do { printf(__VA_ARGS__); if (g_log) { fprintf(g_log, __VA_ARGS__); fflush(g_log); } } while (0)

/* static import from an api set: loads our shells -> kexnt.dll -> PEB emulation */
__declspec(dllimport) ULONGLONG WINAPI GetTickCount64(void);

static ULONGLONG vscm(ULONGLONG m, DWORD type, BYTE cond)
{
    int i;
    for (i = 0; i < 8; i++) if (type & (1u << i)) m |= (ULONGLONG)cond << (i * 3);
    return m;
}

int main(void)
{
    typedef BOOL (WINAPI *pfnVVI)(LPOSVERSIONINFOEXW, DWORD, ULONGLONG);
    typedef LONG (WINAPI *pfnRGV)(LPOSVERSIONINFOEXW);
    typedef PVOID (WINAPI *pfnPeb)(PDWORD, PDWORD, PDWORD);
    HMODULE k32 = GetModuleHandleA("KERNEL32.DLL"), nt = GetModuleHandleA("NTDLL.DLL"), kx;
    OSVERSIONINFOEXA a; OSVERSIONINFOEXW w;
    pfnVVI vvi = (pfnVVI)GetProcAddress(k32, "VerifyVersionInfoW");
    pfnRGV rgv = nt ? (pfnRGV)GetProcAddress(nt, "RtlGetVersion") : NULL;
    pfnPeb peb;
    DWORD v = GetVersion();

    g_log = fopen("vertest.log", "a");
    (void)GetTickCount64();
    LOG("vertest\n");
    LOG("  GetVersion        %08lx -> %lu.%lu build %lu (%s)\n", v, v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0x7FFF,
        (v & 0x80000000UL) ? "9x" : "NT");
    memset(&a, 0, sizeof(a)); a.dwOSVersionInfoSize = sizeof(a);
    if (GetVersionExA((LPOSVERSIONINFOA)&a))
        LOG("  GetVersionExA     %lu.%lu.%lu platform %lu \"%s\" SP%u type %u suite %04x\n", a.dwMajorVersion,
            a.dwMinorVersion, a.dwBuildNumber & 0xFFFF, a.dwPlatformId, a.szCSDVersion, a.wServicePackMajor,
            a.wProductType, a.wSuiteMask);
    else LOG("  GetVersionExA(EX) failed, error %lu\n", GetLastError());
    memset(&w, 0, sizeof(w)); w.dwOSVersionInfoSize = sizeof(w);
    if (GetVersionExW((LPOSVERSIONINFOW)&w))
        LOG("  GetVersionExW     %lu.%lu.%lu platform %lu type %u\n", w.dwMajorVersion, w.dwMinorVersion,
            w.dwBuildNumber & 0xFFFF, w.dwPlatformId, w.wProductType);
    else LOG("  GetVersionExW failed, error %lu\n", GetLastError());
    if (rgv) {
        memset(&w, 0, sizeof(w)); w.dwOSVersionInfoSize = sizeof(w);
        LOG("  RtlGetVersion     status %08lx -> %lu.%lu.%lu\n", (DWORD)rgv(&w), w.dwMajorVersion, w.dwMinorVersion, w.dwBuildNumber);
    } else LOG("  RtlGetVersion     not available in this mode\n");
    if (vvi) {
        static const struct { DWORD maj, min; WORD sp; const char *n; } t[] = {
            { 6, 1, 1, "7 SP1" }, { 6, 2, 0, "8" }, { 6, 3, 0, "8.1" }, { 10, 0, 0, "10" } };
        int i;
        LOG("  IsWindowsXOrGreater:");
        for (i = 0; i < 4; i++) {
            OSVERSIONINFOEXW q;
            memset(&q, 0, sizeof(q)); q.dwOSVersionInfoSize = sizeof(q);
            q.dwMajorVersion = t[i].maj; q.dwMinorVersion = t[i].min; q.wServicePackMajor = t[i].sp;
            LOG(" %s=%s", t[i].n, vvi(&q, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR,
                vscm(vscm(vscm(0, VER_MAJORVERSION, VER_GREATER_EQUAL), VER_MINORVERSION, VER_GREATER_EQUAL),
                     VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL)) ? "yes" : "no");
        }
        LOG("\n");
    } else LOG("  VerifyVersionInfoW not available in this mode\n");
    kx = GetModuleHandleA("kexnt.dll");
    peb = kx ? (pfnPeb)GetProcAddress(kx, "KexGetNtPeb") : NULL;
    if (peb) {
        BYTE *p = (BYTE *)peb(NULL, NULL, NULL);
        LOG("  emulated PEB      %lu.%lu.%u\n", *(DWORD *)(p + 0xA4), *(DWORD *)(p + 0xA8), *(WORD *)(p + 0xAC));
    }
    LOG("\n");
    if (g_log) fclose(g_log);
    printf("Press Enter to close...");
    getchar();
    return 0;
}
