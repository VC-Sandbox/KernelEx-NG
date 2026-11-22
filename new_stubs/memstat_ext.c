/*
 * memstat_ext.c - KernelEx-NG: GlobalMemoryStatusEx that counts Windows 98's disk cache as available memory.
 *
 * Build 59: Chromium was slow and froze now and then. CHRLOG4 shows "Discarding multiple pages" every 5 s for the
 * whole run = Chromium's memory-pressure monitor saw CRITICAL pressure all the time (free physical memory below
 * 200 MB on a machine with less than 4 GB). Critical pressure means: tabs discarded, V8 full garbage collections,
 * image/font/raster caches thrown away and rebuilt - on every 5-second tick.
 *
 * Windows 98's dwAvailPhys counts only completely unused pages. VCACHE (the disk cache) grows into almost all
 * the rest and gives pages back the moment a program needs them - Windows NT reports such memory (its standby
 * list) as available, Windows 98 does not. So here: available = Windows 98's free pages + the disk cache above
 * its minimum size, both read from Windows 98's own performance counters (HKEY_DYN_DATA\PerfStats, the numbers
 * System Monitor shows). If the counters cannot be read, the Windows 98 numbers are passed on unchanged.
 */
#include "kexnt_common.h"

FARPROC kex_prev_impl(const char *dll, const char *name);   /* gdiguard_ext.c */

typedef struct {
    DWORD dwLength, dwMemoryLoad;
    DWORDLONG ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
} MSX_;

static volatile LONG g_state;          /* 0 not tried, 1 counters work, -1 not available */
static volatile DWORD g_tick, g_cur, g_min, g_which;

static BOOL dyn_read(HKEY k, const char *name, DWORD *v)
{
    DWORD t, n = sizeof(DWORD), d = 0;
    if (RegQueryValueExA(k, name, NULL, &t, (BYTE *)&d, &n) != ERROR_SUCCESS || n != sizeof(DWORD)) return FALSE;
    *v = d; return TRUE;
}

/* disk-cache pages now and its minimum (4 KB pages); which = 1 VCACHE counters, 2 VMM counters */
int kex_memstat_cache(DWORD *cur, DWORD *min)
{
    static const char *const names[4] = { "VCACHE\\cCurPages", "VCACHE\\cMinPages", "VMM\\cpgDiskcache", "VMM\\cpgDiskcacheMin" };
    HKEY k; DWORD now = GetTickCount(), c = 0, m = 0, d; int i, which = 0;
    if (g_state < 0) return 0;
    if (g_state > 0 && now - g_tick < 1000) { *cur = g_cur; *min = g_min; return (int)g_which; }
    if (g_state == 0 && RegOpenKeyExA(HKEY_DYN_DATA, "PerfStats\\StartStat", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        for (i = 0; i < 4; i++) dyn_read(k, names[i], &d);     /* reading StartStat switches a counter on */
        RegCloseKey(k);
    }
    if (RegOpenKeyExA(HKEY_DYN_DATA, "PerfStats\\StatData", 0, KEY_READ, &k) != ERROR_SUCCESS) { g_state = -1; return 0; }
    if (dyn_read(k, names[0], &c) && dyn_read(k, names[1], &m)) which = 1;
    else if (dyn_read(k, names[2], &c) && dyn_read(k, names[3], &m)) which = 2;
    RegCloseKey(k);
    if (!which) { g_state = -1; return 0; }
    if (m > c) m = c;
    g_cur = c; g_min = m; g_which = (DWORD)which; g_tick = now; g_state = 1;
    *cur = c; *min = m;
    return which;
}

typedef BOOL (WINAPI *T_GMSX)(MSX_ *);
BOOL KEXAPI kex_GlobalMemoryStatusEx(MSX_ *m)
{
    static T_GMSX prev;
    DWORD cur = 0, min = 0;
    if (!prev) prev = (T_GMSX)(void *)kex_prev_impl("KERNEL32.DLL", "GlobalMemoryStatusEx");
    if (!prev || (void *)prev == (void *)kex_GlobalMemoryStatusEx) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    if (!prev(m)) return FALSE;
    if (m->ullAvailPageFile < (32u << 20)) {   /* build 85: build 84's renderer died of "out of memory" with 0 here */
        static LONG once; if (!InterlockedExchange(&once, 1)) {
            void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
            char win[MAX_PATH]; ULARGE_INTEGER fa, tot, fr; DWORD freemb = 0xFFFFFFFF;
            if (GetWindowsDirectoryA(win, MAX_PATH) >= 3) {
                typedef BOOL (WINAPI *T_GDFSE)(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
                T_GDFSE g = (T_GDFSE)(void *)kex_sysproc("KERNEL32.DLL", "GetDiskFreeSpaceExA");
                win[3] = 0;
                if (g && g(win, &fa, &tot, &fr)) freemb = (DWORD)(fa.QuadPart >> 20);
            }
            kex_crashnote("memory status: swap file (page file) nearly full (total MB, available MB, free MB on the Windows drive, physical available MB)",
                          (DWORD)(m->ullTotalPageFile >> 20), (DWORD)(m->ullAvailPageFile >> 20), freemb, (DWORD)(m->ullAvailPhys >> 20));
        }
    }
    if (kex_memstat_cache(&cur, &min) && cur > min && m->ullTotalPhys) {
        DWORDLONG avail = m->ullAvailPhys + (DWORDLONG)(cur - min) * 4096;
        if (avail > m->ullTotalPhys) avail = m->ullTotalPhys;
        if (avail > m->ullAvailPhys) {
            m->ullAvailPhys = avail;
            m->dwMemoryLoad = (DWORD)(100 - (avail * 100) / m->ullTotalPhys);
            {   static LONG once; if (!InterlockedExchange(&once, 1)) {
                    void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
                    kex_crashnote("memory status: disk cache counted as available (cache pages, minimum, available MB, total MB)",
                                  cur, min, (DWORD)(avail >> 20), (DWORD)(m->ullTotalPhys >> 20)); } }
        }
    }
    return TRUE;
}
