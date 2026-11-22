/* proctime_ext.c - process CPU times for Windows 98 (2026-11-02).
 *
 * Windows 98 has no GetProcessTimes (the KERNEL32 export fails with ERROR_CALL_NOT_IMPLEMENTED) and no cycle
 * counters per process. Chromium 159 asks for both while starting (base::ProcessMetrics::GetCumulativeCPUUsage)
 * and treats a failure on a valid handle as impossible: NOTREACHED at process_metrics_win.cc:140.
 *
 * GetProcessTimes: creation time = when kexnt attached to the process (for the calling process) or the earliest
 * thread creation time KernelEx reports; kernel/user time = sum of the process's threads (Toolhelp thread list,
 * KernelEx OpenThread + GetThreadTimes); exit time = now when the process has ended, else 0.
 * QueryProcessCycleTime / QueryThreadCycleTime: those times converted to TSC cycles with the TSC rate measured
 * against QueryPerformanceCounter since kexnt attached. Only documented behaviour, nothing taken from Windows. */
#include <windows.h>
#include <tlhelp32.h>

FARPROC kex_prev_impl(const char *dll, const char *name);   /* gdiguard_ext.c */
#define KEXAPI WINAPI

typedef HANDLE (WINAPI *T_OT)(DWORD, BOOL, DWORD);
typedef BOOL (WINAPI *T_GTT)(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME);
typedef DWORD (WINAPI *T_GPI)(HANDLE);
typedef DWORD (WINAPI *T_GTI)(HANDLE);

static FILETIME g_start_ft;
static unsigned __int64 g_start_tsc;
static LARGE_INTEGER g_start_qpc, g_qpf;

static unsigned __int64 rdtsc(void) { unsigned int lo, hi; __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi)); return ((unsigned __int64)hi << 32) | lo; }
static int has_tsc(void)
{
    unsigned int a, b, c, d;
    __asm__ volatile ("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1));
    return (d >> 4) & 1;
}
static int g_tsc_ok;

void kex_proctime_init(void)
{
    GetSystemTimeAsFileTime(&g_start_ft);
    g_tsc_ok = has_tsc();
    if (!QueryPerformanceFrequency(&g_qpf)) g_qpf.QuadPart = 0;
    QueryPerformanceCounter(&g_start_qpc);
    if (g_tsc_ok) g_start_tsc = rdtsc();
}

/* TSC cycles per 100 ns, measured since attach (at least 20 ms of it); 0 when not known yet */
static double tsc_per_100ns(void)
{
    static double rate;
    LARGE_INTEGER q; unsigned __int64 t; double secs;
    if (rate > 0) return rate;
    if (!g_tsc_ok || !g_qpf.QuadPart) return 0;
    QueryPerformanceCounter(&q); t = rdtsc();
    secs = (double)(q.QuadPart - g_start_qpc.QuadPart) / (double)g_qpf.QuadPart;
    if (secs < 0.02) { Sleep(25); QueryPerformanceCounter(&q); t = rdtsc(); secs = (double)(q.QuadPart - g_start_qpc.QuadPart) / (double)g_qpf.QuadPart; }
    if (secs <= 0) return 0;
    rate = (double)(t - g_start_tsc) / (secs * 1e7);
    return rate;
}

static unsigned __int64 ft64(const FILETIME *f) { return ((unsigned __int64)f->dwHighDateTime << 32) | f->dwLowDateTime; }
static void set_ft(LPFILETIME f, unsigned __int64 v) { f->dwLowDateTime = (DWORD)v; f->dwHighDateTime = (DWORD)(v >> 32); }

static DWORD pid_of(HANDLE h)
{
    static T_GPI gpi;
    if (h == GetCurrentProcess() || h == (HANDLE)(LONG_PTR)-1) return GetCurrentProcessId();
    if (!gpi) gpi = (T_GPI)(void *)kex_prev_impl("KERNEL32.DLL", "GetProcessId");
    return gpi ? gpi(h) : 0;
}

/* sums the threads of process pid; returns FALSE when nothing could be read */
static BOOL sum_threads(DWORD pid, unsigned __int64 *created, unsigned __int64 *kern, unsigned __int64 *user)
{
    static T_OT ot; static T_GTT gtt;
    HANDLE snap; THREADENTRY32 te; BOOL any = FALSE;
    *created = 0; *kern = 0; *user = 0;
    if (!ot) ot = (T_OT)(void *)kex_prev_impl("KERNEL32.DLL", "OpenThread");
    if (!gtt) gtt = (T_GTT)(void *)kex_prev_impl("KERNEL32.DLL", "GetThreadTimes");
    if (!ot || !gtt || !pid) return FALSE;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID == pid) {
            HANDLE th = ot(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (th) {
                FILETIME c, e, k, u;
                if (gtt(th, &c, &e, &k, &u)) {
                    unsigned __int64 cv = ft64(&c);
                    if (cv && (!*created || cv < *created)) *created = cv;
                    *kern += ft64(&k); *user += ft64(&u); any = TRUE;
                }
                CloseHandle(th);
            }
        }
        te.dwSize = sizeof(te);
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
    return any;
}

BOOL KEXAPI kex_GetProcessTimes(HANDLE h, LPFILETIME c, LPFILETIME e, LPFILETIME k, LPFILETIME u)
{
    DWORD code, pid; unsigned __int64 cr, kt, ut;
    if (GetProcessTimes(h, c, e, k, u)) return TRUE;           /* a Windows that has it */
    if (!c || !e || !k || !u) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!GetExitCodeProcess(h, &code)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    pid = pid_of(h);
    if (!sum_threads(pid, &cr, &kt, &ut)) { cr = 0; kt = 0; ut = 0; }
    if (pid == GetCurrentProcessId() || !cr) cr = ft64(&g_start_ft);
    set_ft(c, cr); set_ft(k, kt); set_ft(u, ut);
    if (code != STILL_ACTIVE) GetSystemTimeAsFileTime(e); else set_ft(e, 0);
    return TRUE;
}

BOOL KEXAPI kex_QueryProcessCycleTime(HANDLE h, PULONG64 cycles)
{
    FILETIME c, e, k, u;
    if (!cycles) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!kex_GetProcessTimes(h, &c, &e, &k, &u)) return FALSE;
    *cycles = (ULONG64)((double)(ft64(&k) + ft64(&u)) * tsc_per_100ns());
    return TRUE;
}

BOOL KEXAPI kex_QueryThreadCycleTime(HANDLE h, PULONG64 cycles)
{
    static T_GTT gtt;
    FILETIME c, e, k, u;
    if (!cycles) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!gtt) gtt = (T_GTT)(void *)kex_prev_impl("KERNEL32.DLL", "GetThreadTimes");
    if (!gtt) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
    if (!gtt(h, &c, &e, &k, &u)) {
        if (GetLastError() != ERROR_BUSY) return FALSE;        /* KernelEx: thread not fully set up yet */
        *cycles = 0; return TRUE;
    }
    *cycles = (ULONG64)((double)(ft64(&k) + ft64(&u)) * tsc_per_100ns());
    return TRUE;
}

/* build 87: exported helper for notes (shm_ext.c: which process received a pipe end) */
DWORD kex_pid_of(HANDLE ph) { return pid_of(ph); }
