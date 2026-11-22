/*
 * yield_ext.c - KernelEx-NG: SwitchToThread, which Windows 98 only has as a "not implemented" stub.
 *
 * Build 60: the profile of a slow Chrome session (KEXPROF_chrome, 233 s) showed 44% of all running samples in
 * chrome.dll's one-line SwitchToThread wrapper (+06f7ff50, 23.7%) and in Windows 98's not-implemented stub that
 * KERNEL32!SwitchToThread jumps to (KERNEL32+1319..1360 and its SetLastError at +ffd0, together ~20%), almost all
 * on Chrome_InProcRendererThread. Windows 98's SwitchToThread returns FALSE at once with error 120 and gives the
 * CPU to nobody: every spin-wait in Chromium (locks, V8 / raster / compositor hand-offs: "yield until the other
 * thread is done") spins for its whole time slice on this single-CPU machine while the thread it waits for
 * cannot run.
 *
 * Here: Sleep(0) (gives the rest of the slice to a ready thread of the same priority), and every 8th call of a
 * thread Sleep(1) (lets lower-priority threads run too - NT's SwitchToThread can do that, 98's
 * Sleep(0) cannot; Chromium's worker and compositor threads often run below the renderer). Returns TRUE.
 */
#include "kexnt_common.h"
#include <x86intrin.h>

static volatile DWORD g_tls = TLS_OUT_OF_INDEXES;

BOOL KEXAPI kex_SwitchToThread(void)
{
    DWORD i = g_tls, n;
    if (i == TLS_OUT_OF_INDEXES) {
        DWORD t = TlsAlloc();
        if (t != TLS_OUT_OF_INDEXES && InterlockedCompareExchange((LONG volatile *)&g_tls, (LONG)t, (LONG)TLS_OUT_OF_INDEXES) != (LONG)TLS_OUT_OF_INDEXES) TlsFree(t);
        i = g_tls;
    }
    if (i == TLS_OUT_OF_INDEXES) { Sleep(0); return TRUE; }
    n = (DWORD)(ULONG_PTR)TlsGetValue(i) + 1;
    TlsSetValue(i, (LPVOID)(ULONG_PTR)n);
    Sleep((n & 7) == 0 ? 1 : 0);
    return TRUE;
}

/* build 60: Chrome's Save As task runs on a new dedicated COM thread; the build-59 thread dump had no such thread
 * at all. A failed CreateThread is silent in Chromium - here it goes to KEXCRASH with the error and the free
 * address space (each thread reserves its stack there). */
FARPROC kex_prev_impl(const char *dll, const char *name);   /* gdiguard_ext.c */
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
BOOL kex_peb_active(void);
typedef HANDLE (WINAPI *T_CT)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
HANDLE KEXAPI kex_CreateThread(LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE fn, LPVOID arg, DWORD flags, LPDWORD tid)
{
    static T_CT prev; HANDLE h;
    if (!prev) prev = (T_CT)(void *)kex_prev_impl("KERNEL32.DLL", "CreateThread");
    if (!prev || (void *)prev == (void *)kex_CreateThread) prev = (T_CT)(void *)kex_sysproc("KERNEL32.DLL", "CreateThread");
    h = prev(sa, stack, fn, arg, flags, tid);
    if (!h) {
        static LONG n; DWORD le = GetLastError();
        if (kex_peb_active() && InterlockedIncrement(&n) <= 20) {
            DWORD free_total = 0, free_max = 0, at = 0x10000; MEMORY_BASIC_INFORMATION m;
            while (at < 0x80000000UL && VirtualQuery((LPCVOID)(ULONG_PTR)at, &m, sizeof(m)) >= sizeof(m) && m.RegionSize) {
                if (m.State == MEM_FREE) { free_total += (DWORD)m.RegionSize; if (m.RegionSize > free_max) free_max = (DWORD)m.RegionSize; }
                at = (DWORD)(ULONG_PTR)m.BaseAddress + (DWORD)m.RegionSize;
            }
            kex_crashnote("CreateThread FAILED (stack size, flags, error, start address)", (DWORD)stack, flags, le, (DWORD)(ULONG_PTR)fn);
            kex_crashnote("  address space below 2 GB: free KB total, largest free block KB", free_total >> 10, free_max >> 10, 0, 0);
        }
        SetLastError(le);
    }
    return h;
}

/* build 61: timeGetTime was the single hottest spot in Chrome's profile (WINMM+62c0): Chromium's TimeTicks use it
 * (no invariant-TSC flag in the VM), and on Windows 98 each call is a VxD call into VTD.
 * Build 63 profile: still 15.5% in WINMM's timeGetTime, and the only readable return address there was
 * kex_timeGetTime itself - the 1 ms cache was not enough. Build 64: after a 1 s calibration of TSC ticks per
 * millisecond, every call is answered from the TSC: last real value + elapsed ticks / ticks-per-ms. The real
 * timeGetTime runs only when the last real call is 500 ms old (resync; drift between the two clocks stays within
 * that half second). Values never go backwards (a process-wide "highest value handed out" is kept and returned
 * when a resync lands lower). Counters go to KEXCRASH every 30 s (first 20): calls, real calls, cycles in them.
 * Build 117: resync after 10 ms of TSC instead of 500 ms. kextest (build 116) saw the cached clock 373 ms behind
 * GetTickCount over 2.5 s: the VM's TSC does not run at the calibrated rate all the time, and with a 500 ms window
 * the error grows to hundreds of ms - different in every process (each has its own cache), while Chromium
 * compares TimeTicks across processes (frame deadlines from viz). A real call costs ~1.7 us (kextest counters). */
static volatile long long g_tgt_cache;     /* high: milliseconds of the last real call, low: TSC low 32 bits then */
static volatile DWORD g_tgt_tpm;           /* TSC ticks per millisecond, 0 = not measured yet */
static volatile DWORD g_tgt_last;          /* highest value handed out */
static volatile LONG g_tgt_calls, g_tgt_real, g_tgt_kcyc, g_tgt_notes; static volatile DWORD g_tgt_note_ms;
static DWORD g_tgt_t0, g_tgt_v0; static unsigned long long g_tgt_tsc0;
typedef DWORD (WINAPI *T_TGT)(void);
static DWORD tgt_mono(DWORD v)
{
    for (;;) {
        DWORD l = g_tgt_last;
        if ((LONG)(v - l) <= 0) return l;
        if (InterlockedCompareExchange((LONG volatile *)&g_tgt_last, (LONG)v, (LONG)l) == (LONG)l) return v;
    }
}
DWORD KEXAPI kex_timeGetTime(void)
{
    static T_TGT real;
    unsigned long long t = __rdtsc(), t2;
    long long c, nc; DWORD v, tpm = g_tgt_tpm;
    InterlockedIncrement(&g_tgt_calls);
    if (tpm) {
        DWORD d;
        c = __sync_val_compare_and_swap(&g_tgt_cache, 0, 0);            /* atomic 64-bit read */
        d = (DWORD)t - (DWORD)c;
        if (d < tpm * 10u) return tgt_mono((DWORD)((unsigned long long)c >> 32) + d / tpm);
    }
    if (!real && !(real = (T_TGT)(void *)kex_sysproc("WINMM.DLL", "timeGetTime"))) return GetTickCount();
    InterlockedIncrement(&g_tgt_real);
    v = real();
    t2 = __rdtsc();
    InterlockedExchangeAdd(&g_tgt_kcyc, (LONG)((t2 - t) >> 10));
    if (!tpm) {
        if (!g_tgt_t0) { g_tgt_tsc0 = t; g_tgt_v0 = v; g_tgt_t0 = 1; }
        else if (v - g_tgt_v0 >= 1000) {
            unsigned long long per_ms = (t - g_tgt_tsc0) / (v - g_tgt_v0);
            if (per_ms >= 2000 && per_ms < 8000000) {                  /* 2 MHz .. 8 GHz; tpm*500 fits 32 bits */
                nc = (long long)(((unsigned long long)v << 32) | (DWORD)t);
                __sync_lock_test_and_set(&g_tgt_cache, nc);
                g_tgt_tpm = (DWORD)per_ms;
            }
        }
        return tgt_mono(v);
    }
    nc = (long long)(((unsigned long long)v << 32) | (DWORD)t);
    for (;;) {                                  /* newest real call wins (by TSC) */
        c = __sync_val_compare_and_swap(&g_tgt_cache, 0, 0);
        if ((LONG)((DWORD)t - (DWORD)c) < 0) break;
        if (__sync_bool_compare_and_swap(&g_tgt_cache, c, nc)) break;
    }
    if (v - g_tgt_note_ms >= 30000 && g_tgt_notes < 20) {
        void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
        g_tgt_note_ms = v; g_tgt_notes++;
        kex_crashnote("timeGetTime (last 30 s): calls, real Windows calls, K-cycles in them, TSC ticks per ms",
                      (DWORD)InterlockedExchange(&g_tgt_calls, 0), (DWORD)InterlockedExchange(&g_tgt_real, 0),
                      (DWORD)InterlockedExchange(&g_tgt_kcyc, 0), tpm);
    }
    return tgt_mono(v);
}
