/*
 * kernel32_ext.c - KernelEx-NG Phase 1: kernel32 APIs missing on Windows 98 SE.
 * Rule: call the real Win98 API where semantics match, emulate otherwise,
 * fail with a proper error code (never silent garbage).
 */
#include "kernel32_ext.h"

/* ---------------- 64-bit tick count (Win98 GetTickCount wraps after 49.7 days) ------------- */
static volatile LONGLONG g_tick_state;   /* high 32 = wrap count, low 32 = last raw tick */

ULONGLONG KEXAPI kex_GetTickCount64(void)
{
    for (;;) {
        LONGLONG old = g_tick_state;                 /* 8-byte read via cmpxchg8b below */
        old = __sync_val_compare_and_swap(&g_tick_state, old, old);
        DWORD last = (DWORD)old, wraps = (DWORD)((ULONGLONG)old >> 32);
        DWORD now = GetTickCount();
        if (now < last && (last - now) > 0x80000000UL)   /* genuine wrap, not a race */
            wraps++;
        LONGLONG nv = ((LONGLONG)wraps << 32) | now;
        if (nv == old || __sync_bool_compare_and_swap(&g_tick_state, old, nv))
            return ((ULONGLONG)wraps << 32) | now;
    }
}

/* ---------------- WOW64: Win98 is native 32-bit, never WOW64 ---------------- */
BOOL KEXAPI kex_IsWow64Process(HANDLE hProcess, PBOOL Wow64Process)
{
    DWORD code;
    if (!Wow64Process || IsBadWritePtr(Wow64Process, sizeof(BOOL))) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    /* validate handle like NT does (pseudo handle -1 is always valid) */
    if (hProcess != GetCurrentProcess() && !GetExitCodeProcess(hProcess, &code)) {
        SetLastError(ERROR_INVALID_HANDLE); return FALSE;
    }
    *Wow64Process = FALSE;
    return TRUE;
}

BOOL KEXAPI kex_IsWow64Process2(HANDLE hProcess, USHORT *pProcessMachine, USHORT *pNativeMachine)
{
    BOOL wow;
    if (!pProcessMachine) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!kex_IsWow64Process(hProcess, &wow)) return FALSE;
    *pProcessMachine = IMAGE_FILE_MACHINE_UNKNOWN;      /* "not a WOW64 process" */
    if (pNativeMachine) *pNativeMachine = IMAGE_FILE_MACHINE_I386;
    return TRUE;
}

/* ---------------- Critical sections ----------------
 * Win98 CRITICAL_SECTION is a wrapper around a K32 object; spin counts are
 * meaningless on a uniprocessor kernel, so we validate and ignore them.
 * InitializeCriticalSection on 9x can raise on OOM; we catch nothing (no SEH in GCC)
 * but pre-check the pointer so the common failure is reported, not crashed. */
#define CS_VALID_FLAGS (0x01000000 /*NO_DEBUG_INFO*/ | 0x02000000 /*DYNAMIC_SPIN*/ | \
                        0x04000000 /*STATIC_INIT*/ | 0x08000000 /*RESOURCE_TYPE*/ | 0x10000000 /*FORCE_DEBUG_INFO*/)

BOOL KEXAPI kex_InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION cs, DWORD spin)
{
    (void)spin;
    if (!cs || IsBadWritePtr(cs, sizeof(*cs))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    { VOID KEXAPI kex_InitializeCriticalSection(LPCRITICAL_SECTION cs); kex_InitializeCriticalSection(cs); }   /* ntcs_ext.c (build 132) */
    return TRUE;
}

BOOL KEXAPI kex_InitializeCriticalSectionEx(LPCRITICAL_SECTION cs, DWORD spin, DWORD flags)
{
    if (flags & ~CS_VALID_FLAGS) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (spin & 0xFF000000UL)     { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return kex_InitializeCriticalSectionAndSpinCount(cs, spin);
}

DWORD KEXAPI kex_SetCriticalSectionSpinCount(LPCRITICAL_SECTION cs, DWORD spin)
{
    (void)cs; (void)spin;
    return 0;   /* previous spin count: always 0 on 9x */
}

/* ---------------- Stack guarantee ----------------
 * 9x grows stacks through guard pages and has no "guaranteed" overflow area.
 * We remember the requested value per thread so the in/out contract holds. */
static DWORD g_guarantee_tls = TLS_OUT_OF_INDEXES;

BOOL KEXAPI kex_SetThreadStackGuarantee(PULONG StackSizeInBytes)
{
    ULONG prev;
    if (!StackSizeInBytes) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (g_guarantee_tls == TLS_OUT_OF_INDEXES) { *StackSizeInBytes = 0; return TRUE; }
    prev = (ULONG)(ULONG_PTR)TlsGetValue(g_guarantee_tls);
    if (*StackSizeInBytes > prev)
        TlsSetValue(g_guarantee_tls, (LPVOID)(ULONG_PTR)((*StackSizeInBytes + 4095) & ~4095UL));
    *StackSizeInBytes = prev;
    return TRUE;
}

SIZE_T KEXAPI kex_GetLargePageMinimum(void) { return 0; }   /* no large-page support */

/* Uniprocessor: a locked RMW is a full serializing barrier for this CPU and DMA-coherent. */
VOID KEXAPI kex_FlushProcessWriteBuffers(void)
{
    __asm__ __volatile__("lock; orl $0, (%%esp)" ::: "memory");
}

/* ---------------- High-resolution time ----------------
 * Win98 QueryPerformanceCounter = 1.193182 MHz PIT (or TSC on some HALs).
 * Precise system time = GetSystemTimeAsFileTime baseline + QPC delta, re-based
 * whenever the coarse clock jumps (>1 s drift, e.g. user changed the clock),
 * and clamped so it never runs backwards. */
static LARGE_INTEGER g_qpf;
static CRITICAL_SECTION g_time_cs;
static ULONGLONG g_base_ft, g_base_qpc, g_last_precise;
static BOOL g_time_ok;

static ULONGLONG qpc_to_100ns(ULONGLONG ticks)
{
    ULONGLONG f = (ULONGLONG)g_qpf.QuadPart;
    return (ticks / f) * 10000000ULL + ((ticks % f) * 10000000ULL) / f;
}

static ULONGLONG ft_now(void)
{
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    return ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

VOID KEXAPI kex_GetSystemTimePreciseAsFileTime(LPFILETIME out)
{
    ULONGLONG coarse = ft_now(), precise;
    LARGE_INTEGER q;
    if (!out) return;
    if (!g_time_ok || !QueryPerformanceCounter(&q)) {
        out->dwLowDateTime = (DWORD)coarse; out->dwHighDateTime = (DWORD)(coarse >> 32); return;
    }
    EnterCriticalSection(&g_time_cs);
    precise = g_base_ft + qpc_to_100ns((ULONGLONG)q.QuadPart - g_base_qpc);
    /* Re-sync only on a real clock change. The 9x system clock advances in ~55 ms steps, so the precise
     * value is legitimately up to one step ahead of it; re-syncing at 32 ms (as before) dragged the time
     * backwards, the monotonic clamp then froze it ("precise time advances (0 us)", test 03:46). */
    if (precise + 10000000ULL < coarse || precise > coarse + 10000000ULL) {
        g_base_ft = coarse; g_base_qpc = (ULONGLONG)q.QuadPart; precise = coarse;   /* clock was set: re-sync */
    }
    if (precise < g_last_precise) precise = g_last_precise;                          /* monotonic */
    g_last_precise = precise;
    LeaveCriticalSection(&g_time_cs);
    out->dwLowDateTime = (DWORD)precise; out->dwHighDateTime = (DWORD)(precise >> 32);
}

/* Interrupt time in 100 ns units since boot. 9x has no sleep-bias accounting, so
 * biased == unbiased. Falls back to GetTickCount64 if QPC is unavailable. */
BOOL KEXAPI kex_QueryUnbiasedInterruptTime(PULONGLONG UnbiasedTime)
{
    LARGE_INTEGER q;
    if (!UnbiasedTime) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (g_time_ok && QueryPerformanceCounter(&q))
        *UnbiasedTime = qpc_to_100ns((ULONGLONG)q.QuadPart);
    else
        *UnbiasedTime = kex_GetTickCount64() * 10000ULL;
    return TRUE;
}

BOOL kex_k32ext_init(void)
{
    LARGE_INTEGER q;
    InitializeCriticalSection(&g_time_cs);
    g_guarantee_tls = TlsAlloc();
    g_time_ok = QueryPerformanceFrequency(&g_qpf) && g_qpf.QuadPart && QueryPerformanceCounter(&q);
    if (g_time_ok) { g_base_ft = ft_now(); g_base_qpc = (ULONGLONG)q.QuadPart; }
    g_tick_state = GetTickCount();
    return TRUE;
}
