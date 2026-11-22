/*
 * sync_ext.c - KernelEx-NG Phase 2: NT6+ synchronization primitives for Windows 98 SE.
 *
 * Win98 has no keyed events and no futex, so everything is built on one primitive:
 * a "parking lot" (kex_park / kex_unpark) = hash table of wait queues keyed by address.
 * Each waiting thread sleeps on its own auto-reset event (created lazily, kept in TLS,
 * closed on DLL_THREAD_DETACH). The value check and the enqueue happen under the
 * bucket lock, and wakers modify the value BEFORE taking the bucket lock, so a wake
 * can never be lost (classic futex contract).
 *
 * On top of it:
 *   WaitOnAddress / WakeByAddressSingle / WakeByAddressAll   (exact semantics)
 *   SRW locks       - pointer-sized word: bit0 exclusive, bit1 waiters, bits2+ shared count
 *   Condition vars  - pointer-sized sequence counter + park on it
 *   InitOnce        - pointer-sized: 0 / 1 sync-in-progress / 3 async-in-progress / ctx|2 done
 *
 * Known limits (documented in ARCHITECTURE.md):
 *   - SRW is reader-preferring (a stream of readers can delay a writer); no recursion
 *     detection (same as NT: recursive acquire deadlocks).
 *   - Build 61: SRW release wakes ONE exclusive waiter (or every waiting reader when the first in the queue
 *     is a reader) and keeps the waiter bit while others remain queued. The old wake-all made every release of
 *     a contended lock (Chrome's thread-pool / allocator locks: the build-60 dump had 12 threads parked on SRW
 *     locks at once) wake all of them; on one CPU each woke, lost the race and parked again.
 */
#include "sync_ext.h"

#define KEX_NBUCKETS 128               /* power of two */

typedef struct kex_waiter {
    struct kex_waiter *next, *prev;
    volatile void     *addr;
    HANDLE             ev;
    volatile LONG      queued;
    int                kind;           /* 0 plain, 1 SRW exclusive, 2 SRW shared */
} kex_waiter;

typedef struct {
    CRITICAL_SECTION cs;
    kex_waiter       head;             /* circular list sentinel */
} kex_bucket;

static kex_bucket g_buckets[KEX_NBUCKETS];
static DWORD      g_ev_tls = TLS_OUT_OF_INDEXES;
static BOOL       g_sync_ok;

static kex_bucket *bucket_of(volatile void *addr)
{
    ULONG h = (ULONG)(ULONG_PTR)addr;
    h = (h >> 2) * 2654435761UL;       /* Knuth multiplicative hash */
    return &g_buckets[h >> (32 - 7)];
}

static HANDLE thread_event(void)
{
    HANDLE ev = (HANDLE)TlsGetValue(g_ev_tls);
    if (!ev) {
        ev = CreateEventA(NULL, FALSE, FALSE, NULL);   /* auto-reset */
        if (ev) TlsSetValue(g_ev_tls, ev);
    }
    return ev;
}

/* Atomic snapshot compare of 1/2/4/8 bytes. 8-byte uses cmpxchg8b (Pentium+). */
static BOOL value_equals(volatile void *addr, const void *cmp, SIZE_T size)
{
    switch (size) {
    case 1: return *(volatile BYTE  *)addr == *(const BYTE  *)cmp;
    case 2: return *(volatile WORD  *)addr == *(const WORD  *)cmp;
    case 4: return *(volatile DWORD *)addr == *(const DWORD *)cmp;
    case 8: return (ULONGLONG)__sync_val_compare_and_swap((volatile LONGLONG *)addr, 0, 0)
                   == *(const ULONGLONG *)cmp;
    }
    return FALSE;
}

/* Returns 1 = woken or value already differed, 0 = timed out, -1 = no event available. */
static int kex_park_k(volatile void *addr, const void *cmp, SIZE_T size, DWORD ms, int kind)
{
    kex_bucket *b = bucket_of(addr);
    kex_waiter w;
    DWORD r;

    w.ev = thread_event();
    if (!w.ev) return -1;
    w.addr = addr;
    w.kind = kind;

    EnterCriticalSection(&b->cs);
    if (!value_equals(addr, cmp, size)) { LeaveCriticalSection(&b->cs); return 1; }
    if (ms == 0)                         { LeaveCriticalSection(&b->cs); return 0; }
    w.queued = 1;
    w.prev = b->head.prev; w.next = &b->head;          /* FIFO: append at tail */
    b->head.prev->next = &w; b->head.prev = &w;
    LeaveCriticalSection(&b->cs);

    r = WaitForSingleObject(w.ev, ms);
    if (r == WAIT_OBJECT_0) return 1;

    /* Timeout (or wait failure): dequeue ourselves unless a waker already did. */
    EnterCriticalSection(&b->cs);
    if (w.queued) {
        w.prev->next = w.next; w.next->prev = w.prev;
        LeaveCriticalSection(&b->cs);
        return 0;
    }
    LeaveCriticalSection(&b->cs);
    /* A waker dequeued us and SetEvent'ed under the lock: consume that signal so it
     * cannot leak into this thread's next wait. */
    WaitForSingleObject(w.ev, INFINITE);
    return 1;
}

static int kex_park(volatile void *addr, const void *cmp, SIZE_T size, DWORD ms) { return kex_park_k(addr, cmp, size, ms, 0); }

/* SRW release: wake the first waiter; if it is a reader, every queued reader. Clear the waiter bit (under the
 * bucket lock, so no new waiter can slip in between) when nobody is left queued on this lock. */
#define SRW_WAIT_BIT 2L
static void srw_wake(volatile LONG *addr)
{
    kex_bucket *b = bucket_of((volatile void *)addr);
    kex_waiter *w, *n;
    int first = 0, remaining = 0;
    EnterCriticalSection(&b->cs);
    for (w = b->head.next; w != &b->head; w = n) {
        n = w->next;
        if (w->addr != (volatile void *)addr) continue;
        if (!first || (first == 2 && w->kind == 2)) {
            if (!first) first = w->kind == 2 ? 2 : 1;
            w->prev->next = w->next; w->next->prev = w->prev;
            w->queued = 0;
            SetEvent(w->ev);
        } else remaining = 1;
    }
    if (!remaining) __sync_fetch_and_and(addr, ~SRW_WAIT_BIT);
    LeaveCriticalSection(&b->cs);
}

static void kex_unpark(volatile void *addr, BOOL all)
{
    kex_bucket *b = bucket_of(addr);
    kex_waiter *w, *n;
    EnterCriticalSection(&b->cs);
    for (w = b->head.next; w != &b->head; w = n) {
        n = w->next;
        if (w->addr != addr) continue;
        w->prev->next = w->next; w->next->prev = w->prev;
        w->queued = 0;
        SetEvent(w->ev);                /* under the lock: see kex_park timeout path */
        if (!all) break;
    }
    LeaveCriticalSection(&b->cs);
}

/* Blocking park used by the lock primitives: they must never fail, so if the per-thread
 * event cannot be created (out of kernel memory) we degrade to a polite spin. */
static void park_forever_k(volatile void *addr, LONG expected, int kind)
{
    DWORD le = GetLastError();
    if (kex_park_k(addr, &expected, 4, INFINITE, kind) < 0) Sleep(1);
    SetLastError(le);
}
static void park_forever(volatile void *addr, LONG expected)
{
    DWORD le = GetLastError();
    if (kex_park(addr, &expected, 4, INFINITE) < 0) Sleep(1);
    SetLastError(le);                   /* locks must not clobber the caller's last error */
}

/* ------------------------------ WaitOnAddress ------------------------------ */
BOOL KEXAPI kex_WaitOnAddress(volatile VOID *Address, PVOID CompareAddress, SIZE_T AddressSize, DWORD dwMilliseconds)
{
    int r;
    if (!Address || !CompareAddress ||
        (AddressSize != 1 && AddressSize != 2 && AddressSize != 4 && AddressSize != 8)) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    r = kex_park(Address, CompareAddress, AddressSize, dwMilliseconds);
    if (r > 0) return TRUE;
    SetLastError(r == 0 ? ERROR_TIMEOUT : ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
}

VOID KEXAPI kex_WakeByAddressSingle(PVOID Address) { if (Address) kex_unpark(Address, FALSE); }
VOID KEXAPI kex_WakeByAddressAll(PVOID Address)    { if (Address) kex_unpark(Address, TRUE); }

/* --------------------------------- SRW locks -------------------------------- */
#define SRW_EXCL 1L
#define SRW_WAIT 2L
#define SRW_SH   4L
#define SRW_P(l) ((volatile LONG *)&(l)->Ptr)
#define CAS(p, o, n) __sync_bool_compare_and_swap((p), (o), (n))

VOID KEXAPI kex_InitializeSRWLock(PSRWLOCK l) { l->Ptr = NULL; }

VOID KEXAPI kex_AcquireSRWLockExclusive(PSRWLOCK l)
{
    volatile LONG *p = SRW_P(l);
    if (CAS(p, 0, SRW_EXCL)) return;
    for (;;) {
        LONG v = *p;
        if (!(v & ~SRW_WAIT)) { if (CAS(p, v, v | SRW_EXCL)) return; continue; }
        if (!(v & SRW_WAIT)) { if (!CAS(p, v, v | SRW_WAIT)) continue; v |= SRW_WAIT; }
        park_forever_k(p, v, 1);
    }
}

VOID KEXAPI kex_AcquireSRWLockShared(PSRWLOCK l)
{
    volatile LONG *p = SRW_P(l);
    for (;;) {
        LONG v = *p;
        if (!(v & SRW_EXCL)) { if (CAS(p, v, v + SRW_SH)) return; continue; }
        if (!(v & SRW_WAIT)) { if (!CAS(p, v, v | SRW_WAIT)) continue; v |= SRW_WAIT; }
        park_forever_k(p, v, 2);
    }
}

VOID KEXAPI kex_ReleaseSRWLockExclusive(PSRWLOCK l)
{
    volatile LONG *p = SRW_P(l);
    LONG v = __sync_fetch_and_and(p, ~SRW_EXCL);      /* the waiter bit stays: srw_wake decides */
    if (v & SRW_WAIT) srw_wake(p);
}

VOID KEXAPI kex_ReleaseSRWLockShared(PSRWLOCK l)
{
    volatile LONG *p = SRW_P(l);
    for (;;) {
        LONG v = *p, nv = v - SRW_SH;
        if (!CAS(p, v, nv)) continue;
        if (nv == SRW_WAIT) srw_wake(p);    /* last reader out, someone waits */
        return;
    }
}

BOOLEAN KEXAPI kex_TryAcquireSRWLockExclusive(PSRWLOCK l)
{
    volatile LONG *p = SRW_P(l);
    for (;;) {
        LONG v = *p;
        if (v & ~SRW_WAIT) return FALSE;
        if (CAS(p, v, v | SRW_EXCL)) return TRUE;
    }
}

BOOLEAN KEXAPI kex_TryAcquireSRWLockShared(PSRWLOCK l)
{
    volatile LONG *p = SRW_P(l);
    for (;;) {
        LONG v = *p;
        if (v & SRW_EXCL) return FALSE;
        if (CAS(p, v, v + SRW_SH)) return TRUE;
    }
}

/* ----------------------------- Condition variables --------------------------- */
#define CV_P(c) ((volatile LONG *)&(c)->Ptr)

VOID KEXAPI kex_InitializeConditionVariable(PCONDITION_VARIABLE c) { c->Ptr = NULL; }

static BOOL cv_wait(PCONDITION_VARIABLE c, LONG seq, DWORD ms)
{
    int r = kex_park(CV_P(c), &seq, 4, ms);
    if (r < 0) { if (ms) Sleep(1); r = 1; }   /* no event: a spurious wake is legal for CVs */
    return r > 0;
}

BOOL KEXAPI kex_SleepConditionVariableSRW(PCONDITION_VARIABLE c, PSRWLOCK l, DWORD ms, ULONG flags)
{
    LONG seq;
    BOOL ok, shared = (flags & CONDITION_VARIABLE_LOCKMODE_SHARED) != 0;
    if (flags & ~CONDITION_VARIABLE_LOCKMODE_SHARED) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    seq = *CV_P(c);
    if (shared) kex_ReleaseSRWLockShared(l); else kex_ReleaseSRWLockExclusive(l);
    ok = cv_wait(c, seq, ms);
    if (shared) kex_AcquireSRWLockShared(l); else kex_AcquireSRWLockExclusive(l);
    if (!ok) { SetLastError(ERROR_TIMEOUT); return FALSE; }
    return TRUE;
}

BOOL KEXAPI kex_SleepConditionVariableCS(PCONDITION_VARIABLE c, PCRITICAL_SECTION cs, DWORD ms)
{
    LONG seq = *CV_P(c);
    BOOL ok;
    LeaveCriticalSection(cs);
    ok = cv_wait(c, seq, ms);
    EnterCriticalSection(cs);
    if (!ok) { SetLastError(ERROR_TIMEOUT); return FALSE; }
    return TRUE;
}

VOID KEXAPI kex_WakeConditionVariable(PCONDITION_VARIABLE c)
{
    __sync_fetch_and_add(CV_P(c), 1);
    kex_unpark(CV_P(c), FALSE);
}

VOID KEXAPI kex_WakeAllConditionVariable(PCONDITION_VARIABLE c)
{
    __sync_fetch_and_add(CV_P(c), 1);
    kex_unpark(CV_P(c), TRUE);
}

/* ---------------------------------- InitOnce --------------------------------- */
#define IO_SYNC  1L
#define IO_DONE  2L
#define IO_ASYNC 3L
#define IO_P(o) ((volatile LONG *)&(o)->Ptr)
#ifndef INIT_ONCE_CHECK_ONLY
#define INIT_ONCE_CHECK_ONLY  0x1
#define INIT_ONCE_ASYNC       0x2
#define INIT_ONCE_INIT_FAILED 0x4
#endif

VOID KEXAPI kex_InitOnceInitialize(PINIT_ONCE o) { o->Ptr = NULL; }

BOOL KEXAPI kex_InitOnceBeginInitialize(LPINIT_ONCE o, DWORD flags, PBOOL pending, LPVOID *ctx)
{
    volatile LONG *p = IO_P(o);
    if (!pending || (flags & ~(INIT_ONCE_CHECK_ONLY | INIT_ONCE_ASYNC)) ||
        flags == (INIT_ONCE_CHECK_ONLY | INIT_ONCE_ASYNC)) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    for (;;) {
        LONG v = *p;
        if ((v & 3) == IO_DONE) {
            *pending = FALSE;
            if (ctx) *ctx = (LPVOID)(ULONG_PTR)(v & ~3L);
            return TRUE;
        }
        if (flags & INIT_ONCE_CHECK_ONLY) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
        if (flags & INIT_ONCE_ASYNC) {
            if (v == IO_SYNC) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
            if (v == 0 && !CAS(p, 0, IO_ASYNC)) continue;
            *pending = TRUE;
            return TRUE;
        }
        if (v == 0) { if (CAS(p, 0, IO_SYNC)) { *pending = TRUE; return TRUE; } continue; }
        if (v == IO_ASYNC) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        park_forever(p, v);             /* another thread is running the initializer */
    }
}

BOOL KEXAPI kex_InitOnceComplete(LPINIT_ONCE o, DWORD flags, LPVOID ctx)
{
    volatile LONG *p = IO_P(o);
    LONG v = *p, done = (LONG)(ULONG_PTR)ctx | IO_DONE;
    if (((ULONG_PTR)ctx & 3) || (flags & ~(INIT_ONCE_ASYNC | INIT_ONCE_INIT_FAILED)) ||
        flags == (INIT_ONCE_ASYNC | INIT_ONCE_INIT_FAILED)) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    if (flags & INIT_ONCE_INIT_FAILED) {
        if (v != IO_SYNC) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
        __sync_lock_test_and_set(p, 0);
        kex_unpark(p, TRUE);
        return TRUE;
    }
    if (flags & INIT_ONCE_ASYNC) {
        if (v != IO_ASYNC) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        if (!CAS(p, IO_ASYNC, done)) { SetLastError(ERROR_ALREADY_EXISTS); return FALSE; }
        return TRUE;
    }
    if (v != IO_SYNC) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    __sync_lock_test_and_set(p, done);
    kex_unpark(p, TRUE);
    return TRUE;
}

BOOL KEXAPI kex_InitOnceExecuteOnce(PINIT_ONCE o, PINIT_ONCE_FN fn, PVOID param, LPVOID *ctx)
{
    BOOL pending;
    LPVOID c = NULL;
    if (!kex_InitOnceBeginInitialize(o, 0, &pending, ctx)) return FALSE;
    if (!pending) return TRUE;
    if (fn && fn(o, param, &c)) {
        kex_InitOnceComplete(o, 0, c);
        if (ctx) *ctx = c;
        return TRUE;
    }
    kex_InitOnceComplete(o, INIT_ONCE_INIT_FAILED, NULL);
    return FALSE;
}

/* ----------------------------------- setup ----------------------------------- */
BOOL kex_sync_init(void)
{
    int i;
    g_ev_tls = TlsAlloc();
    if (g_ev_tls == TLS_OUT_OF_INDEXES) return FALSE;
    for (i = 0; i < KEX_NBUCKETS; i++) {
        InitializeCriticalSection(&g_buckets[i].cs);
        g_buckets[i].head.next = g_buckets[i].head.prev = &g_buckets[i].head;
    }
    g_sync_ok = TRUE;
    return TRUE;
}

void kex_sync_thread_detach(void)
{
    HANDLE ev;
    if (!g_sync_ok) return;
    ev = (HANDLE)TlsGetValue(g_ev_tls);
    if (ev) { TlsSetValue(g_ev_tls, NULL); CloseHandle(ev); }
}
