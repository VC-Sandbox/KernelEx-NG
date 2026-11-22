/* wait_ext.c - thread-pool waits: RegisterWaitForSingleObject(Ex), UnregisterWait(Ex) (2026-11-10, builds 29-30),
 * plus DeleteTimerQueueTimer's completion event.
 *
 * KernelEx 4.5.2 (kexbases ThreadPool.c) has two problems Chromium runs into:
 *  - UnregisterWaitEx(wait, hEvent) never signals hEvent when no callback is pending (NT always does).
 *    Chromium's base::win::ObjectWatcher::StopWatching waits on that event: build 28's thread snapshot showed
 *    "NetworkService" stuck there forever, so no page could load.
 *  - Once waits really get unregistered, its wait threads race (APC-driven list edits while a wait is in
 *    progress, items freed twice): build 29 died 15 s in with a stack overflow in WaitThreadProc ->
 *    WaitThreadWait, alloca(nItems * 8) with a corrupted negative nItems.
 * So kexnt has its own implementation:
 *  - waits live in a fixed table of slots (never freed memory: a wait thread that still holds a slot number
 *    from before an unregister finds it stale by its generation count, under the lock);
 *  - wait threads, each watching up to 62 objects plus its own wake-up event; a thread rebuilds its handle
 *    list whenever the set changes; the same handle is never put twice into one thread's list;
 *  - WT_EXECUTEINWAITTHREAD callbacks run on the wait thread, others through QueueUserWorkItem;
 *    WT_EXECUTEONLYONCE removes the wait before its callback runs; timeouts are handled per wait;
 *  - UnregisterWaitEx: NULL = don't wait (ERROR_IO_PENDING while a callback runs), INVALID_HANDLE_VALUE = wait
 *    for running callbacks (except from inside its own callback), an event = signalled when the last callback
 *    has finished (at once if none runs) - the NT rules.
 */
#include "kexnt_common.h"
FARPROC kex_prev_impl(const char *dll, const char *name);
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

#define K_WT_EXECUTEINWAITTHREAD 0x04
#define K_WT_EXECUTEONLYONCE     0x08
#define NSLOTS   2048
#define NTHREADS 40
#define PER_THREAD 62

typedef VOID (CALLBACK *K_WAITCB)(PVOID, BOOLEAN);
enum { S_FREE = 0, S_ACTIVE, S_FIRED, S_DEAD };   /* DEAD = unregistered, callbacks still running */

typedef struct {
    DWORD gen; int state; int th;                  /* th = wait thread index, -1 = not in a list */
    HANDLE obj; K_WAITCB cb; PVOID ctx; DWORD ms; ULONG flags; DWORD due;
    LONG inflight;                                 /* callbacks running or queued */
    DWORD cb_tid;                                  /* thread running an in-wait-thread callback */
    HANDLE done_ev;                                /* event to set when inflight drops to 0 after unregister */
} SLOT;
typedef struct { HANDLE thread, wake; DWORD tid; int n; int slot[PER_THREAD]; } WTH;

static SLOT g_s[NSLOTS];
static WTH g_t[NTHREADS];
static int g_nt;
static volatile LONG g_lk;
static void lk(void) { kex_spin_acquire(&g_lk); }
static void ulk(void) { InterlockedExchange((LONG *)&g_lk, 0); }

/* a live handle (checked without waiting on it: a wait would take an auto-reset event's signal) */
static BOOL handle_ok(HANDLE h)
{
    HANDLE d = NULL;
    if (!h || h == INVALID_HANDLE_VALUE) return FALSE;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &d, 0, FALSE, DUPLICATE_SAME_ACCESS)) return FALSE;
    CloseHandle(d);
    return TRUE;
}
static void list_remove(SLOT *s)                   /* lock held */
{
    int i, idx = (int)(s - g_s);
    WTH *t;
    if (s->th < 0) return;
    t = &g_t[s->th];
    for (i = 0; i < t->n; i++)
        if (t->slot[i] == idx) { t->slot[i] = t->slot[--t->n]; break; }
    SetEvent(t->wake);
    s->th = -1;
}
static void slot_free(SLOT *s)                     /* lock held */
{
    s->state = S_FREE; s->gen++; s->obj = NULL; s->cb = NULL; s->done_ev = NULL; s->inflight = 0; s->th = -1;
}
/* one callback finished (lock held): finish an unregistered wait when it was the last */
static void cb_done(SLOT *s)
{
    if (--s->inflight == 0 && s->state == S_DEAD) {
        HANDLE ev = s->done_ev;
        slot_free(s);
        if (ev && ev != INVALID_HANDLE_VALUE) SetEvent(ev);
    }
}

typedef struct { int idx; DWORD gen; K_WAITCB cb; PVOID ctx; BOOLEAN timed; } QCALL;
static DWORD WINAPI queued_cb(LPVOID p)
{
    QCALL *q = (QCALL *)p; SLOT *s = &g_s[q->idx];
    q->cb(q->ctx, q->timed);
    lk();
    if (s->gen == q->gen) cb_done(s);
    ulk();
    HeapFree(GetProcessHeap(), 0, q);
    return 0;
}
typedef BOOL (WINAPI *T_QUWI)(LPTHREAD_START_ROUTINE, PVOID, ULONG);

/* fire one wait (called on its wait thread, lock NOT held) */
static void fire(int idx, DWORD gen, BOOLEAN timed)
{
    static T_QUWI quwi;
    SLOT *s = &g_s[idx]; K_WAITCB cb; PVOID ctx; ULONG fl;
    lk();
    if (s->gen != gen || s->state != S_ACTIVE) { ulk(); return; }
    cb = s->cb; ctx = s->ctx; fl = s->flags;
    if ((fl & K_WT_EXECUTEONLYONCE) || s->ms == 0) { list_remove(s); s->state = S_FIRED; }
    else if (s->ms != INFINITE) s->due = GetTickCount() + s->ms;
    s->inflight++;
    if (fl & K_WT_EXECUTEINWAITTHREAD) {
        s->cb_tid = GetCurrentThreadId();
        ulk();
        cb(ctx, timed);
        lk();
        if (s->gen == gen) { s->cb_tid = 0; cb_done(s); }
        ulk();
        return;
    }
    ulk();
    {
        QCALL *q = (QCALL *)HeapAlloc(GetProcessHeap(), 0, sizeof(QCALL));
        if (!quwi) quwi = (T_QUWI)(void *)kex_prev_impl("KERNEL32.DLL", "QueueUserWorkItem");
        if (q) { q->idx = idx; q->gen = gen; q->cb = cb; q->ctx = ctx; q->timed = timed; }
        if (!q || !quwi || !quwi(queued_cb, q, 0)) {           /* no pool: run it here */
            if (q) HeapFree(GetProcessHeap(), 0, q);
            cb(ctx, timed);
            lk(); if (s->gen == gen) cb_done(s); ulk();
        }
    }
}

static DWORD WINAPI wait_thread(LPVOID p)
{
    int ti = (int)(ULONG_PTR)p; WTH *t = &g_t[ti];
    HANDLE h[PER_THREAD + 1]; int idx[PER_THREAD]; DWORD gen[PER_THREAD];
    for (;;) {
        int n, i; DWORD now = GetTickCount(), timeout = INFINITE, r;
        lk();
        n = t->n;
        h[0] = t->wake;
        for (i = 0; i < n; i++) {
            SLOT *s = &g_s[t->slot[i]];
            idx[i] = t->slot[i]; gen[i] = s->gen; h[i + 1] = s->obj;
            if (s->ms != INFINITE) {
                DWORD left = (LONG)(s->due - now) > 0 ? s->due - now : 0;
                if (left < timeout) timeout = left;
            }
        }
        ulk();
        r = WaitForMultipleObjects((DWORD)n + 1, h, FALSE, timeout);
        if (r == WAIT_OBJECT_0) continue;                       /* set changed */
        if (r > WAIT_OBJECT_0 && r <= WAIT_OBJECT_0 + (DWORD)n) { fire(idx[r - WAIT_OBJECT_0 - 1], gen[r - WAIT_OBJECT_0 - 1], FALSE); continue; }
        if (r >= WAIT_ABANDONED_0 + 1 && r <= WAIT_ABANDONED_0 + (DWORD)n) { fire(idx[r - WAIT_ABANDONED_0 - 1], gen[r - WAIT_ABANDONED_0 - 1], FALSE); continue; }
        if (r == WAIT_TIMEOUT) {
            now = GetTickCount();
            for (i = 0; i < n; i++) {
                SLOT *s = &g_s[idx[i]]; int due;
                lk(); due = s->gen == gen[i] && s->state == S_ACTIVE && s->ms != INFINITE && (LONG)(s->due - now) <= 0; ulk();
                if (due) fire(idx[i], gen[i], TRUE);
            }
            continue;
        }
        /* WAIT_FAILED: a handle was closed under us. Drop the waits whose handle no longer works. */
        for (i = 0; i < n; i++) {
            if (!handle_ok(h[i + 1])) {
                SLOT *s = &g_s[idx[i]];
                lk();
                if (s->gen == gen[i] && s->state == S_ACTIVE) { list_remove(s); s->state = S_FIRED; }
                ulk();
                { static LONG k; if (InterlockedIncrement(&k) <= 10) kex_trace("thread-pool wait: handle no longer valid, wait dropped", (DWORD)(ULONG_PTR)h[i + 1], idx[i], 0, 0); }
            }
        }
        Sleep(1);
    }
    return 0;
}

/* a wait thread with room that is not already watching obj (lock held); -1 if none can be made */
static int pick_thread(HANDLE obj)
{
    int i, k;
    for (i = 0; i < g_nt; i++) {
        WTH *t = &g_t[i]; int dup = 0;
        if (t->n >= PER_THREAD) continue;
        for (k = 0; k < t->n; k++) if (g_s[t->slot[k]].obj == obj) { dup = 1; break; }
        if (!dup) return i;
    }
    if (g_nt >= NTHREADS) return -1;
    i = g_nt;
    g_t[i].wake = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!g_t[i].wake) return -1;
    g_t[i].n = 0;
    g_t[i].thread = CreateThread(NULL, 256 * 1024, wait_thread, (LPVOID)(ULONG_PTR)i, 0, &g_t[i].tid);
    if (!g_t[i].thread) { CloseHandle(g_t[i].wake); g_t[i].wake = NULL; return -1; }
    g_nt++;
    return i;
}

BOOL KEXAPI kex_RegisterWaitForSingleObject(PHANDLE out, HANDLE obj, K_WAITCB cb, PVOID ctx, ULONG ms, ULONG flags)
{
    int i, ti; SLOT *s;
    if (!out || !cb) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!handle_ok(obj)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    lk();
    for (i = 0; i < NSLOTS; i++) if (g_s[i].state == S_FREE) break;
    if (i == NSLOTS || (ti = pick_thread(obj)) < 0) {
        ulk();
        kex_trace("RegisterWaitForSingleObject: out of waits", (DWORD)i, (DWORD)g_nt, 0, 0);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE;
    }
    s = &g_s[i];
    s->state = S_ACTIVE; s->obj = obj; s->cb = cb; s->ctx = ctx; s->ms = ms; s->flags = flags;
    s->due = GetTickCount() + (ms == INFINITE ? 0 : ms);
    s->inflight = 0; s->cb_tid = 0; s->done_ev = NULL; s->th = ti;
    g_t[ti].slot[g_t[ti].n++] = i;
    SetEvent(g_t[ti].wake);
    ulk();
    *out = (HANDLE)s;
    return TRUE;
}

HANDLE KEXAPI kex_RegisterWaitForSingleObjectEx(HANDLE obj, K_WAITCB cb, PVOID ctx, ULONG ms, ULONG flags)
{
    HANDLE h = NULL;
    return kex_RegisterWaitForSingleObject(&h, obj, cb, ctx, ms, flags) ? h : NULL;
}

BOOL KEXAPI kex_UnregisterWaitEx(HANDLE wait, HANDLE ev)
{
    SLOT *s = (SLOT *)wait; DWORD gen;
    if (!s || s < g_s || s >= g_s + NSLOTS || ((char *)s - (char *)g_s) % sizeof(SLOT)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    lk();
    if (s->state != S_ACTIVE && s->state != S_FIRED) { ulk(); SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    list_remove(s);
    if (!s->inflight) {
        slot_free(s);
        ulk();
        if (ev && ev != INVALID_HANDLE_VALUE) SetEvent(ev);
        return TRUE;
    }
    s->state = S_DEAD;
    if (ev == INVALID_HANDLE_VALUE && s->cb_tid != GetCurrentThreadId()) {
        gen = s->gen;
        ulk();
        for (;;) {                                         /* wait for the running callbacks */
            int busy;
            lk(); busy = s->gen == gen; ulk();
            if (!busy) return TRUE;
            Sleep(1);
        }
    }
    s->done_ev = (ev == INVALID_HANDLE_VALUE) ? NULL : ev;
    ulk();
    SetLastError(ERROR_IO_PENDING);
    return FALSE;
}

BOOL KEXAPI kex_UnregisterWait(HANDLE wait) { return kex_UnregisterWaitEx(wait, NULL); }

/* ---------------------------------------------------------------- timer queues (still KernelEx's) */
typedef BOOL (WINAPI *T_DTQT)(HANDLE, HANDLE, HANDLE);
BOOL KEXAPI kex_DeleteTimerQueueTimer(HANDLE queue, HANDLE timer, HANDLE ev)
{
    static T_DTQT prev; BOOL r;
    if (!prev) prev = (T_DTQT)(void *)kex_prev_impl("KERNEL32.DLL", "DeleteTimerQueueTimer");
    if (!prev || (void *)prev == (void *)kex_DeleteTimerQueueTimer) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    if (!ev || ev == INVALID_HANDLE_VALUE) return prev(queue, timer, ev);
    r = prev(queue, timer, INVALID_HANDLE_VALUE);          /* KernelEx never signals a real event when nothing was pending */
    if (r) SetEvent(ev);
    return r;
}
