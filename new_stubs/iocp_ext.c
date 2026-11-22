/* iocp_ext.c - I/O completion ports with file association (2026-11-10, build 20).
 *
 * Win98 has no completion ports. KernelEx 4.5.2 (kexbases/Kernel32/port.c) emulates the queue only
 * (Post/GetQueuedCompletionStatus) and refuses CreateIoCompletionPort(file, ...) with
 * ERROR_CALL_NOT_IMPLEMENTED. Chromium's IO threads register files and pipes with
 * MessagePumpForIO::RegisterIOHandler (base/message_loop/message_pump_win.cc) - the crash keys of the
 * build-19 run held "RegisterIOHandlerError" = 120 - and then wait for completion packets that never came.
 *
 * Here, per process:
 *   port            = a semaphore (its count = queued packets) + a packet queue in our table
 *   association     = handle -> (port, key, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS)
 *   kex_iocp_done() = called by kexnt where an OVERLAPPED operation completes (pipe_ext.c: kexnt pipes,
 *                     ReadFile/WriteFile on files done synchronously); queues a packet like NT does:
 *                     on asynchronous completion always, on immediate success unless the handle skips it,
 *                     never when the OVERLAPPED's hEvent has bit 0 set, never for immediate failure.
 * GetQueuedCompletionStatus(Ex) / PostQueuedCompletionStatus / SetFileCompletionNotificationModes use it.
 * Ports are not shared between processes (NT does not allow that either).
 */
#include "kexnt_common.h"
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
FARPROC kex_prev_impl(const char *dll, const char *name);   /* gdiguard_ext.c: KernelEx's own implementation */
/* build 22: a handle that is not one of our ports may be a KernelEx 4.5 port (a file mapping, kexbases port.c)
 * made by code that did not come through kexnt; hand those calls to KernelEx instead of failing. */
typedef BOOL (WINAPI *T_GQCS)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED *, DWORD);
typedef BOOL (WINAPI *T_PQCS)(HANDLE, DWORD, ULONG_PTR, LPOVERLAPPED);

#define NPORTS 64
#define NASSOC 1024
#define K_FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1

typedef struct { DWORD bytes; ULONG_PTR key; LPOVERLAPPED ov; DWORD err; } PKT;
typedef struct { HANDLE sem; PKT *q; DWORD cap, head, count; volatile LONG waiters; DWORD nposts, tpost, ntakes, ttake; } PORT;
typedef struct { HANDLE h; HANDLE port; ULONG_PTR key; BYTE skip; } ASSOC;

static PORT g_ports[NPORTS];
static ASSOC g_assoc[NASSOC];
static LONG g_nassoc_hi;           /* entries [0, hi) may be in use */
static volatile LONG g_lock;
static volatile LONG g_used;     /* any port or association ever made in this process */

static void lk(void) { kex_spin_acquire((volatile LONG *)&g_lock); }
static void ulk(void) { InterlockedExchange((LONG *)&g_lock, 0); }

static PORT *port_of(HANDLE h)      /* lock held */
{
    int i;
    if (!h || h == INVALID_HANDLE_VALUE) return NULL;
    for (i = 0; i < NPORTS; i++) if (g_ports[i].sem == h) return &g_ports[i];
    return NULL;
}
static ASSOC *assoc_of(HANDLE h)    /* lock held */
{
    LONG i;
    for (i = 0; i < g_nassoc_hi; i++) if (g_assoc[i].h == h) return &g_assoc[i];
    return NULL;
}
static ASSOC *assoc_new(HANDLE h)   /* lock held */
{
    LONG i;
    for (i = 0; i < NASSOC; i++)
        if (!g_assoc[i].h) {
            ZeroMemory(&g_assoc[i], sizeof(g_assoc[i]));
            g_assoc[i].h = h;
            if (i >= g_nassoc_hi) g_nassoc_hi = i + 1;
            return &g_assoc[i];
        }
    return NULL;
}

/* lock held; FALSE when out of memory */
static BOOL push(PORT *p, DWORD bytes, ULONG_PTR key, LPOVERLAPPED ov, DWORD err)
{
    PKT *k;
    if (p->count == p->cap) {
        DWORD ncap = p->cap ? p->cap * 2 : 64, i;
        PKT *nq = (PKT *)HeapAlloc(GetProcessHeap(), 0, ncap * sizeof(PKT));
        if (!nq) return FALSE;
        for (i = 0; i < p->count; i++) nq[i] = p->q[(p->head + i) % p->cap];
        if (p->q) HeapFree(GetProcessHeap(), 0, p->q);
        p->q = nq; p->cap = ncap; p->head = 0;
    }
    k = &p->q[(p->head + p->count) % p->cap];
    k->bytes = bytes; k->key = key; k->ov = ov; k->err = err;
    p->count++;
    p->nposts++; p->tpost = GetTickCount();
    ReleaseSemaphore(p->sem, 1, NULL);
    return TRUE;
}

/* lock held; FALSE if empty (should not happen after a successful semaphore wait) */
static BOOL pop(PORT *p, PKT *out)
{
    if (!p->count) return FALSE;
    *out = p->q[p->head];
    p->head = (p->head + 1) % p->cap;
    p->count--;
    return TRUE;
}

/* ---------------------------------------------------------------- called by other kexnt parts */
/* An OVERLAPPED operation on h finished. immediate = it finished inside the call that started it. */
/* build 37: ev = the OVERLAPPED's hEvent, read by the caller BEFORE it signalled completion - once the event is set
 * (or Internal says done) the program may free the OVERLAPPED (pipe worker crashed reading a freed one, KEXNT+36280). */
void kex_iocp_done2(HANDLE h, LPOVERLAPPED ov, HANDLE ev, DWORD bytes, DWORD err, BOOL immediate)
{
    ASSOC *a; PORT *p;
    if (!ov || ((ULONG_PTR)ev & 1) || !g_nassoc_hi) return;
    if (immediate && err) return;                          /* NT: an immediate failure queues nothing */
    lk();
    a = assoc_of(h);
    if (a && a->port && !(immediate && a->skip) && (p = port_of(a->port)) != NULL) push(p, bytes, a->key, ov, err);
    ulk();
}
void kex_iocp_done(HANDLE h, LPOVERLAPPED ov, DWORD bytes, DWORD err, BOOL immediate)
{
    if (ov) kex_iocp_done2(h, ov, ov->hEvent, bytes, err, immediate);
}

/* CloseHandle: a port or an associated handle goes away. */
void kex_iocp_close(HANDLE h)
{
    PORT *p; ASSOC *a;
    if (!g_used) return;
    lk();
    if ((a = assoc_of(h)) != NULL) a->h = NULL;
    if ((p = port_of(h)) != NULL) {
        kex_trace("CloseHandle: completion port closed", (DWORD)(ULONG_PTR)h, p->count, 0, 0);
        if (p->q) HeapFree(GetProcessHeap(), 0, p->q);
        ZeroMemory(p, sizeof(*p));
    }
    ulk();
}

/* Handles kex_iocp_done() is called for: kexnt pipe ends, kexnt folder handles, disk files (K32 type 8). */
BOOL kex_handle_facts(HANDLE h, BYTE *type, DWORD *access, BOOL *inherit);   /* procspawn_ext.c */
BOOL kex_pipe_name(HANDLE h, char *out, int cb);                              /* pipe_ext.c */
BOOL kex_dir_is(HANDLE h);                                                    /* dirhandle_ext.c */
static BOOL completable(HANDLE h)
{
    char nm[64]; BYTE t = 0;
    if (kex_dir_is(h) || kex_pipe_name(h, nm, sizeof(nm))) return TRUE;
    if (kex_handle_facts(h, &t, NULL, NULL) && t == 8 && GetFileType(h) == FILE_TYPE_DISK) return TRUE;
    return FALSE;
}

/* ---------------------------------------------------------------- the API */
HANDLE KEXAPI kex_CreateIoCompletionPort(HANDLE file, HANDLE existing, ULONG_PTR key, DWORD threads)
{
    PORT *p = NULL; HANDLE port; int i;
    /* build 93: decided BEFORE taking the port lock. completable() takes the pipe arena mutex (kex_pipe_name) and
     * the folder-handle lock; the pipe worker holds the arena mutex while it queues a completion packet (port
     * lock). Asking under the port lock was a lock-order inversion: build 92 KEXHANG - Chrome_IOThread in
     * CreateIoCompletionPort -> kex_pipe_name waiting for the arena mutex, the pipe worker in kex_iocp_done2
     * spinning on the port lock, and every other thread that posted a packet (browser main thread too) stuck
     * behind them = whole browser frozen. */
    BOOL ok_file = !(file && file != INVALID_HANDLE_VALUE) || completable(file);
    lk();
    if (existing) {
        if (!(p = port_of(existing))) { ulk(); SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
        port = existing;
    } else {
        for (i = 0; i < NPORTS; i++) if (!g_ports[i].sem) break;
        if (i == NPORTS) { ulk(); kex_trace("CreateIoCompletionPort: out of ports", 0, 0, 0, 0); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
        port = CreateSemaphoreA(NULL, 0, 0x7FFFFFFF, NULL);
        if (!port) { ulk(); return NULL; }
        p = &g_ports[i];
        ZeroMemory(p, sizeof(*p));
        p->sem = port;
        g_used = 1;
        { static LONG n; if (InterlockedIncrement(&n) <= 40) kex_trace("CreateIoCompletionPort: new port", (DWORD)(ULONG_PTR)port, (DWORD)(ULONG_PTR)file, (DWORD)(ULONG_PTR)__builtin_return_address(0), 0); }
    }
    if (!ok_file) {
        /* build 22: only handles whose completions kexnt delivers. A socket (or anything else Win98 completes
         * by itself) would never get a packet - NSPR (Mypal) and Chromium then wait forever. Refuse it as
         * KernelEx 4.5 did, so the program keeps using its non-port path. */
        ulk();
        if (!existing) kex_iocp_close(port), CloseHandle(port);
        { static LONG n; if (InterlockedIncrement(&n) <= 20) { BYTE t = 0; kex_handle_facts(file, &t, NULL, NULL);
          kex_trace("CreateIoCompletionPort: handle refused (K32 type)", (DWORD)(ULONG_PTR)file, t, 0, 0); } }
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL;
    }
    if (file && file != INVALID_HANDLE_VALUE) {
        ASSOC *a = assoc_of(file);
        if (a && a->port) {                                /* NT: a handle joins one port only */
            ulk();
            if (!existing) kex_iocp_close(port), CloseHandle(port);
            SetLastError(ERROR_INVALID_PARAMETER); return NULL;
        }
        if (!a) a = assoc_new(file);
        if (!a) {
            ulk();
            if (!existing) kex_iocp_close(port), CloseHandle(port);
            kex_trace("CreateIoCompletionPort: association table full", 0, 0, 0, 0);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL;
        }
        a->port = port; a->key = key;
    } else if (existing) {
        ulk(); SetLastError(ERROR_INVALID_PARAMETER); return NULL;
    }
    ulk();
    (void)threads;
    SetLastError(0);
    return port;
}

BOOL KEXAPI kex_PostQueuedCompletionStatus(HANDLE port, DWORD bytes, ULONG_PTR key, LPOVERLAPPED ov)
{
    PORT *p; BOOL r;
    lk();
    if (!(p = port_of(port))) {
        static T_PQCS prev;
        ulk();
        if (!prev) prev = (T_PQCS)(void *)kex_prev_impl("KERNEL32.DLL", "PostQueuedCompletionStatus");
        if (prev && (void *)prev != (void *)kex_PostQueuedCompletionStatus) return prev(port, bytes, key, ov);
        SetLastError(ERROR_INVALID_HANDLE); return FALSE;
    }
    r = push(p, bytes, key, ov, 0);
    ulk();
    if (!r) SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return r;
}

/* wait for one packet; WAIT_OBJECT_0, WAIT_TIMEOUT, WAIT_IO_COMPLETION or WAIT_FAILED */
static DWORD take(HANDLE port, DWORD ms, BOOL alertable, PKT *k)
{
    for (;;) {
        DWORD w; PORT *p; BOOL got;
        lk(); if ((p = port_of(port)) != NULL) p->waiters++; ulk();
        w = WaitForSingleObjectEx(port, ms, alertable);
        lk();
        p = port_of(port);
        if (p && p->waiters > 0) p->waiters--;
        if (w != WAIT_OBJECT_0) { ulk(); return w == WAIT_ABANDONED ? WAIT_FAILED : w; }
        got = p && pop(p, k);
        if (got) { p->ntakes++; p->ttake = GetTickCount(); }
        ulk();
        if (!p) { SetLastError(ERROR_ABANDONED_WAIT_0); return WAIT_FAILED; }
        if (got) return WAIT_OBJECT_0;
    }
}

BOOL KEXAPI kex_GetQueuedCompletionStatus(HANDLE port, LPDWORD bytes, PULONG_PTR key, LPOVERLAPPED *ov, DWORD ms)
{
    PKT k; DWORD w; BOOL known;
    if (!bytes || !key || !ov) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    lk(); known = port_of(port) != NULL; ulk();
    *ov = NULL;
    if (!known) {
        static T_GQCS prev; static LONG n;
        if (InterlockedIncrement(&n) <= 20) kex_trace("GetQueuedCompletionStatus: not our port -> KernelEx", (DWORD)(ULONG_PTR)port, ms, 0, 0);
        if (!prev) prev = (T_GQCS)(void *)kex_prev_impl("KERNEL32.DLL", "GetQueuedCompletionStatus");
        if (prev && (void *)prev != (void *)kex_GetQueuedCompletionStatus) return prev(port, bytes, key, ov, ms);
        SetLastError(ERROR_INVALID_HANDLE); return FALSE;
    }
    w = take(port, ms, FALSE, &k);
    if (w == WAIT_TIMEOUT) { SetLastError(WAIT_TIMEOUT); return FALSE; }
    if (w != WAIT_OBJECT_0) { DWORD le = GetLastError(); kex_trace("GetQueuedCompletionStatus: wait failed", (DWORD)(ULONG_PTR)port, ms, w, le); SetLastError(le); return FALSE; }
    *bytes = k.bytes; *key = k.key; *ov = k.ov;
    if (k.err) { SetLastError(k.err); return FALSE; }
    return TRUE;
}

typedef struct { ULONG_PTR lpCompletionKey; LPOVERLAPPED lpOverlapped; ULONG_PTR Internal; DWORD dwNumberOfBytesTransferred; } K_OVERLAPPED_ENTRY;

BOOL KEXAPI kex_GetQueuedCompletionStatusEx(HANDLE port, K_OVERLAPPED_ENTRY *e, ULONG n, PULONG removed, DWORD ms, BOOL alertable)
{
    PKT k; DWORD w; ULONG got = 0; BOOL known;
    if (!e || !n || !removed) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *removed = 0;
    lk(); known = port_of(port) != NULL; ulk();
    if (!known) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    w = take(port, ms, alertable, &k);
    if (w == WAIT_TIMEOUT) { SetLastError(WAIT_TIMEOUT); return FALSE; }
    if (w == WAIT_IO_COMPLETION) { SetLastError(WAIT_IO_COMPLETION); return FALSE; }
    if (w != WAIT_OBJECT_0) return FALSE;
    for (;;) {
        e[got].lpCompletionKey = k.key; e[got].lpOverlapped = k.ov;
        e[got].Internal = k.err;                       /* 0 = success; callers read the result from the OVERLAPPED */
        e[got].dwNumberOfBytesTransferred = k.bytes;
        got++;
        if (got == n || take(port, 0, FALSE, &k) != WAIT_OBJECT_0) break;
    }
    *removed = got;
    return TRUE;
}

BOOL KEXAPI kex_SetFileCompletionNotificationModes(HANDLE h, UCHAR flags)
{
    ASSOC *a;
    if (!h || h == INVALID_HANDLE_VALUE) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    lk();
    g_used = 1;
    if (!(a = assoc_of(h))) a = assoc_new(h);
    if (a) a->skip = (flags & K_FILE_SKIP_COMPLETION_PORT_ON_SUCCESS) ? 1 : 0;
    ulk();
    if (!a) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    return TRUE;
}

/* thread snapshot (crashlog_ext.c): one port's state, no lock (diagnostics only).
 * v = handle, queued packets, threads waiting, packets posted, tick of last post, packets taken, tick of last take */
int kex_iocp_stat(int i, DWORD v[7])
{
    PORT *p;
    if (i < 0 || i >= NPORTS) return -1;
    p = &g_ports[i];
    if (!p->sem) { v[0] = 0; return 0; }
    v[0] = (DWORD)(ULONG_PTR)p->sem; v[1] = p->count; v[2] = (DWORD)p->waiters;
    v[3] = p->nposts; v[4] = p->tpost; v[5] = p->ntakes; v[6] = p->ttake;
    return 1;
}
