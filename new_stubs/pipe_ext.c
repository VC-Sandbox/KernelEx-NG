/*
 * pipe_ext.c - KernelEx-NG: local named pipes for Windows 98 SE.
 *
 * Win9x can open named pipes on NT servers but cannot create them (CreateNamedPipe fails with
 * ERROR_CALL_NOT_IMPLEMENTED). Chromium needs pipe servers for Crashpad (crashpad_client_win.cc:331
 * CHECK(pipe_instance->is_valid())) and Mojo IPC. This module implements local pipes (\\.\pipe\name)
 * with the documented Win32 semantics, built only from things Win98 has.
 *
 * Handles. A pipe end is a NAMED EVENT ("KXNP<slot>S<gen>" server, "KXNP<slot>C<gen>" client), so the
 * handle is a real kernel handle: CloseHandle, DuplicateHandle and inheritance by child processes work
 * natively. A handle is recognised as a pipe end by its K32 object address (the same in every process on
 * 9x), compared with the addresses stored in the arena. ReadFile/WriteFile/... on anything that is not an
 * event take the normal path immediately.
 * Liveness. A named Win98 object exists while any handle to it is open, so "is the other end still open"
 * is OpenEvent(peer name) - this also covers processes that die without closing.
 *
 * Data. One named shared mapping ("KXNP_ARENA") holds NP_MAX instances, each with two ring buffers
 * (server->client, client->server) and a queue of message lengths, so message-mode pipes keep message
 * boundaries (PIPE_TYPE_MESSAGE / PIPE_READMODE_MESSAGE) and byte-mode readers ignore them. Only offsets
 * are stored. A global named mutex guards it; state changes PulseEvent a global event, waiters re-check
 * at least every 20 ms (so a missed pulse costs at most 20 ms).
 *
 * Overlapped I/O. Win98 has no overlapped I/O for this; a per-process worker thread completes queued
 * ConnectNamedPipe / ReadFile / WriteFile requests and then fills OVERLAPPED.Internal (NTSTATUS) and
 * .InternalHigh (bytes) and signals OVERLAPPED.hEvent - or the pipe handle itself when hEvent is NULL,
 * as NT signals the file handle. Requests that complete at once return TRUE and also signal (NT does).
 * GetOverlappedResult / CancelIo / CancelIoEx understand these requests.
 *
 * Passing through: CreateFileA/W, ReadFile, WriteFile and GetOverlappedResult replace KernelEx's
 * versions, so for everything that is not a pipe they reproduce what KernelEx 4.5 does (kexbases
 * file.c: NT access rights -> generic rights, no FILE_SHARE_DELETE, no template file, retry without
 * FILE_FLAG_OVERLAPPED; synchronous fallback for overlapped file reads/writes) on top of Win98's own calls.
 *
 * Limits (first version): NP_MAX instances system wide, NP_BUF bytes per direction (larger writes are
 * split, message-mode messages larger than NP_BUF arrive as ERROR_MORE_DATA pieces), no PIPE_NOWAIT,
 * no remote pipes (\\server\pipe\x still goes to Win98's redirector), no impersonation.
 */
#include "kexnt_common.h"
#include <string.h>

BYTE *kex_k32_object(HANDLE h, int type);      /* chrome_ext.c */
#define K32_EVENT 2

#define NP_MAX   96                 /* build 62: was 48 (Chrome's audio sync sockets add pipes per stream) */
#define NP_BUF   32768
#define NP_MQ    256
#define NP_NAME  120

#define ST_FREE       0
#define ST_LISTENING  1     /* server waiting for a client */
#define ST_CONNECTED  2
#define ST_CLOSING    3     /* client gone; server must DisconnectNamedPipe */

typedef struct {
    DWORD head, tail, used;                 /* byte ring */
    DWORD mt[NP_MQ];                        /* build 127: tick each queued piece was written */
    DWORD mq[NP_MQ];                        /* message lengths; bit 31 = continued in the next entry */
    DWORD mq_head, mq_tail, mq_count;
    BYTE  data[NP_BUF];
} RING;

typedef struct {
    LONG  state;
    DWORD gen;                              /* server end generation (new CreateNamedPipe) */
    DWORD cgen;                             /* client connection serial (new client after Disconnect) */
    char  name[NP_NAME];                    /* lower case, without the \\.\pipe\ prefix */
    DWORD open_mode, pipe_mode, max_inst, out_size, in_size;
    DWORD srv_obj, cli_obj;                 /* K32 object addresses of the end events */
    DWORD srv_pid, cli_pid;
    DWORD readmode[2];                      /* [0] server, [1] client: PIPE_READMODE_MESSAGE or 0 */
    RING  ring[2];                          /* [0] to server (client writes), [1] to client (server writes) */
} NPI;

typedef struct { DWORD magic, version; NPI inst[NP_MAX]; } ARENA;
#define NP_MAGIC 0x504E584B                 /* 'KXNP' */

static ARENA *g_ar;
static HANDLE g_mtx, g_chg;                 /* per-process handles to the global mutex / change event */
static volatile LONG g_init_lock;

/* ------------------------------------------------------------------ NTSTATUS used in OVERLAPPED.Internal */
#define S_OK_K            0x00000000UL
#define S_PENDING_K       0x00000103UL
#define S_BUF_OVERFLOW_K  0x80000005UL
#define S_CANCELLED_K     0xC0000120UL
#define S_PIPE_BROKEN_K   0xC000014BUL
#define S_PIPE_DISC_K     0xC00000B0UL
#define S_PIPE_CLOSING_K  0xC00000B1UL
#define S_PIPE_LISTEN_K   0xC00000B3UL

static DWORD status_to_err(DWORD s)
{
    switch (s) {
    case S_OK_K: return 0;
    case S_BUF_OVERFLOW_K: return ERROR_MORE_DATA;
    case S_CANCELLED_K: return ERROR_OPERATION_ABORTED;
    case S_PIPE_BROKEN_K: return ERROR_BROKEN_PIPE;
    case S_PIPE_DISC_K: return ERROR_PIPE_NOT_CONNECTED;
    case S_PIPE_CLOSING_K: return ERROR_NO_DATA;
    case S_PIPE_LISTEN_K: return ERROR_PIPE_LISTENING;
    case S_PENDING_K: return ERROR_IO_INCOMPLETE;
    }
    return ERROR_GEN_FAILURE;
}

/* ------------------------------------------------------------------ arena */
static BOOL arena(void)
{
    HANDLE m;
    if (g_ar) return TRUE;
    kex_spin_acquire((volatile LONG *)&g_init_lock);
    if (!g_ar) {
        g_mtx = CreateMutexA(NULL, FALSE, "KXNP_LOCK");
        g_chg = CreateEventA(NULL, TRUE, FALSE, "KXNP_CHANGE");
        m = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(ARENA), "KXNP_ARENA");
        if (g_mtx && g_chg && m) {
            ARENA *a = (ARENA *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0);
            if (a) {
                WaitForSingleObject(g_mtx, INFINITE);
                if (a->magic != NP_MAGIC || a->version != 4) {   /* a fresh mapping is zero: only an old layout is wiped */
                    if (a->magic || a->version) memset(a, 0, sizeof(*a));
                    a->magic = NP_MAGIC; a->version = 4;   /* build 127: RING.mt */
                }
                ReleaseMutex(g_mtx);
                g_ar = a;                    /* mapping handle kept open for the life of the process */
            }
        }
    }
    InterlockedExchange((LONG *)&g_init_lock, 0);
    return g_ar != NULL;
}
/* build 127: IPC timing for the per-second timeline (prof_ext.c KEXTL_*.LOG) - this process's pipe traffic, the
 * longest time data sat in a pipe before this process read it, and the longest wait for the global pipe lock */
static volatile LONG g_tl_in, g_tl_out, g_tl_maxwait, g_tl_lockmax, g_tl_slow, g_tl_logged;
void kex_pipe_tl_stats(DWORD *in, DWORD *out, DWORD *maxwait, DWORD *lockmax, DWORD *slow)
{
    *in = (DWORD)InterlockedExchange(&g_tl_in, 0); *out = (DWORD)InterlockedExchange(&g_tl_out, 0);
    *maxwait = (DWORD)InterlockedExchange(&g_tl_maxwait, 0); *lockmax = (DWORD)InterlockedExchange(&g_tl_lockmax, 0);
    *slow = (DWORD)InterlockedExchange(&g_tl_slow, 0);
}
static void tl_max(volatile LONG *m, LONG v) { LONG o; while ((o = *m) < v && InterlockedCompareExchange(m, v, o) != o) {} }
static void lock(void)
{
    DWORD t0 = GetTickCount(), dt;
    WaitForSingleObject(g_mtx, INFINITE);
    dt = GetTickCount() - t0;
    if (dt) tl_max(&g_tl_lockmax, (LONG)dt);
}
static void unlock(void) { ReleaseMutex(g_mtx); }
static void changed(void) { PulseEvent(g_chg); }
static void nap(void) { WaitForSingleObject(g_chg, 20); }

static void end_name(char *out, int slot, DWORD gen, int client)
{
    static const char hx[] = "0123456789ABCDEF";
    int i = 0, k;
    out[i++] = 'K'; out[i++] = 'X'; out[i++] = 'N'; out[i++] = 'P';
    out[i++] = hx[(slot >> 4) & 15]; out[i++] = hx[slot & 15];
    out[i++] = client ? 'C' : 'S';
    for (k = 28; k >= 0; k -= 4) out[i++] = hx[(gen >> k) & 15];
    out[i] = 0;
}
/* build 77: Chrome's renderers kept ending by themselves (exit code 0 from the renderer's own shutdown path = its
 * IPC pipe to the browser broke) while the system had 1 MB of memory free. OpenEvent failing for lack of memory
 * or handles is not "the other end is gone": only "no such name" (2) and its relatives count as gone. Any other
 * failure keeps the end alive and is noted in KEXCRASH (it was a broken Chrome IPC channel before). */
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
static BOOL end_alive(int slot, DWORD gen, int client)
{
    char n[24]; HANDLE h; DWORD e;
    end_name(n, slot, gen, client);
    SetLastError(0);
    if (!(h = OpenEventA(EVENT_ALL_ACCESS, FALSE, n))) {
        e = GetLastError();
        if (e == 0 || e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND || e == ERROR_INVALID_HANDLE ||
            e == ERROR_INVALID_NAME || e == ERROR_INVALID_PARAMETER) return FALSE;
        {   static LONG k; if (InterlockedIncrement(&k) <= 20)
                kex_crashnote("pipe: could not look at the other end (error) - taken as still open (error, slot, generation, client end)",
                              e, (DWORD)slot, gen, (DWORD)client); }
        return TRUE;
    }
    CloseHandle(h);
    return TRUE;
}

/* build 77: a connected pipe whose other end went away - one KEXCRASH line each (Chrome IPC: which process) */
static void note_broken(const NPI *p, int side)
{
    static LONG k; char t[256];
    if (InterlockedIncrement(&k) > 30) return;
    lstrcpyA(t, "pipe: other end gone (read side 0 server 1 client, other process, this process, its event: type|references<<16) "); lstrcpynA(t + lstrlenA(t), p->name, 60);
    {   DWORD obj = side ? p->srv_obj : p->cli_obj; const BYTE *o = (const BYTE *)(ULONG_PTR)obj;
        DWORD st = (obj >= 0x80000000UL && !IsBadReadPtr(o, 4)) ? (*(const DWORD *)o) : 0xFFFFFFFFUL;   /* type | refs<<16 */
        kex_crashnote(t, (DWORD)side, side ? p->srv_pid : p->cli_pid, GetCurrentProcessId(), st); }
}

/* name generation of an end: server = gen, client = cgen (each connection gets its own client event name,
 * so a stale client handle from before DisconnectNamedPipe can never alias the next client) */
static DWORD end_gen(const NPI *p, int client) { return client ? p->cgen : p->gen; }
/* build 81: Chrome's tab processes ended 1-2 s after start with their channel to the browser "broken" (KEXCRASH
 * "pipe: other end gone ... read side 1 ... other process <browser>") while the browser was alive and still wanted
 * them (the same RenderProcessHost relaunched on reload = the blank first pages). The name lookup said the
 * browser's end was gone. Second opinion before believing it: the end's own K32 event object (address kept in the
 * arena; K32OBJHEAD {WORD Type; WORD cReferences}) still an event with references, and the process that made
 * that end still running -> the end is alive. Each such disagreement is noted (with the numbers) in KEXCRASH. */
static BOOL pid_alive(DWORD pid)
{
    HANDLE h; DWORD code = 0;
    if (!pid) return FALSE;
    if (pid == GetCurrentProcessId()) return TRUE;
    if (!(h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid))) return FALSE;
    if (!GetExitCodeProcess(h, &code)) code = 0;
    CloseHandle(h);
    return code == STILL_ACTIVE;
}
static BOOL alive(const NPI *p, int slot, int client)
{
    DWORD obj, pid; const BYTE *o;
    if (end_alive(slot, end_gen(p, client), client)) return TRUE;
    /* build 121: no second opinion any more. A Windows 98 object keeps its name for as long as it exists, so "no
     * such name" means the end's event is destroyed. Build 120 data: the "event object still live" that builds
     * 81-120 believed was ANOTHER event that Windows had put at the freed address (renderer ff8c520b: object
     * d49ef7a0 "kept open", and the next CloseHandle of an unrelated event at that address was taken for the
     * pipe's server end; one renderer handle value was taken for a pipe end 34 times). Such a stale slot also
     * made new events - and new pipe ends - look like the dead pipe. Noted, then the end counts as gone. */
    obj = client ? p->cli_obj : p->srv_obj; pid = client ? p->cli_pid : p->srv_pid;
    o = (const BYTE *)(ULONG_PTR)obj;
    if (pid != GetCurrentProcessId() &&
        obj >= 0x80000000UL && !IsBadReadPtr(o, 4) && o[0] == K32_EVENT && *(const WORD *)(o + 2) != 0) {
        static LONG k; char t[256];
        if (InterlockedIncrement(&k) <= 20) {
            lstrcpyA(t, "pipe: end's name is gone, its old object address now holds another event - end taken as gone (object, references, its process alive, client end) ");
            lstrcpynA(t + lstrlenA(t), p->name, 40);
            kex_crashnote(t, obj, *(const WORD *)(o + 2), (DWORD)pid_alive(pid), (DWORD)client);
        }
    }
    return FALSE;
}

/* \\.\pipe\Name -> "name" (lower case). Returns FALSE if not a local pipe path. */
static BOOL pipe_name_a(const char *path, char *out)
{
    static const char pre[] = "\\\\.\\pipe\\";
    int i;
    if (!path) return FALSE;
    for (i = 0; pre[i]; i++) {
        char c = path[i]; if (c >= 'A' && c <= 'Z') c += 32;
        if (c != pre[i]) return FALSE;
    }
    path += i;
    for (i = 0; path[i] && i < NP_NAME - 1; i++) { char c = path[i]; out[i] = (c >= 'A' && c <= 'Z') ? c + 32 : c; }
    out[i] = 0;
    return i > 0 && !path[i];
}
static BOOL pipe_name_w(const WCHAR *path, char *out)
{
    char a[NP_NAME + 16]; int i;
    if (!path) return FALSE;
    for (i = 0; path[i] && i < (int)sizeof(a) - 1; i++) {
        if (path[i] > 0x7E) return FALSE;            /* pipe names Chromium uses are ASCII */
        a[i] = (char)path[i];
    }
    if (path[i]) return FALSE;
    a[i] = 0;
    return pipe_name_a(a, out);
}

/* Which pipe end is handle h? (caller holds the lock or accepts a racy answer) */
static int find_end(HANDLE h, int *side)
{
    DWORD o; int i;
    BYTE *obj = kex_k32_object(h, K32_EVENT);
    if (!obj || !arena()) return -1;
    o = (DWORD)obj;
    for (i = 0; i < NP_MAX; i++) {
        NPI *p = &g_ar->inst[i];
        if (p->state == ST_FREE) continue;
        if (p->srv_obj == o) { *side = 0; return i; }
        if (p->cli_obj == o && p->state == ST_CONNECTED) { *side = 1; return i; }
    }
    return -1;
}
static BOOL is_event_handle(HANDLE h) { return kex_k32_object(h, K32_EVENT) != NULL; }

/* build 121: a new pipe end's event can sit at the address of an end that is already destroyed (Windows 98 reuses
 * freed object memory at once). Any other slot still holding that address refers to the dead end: drop it there,
 * so find_end() can only ever answer the new end's slot. Lock held. */
static void drop_aliases(DWORD obj, int keep)
{
    int i;
    for (i = 0; i < NP_MAX; i++) {
        NPI *q = &g_ar->inst[i];
        if (i == keep || q->state == ST_FREE) continue;
        if (q->srv_obj == obj || q->cli_obj == obj) {
            static LONG k;
            if (InterlockedIncrement(&k) <= 20) {
                char t[200]; lstrcpyA(t, "pipe: new end's event is at a dead end's old address - dead end dropped (slot, server end, state, new slot) ");
                lstrcpynA(t + lstrlenA(t), q->name, 40);
                kex_crashnote(t, (DWORD)i, q->srv_obj == obj, (DWORD)q->state, (DWORD)keep);
            }
            if (q->srv_obj == obj) q->srv_obj = 0;
            if (q->cli_obj == obj) q->cli_obj = 0;
        }
    }
}

/* ------------------------------------------------------------------ rings */
static DWORD ring_free(RING *r) { return (r->mq_count >= NP_MQ - 1) ? 0 : NP_BUF - r->used; }

static void ring_put(RING *r, const BYTE *src, DWORD n, BOOL continued)
{
    InterlockedExchangeAdd(&g_tl_out, (LONG)n);
    r->mt[r->mq_head] = GetTickCount();
    DWORD first = NP_BUF - r->head; if (first > n) first = n;
    memcpy(r->data + r->head, src, first);
    memcpy(r->data, src + first, n - first);
    r->head = (r->head + n) % NP_BUF; r->used += n;
    r->mq[r->mq_head] = n | (continued ? 0x80000000UL : 0);
    r->mq_head = (r->mq_head + 1) % NP_MQ; r->mq_count++;
}

/* copy up to n bytes from the ring at the read position (+skip) without consuming */
static void ring_peek(RING *r, BYTE *dst, DWORD n, DWORD skip)
{
    DWORD pos = (r->tail + skip) % NP_BUF, first = NP_BUF - pos;
    if (first > n) first = n;
    memcpy(dst, r->data + pos, first);
    memcpy(dst + first, r->data, n - first);
}
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
static void ring_consume(RING *r, DWORD n)
{
    if (n) {                                 /* build 127: how long the oldest of this data waited */
        DWORD now = GetTickCount(), wt = r->mq_count ? now - r->mt[r->mq_tail] : 0;
        InterlockedExchangeAdd(&g_tl_in, (LONG)n);
        if (wt < 600000) {
            tl_max(&g_tl_maxwait, (LONG)wt);
            if (wt > 300) InterlockedIncrement(&g_tl_slow);
            if (wt > 1000 && InterlockedIncrement(&g_tl_logged) <= 40)
                kex_crashnote("IPC: pipe data waited over 1 s before this process read it (ms, bytes read, bytes still queued, ring)", wt, n, r->used - n, (DWORD)(ULONG_PTR)r);
        }
    }
    r->tail = (r->tail + n) % NP_BUF; r->used -= n;
    while (n && r->mq_count) {
        DWORD len = r->mq[r->mq_tail] & 0x7FFFFFFFUL, take = n < len ? n : len;
        if (take == len) { r->mq_tail = (r->mq_tail + 1) % NP_MQ; r->mq_count--; }
        else r->mq[r->mq_tail] -= take;
        n -= take;
    }
}

/* Read from ring. Message mode: at most one message (following continuation entries); *more set if
 * part of the message remains. Byte mode: whatever is there, up to n. Returns bytes copied. */
static DWORD ring_get(RING *r, BYTE *dst, DWORD n, BOOL msg, BOOL *more, BOOL consume)
{
    DWORD got = 0;
    *more = FALSE;
    if (!r->used) return 0;
    if (!msg) {
        got = r->used < n ? r->used : n;
        if (dst && got) ring_peek(r, dst, got, 0);
        if (consume) ring_consume(r, got);
        return got;
    }
    {
        DWORD idx = r->mq_tail, cnt = r->mq_count, total = 0;
        while (cnt) {                                     /* length of the logical message */
            DWORD e = r->mq[idx];
            total += e & 0x7FFFFFFFUL;
            if (!(e & 0x80000000UL)) break;
            idx = (idx + 1) % NP_MQ; cnt--;
        }
        got = total < n ? total : n;
        if (dst && got) ring_peek(r, dst, got, 0);
        *more = got < total;
        if (consume) ring_consume(r, got);
        return got;
    }
}

/* ------------------------------------------------------------------ state helpers (lock held) */
static void inst_reset_data(NPI *p) { memset(p->ring, 0, sizeof(p->ring)); }

/* Garbage-collect instances whose server end is gone. */
static void reap(void)
{
    int i;
    for (i = 0; i < NP_MAX; i++) {
        NPI *p = &g_ar->inst[i];
        if (p->state != ST_FREE && !alive(p, i, 0)) {
            p->state = ST_FREE; p->srv_obj = p->cli_obj = 0;
        }
    }
}

/* ------------------------------------------------------------------ async requests (per process) */
#define OP_CONNECT 1
#define OP_READ    2
#define OP_WRITE   3

typedef struct op {
    struct op *next;
    int type, slot, side; DWORD gen, cgen;
    HANDLE h; LPOVERLAPPED ov;
    BYTE *buf; DWORD len, done;
    BOOL cancel;
} OP;

static OP *g_ops;
static CRITICAL_SECTION g_ops_cs;
static BOOL g_ops_cs_ok;
static HANDLE g_work, g_thread;

void kex_iocp_done(HANDLE h, LPOVERLAPPED ov, DWORD bytes, DWORD err, BOOL immediate);   /* iocp_ext.c */
static DWORD status_to_err(DWORD s);
void kex_iocp_done2(HANDLE h, LPOVERLAPPED ov, HANDLE ev, DWORD bytes, DWORD err, BOOL immediate);
static void complete(OP *o, DWORD status)
{
    LPOVERLAPPED ov = o->ov; HANDLE ev = ov->hEvent;   /* read everything first: once Internal/the event say done, */
    ov->InternalHigh = o->done;                         /* the program may free the OVERLAPPED (build 37) */
    ov->Internal = status;                    /* after InternalHigh: readers poll Internal */
    kex_iocp_done2(o->h, ov, ev, o->done, status_to_err(status), FALSE);   /* completion port packet */
    SetEvent(ev ? ev : o->h);
}

/* Try to make progress on one request; returns TRUE when finished (completion done). Lock held. */
static BOOL op_step(OP *o)
{
    NPI *p = &g_ar->inst[o->slot];
    int me = o->side, peer = !me;
    if (o->cancel) { complete(o, S_CANCELLED_K); return TRUE; }
    if (p->gen != o->gen || p->state == ST_FREE || (me == 1 && p->cgen != o->cgen) || !alive(p, o->slot, me)) {
        complete(o, S_CANCELLED_K); return TRUE;              /* our own handle was closed */
    }
    switch (o->type) {
    case OP_CONNECT:
        if (p->state == ST_CONNECTED) { complete(o, S_OK_K); return TRUE; }
        if (p->state == ST_CLOSING) { complete(o, S_PIPE_CLOSING_K); return TRUE; }
        return FALSE;
    case OP_READ: {
        RING *r = &p->ring[me]; BOOL more;
        if (r->used) {
            o->done = ring_get(r, o->buf, o->len, p->readmode[me] != 0, &more, TRUE);
            complete(o, more ? S_BUF_OVERFLOW_K : S_OK_K); return TRUE;
        }
        if (p->state != ST_CONNECTED || !alive(p, o->slot, peer)) {
            if (p->state == ST_CONNECTED) note_broken(p, me);
            complete(o, p->state == ST_LISTENING ? S_PIPE_LISTEN_K : S_PIPE_BROKEN_K); return TRUE;
        }
        return FALSE;
    }
    case OP_WRITE: {
        RING *r = &p->ring[peer];
        if (p->state != ST_CONNECTED || !alive(p, o->slot, peer)) {
            complete(o, p->state == ST_LISTENING ? S_PIPE_LISTEN_K : S_PIPE_CLOSING_K); return TRUE;
        }
        while (o->done < o->len) {
            DWORD f = ring_free(r), n = o->len - o->done;
            if (!f) break;
            if (n > f) n = f;
            ring_put(r, o->buf + o->done, n, o->done + n < o->len);
            o->done += n;
        }
        if (o->done == o->len) { complete(o, S_OK_K); return TRUE; }
        return FALSE;
    }
    }
    complete(o, S_CANCELLED_K);
    return TRUE;
}

static DWORD WINAPI worker(LPVOID unused)
{
    HANDLE w[2];
    for (;;) {
        OP **pp, *o; BOOL any = FALSE, progressed = FALSE;
        if (g_ops) {                              /* lock order everywhere: arena mutex, then g_ops_cs */
            lock();
            EnterCriticalSection(&g_ops_cs);
            for (pp = &g_ops; (o = *pp) != NULL; ) {
                if (op_step(o)) { *pp = o->next; HeapFree(GetProcessHeap(), 0, o); progressed = TRUE; }
                else pp = &o->next;
            }
            any = g_ops != NULL;
            LeaveCriticalSection(&g_ops_cs);
            unlock();
        }
        if (progressed) changed();
        w[0] = g_work; w[1] = g_chg;
        WaitForMultipleObjects(2, w, FALSE, any ? 20 : INFINITE);
    }
    return 0;
}

static void ops_init(void)
{
    if (g_ops_cs_ok) return;
    kex_spin_acquire((volatile LONG *)&g_init_lock);
    if (!g_ops_cs_ok) {
        DWORD tid;
        InitializeCriticalSection(&g_ops_cs);
        g_work = CreateEventA(NULL, FALSE, FALSE, NULL);
        g_thread = CreateThread(NULL, 0x10000, worker, NULL, 0, &tid);
        g_ops_cs_ok = TRUE;
    }
    InterlockedExchange((LONG *)&g_init_lock, 0);
}

/* Queue a request: ERROR_IO_PENDING, OVERLAPPED.Internal = STATUS_PENDING. */
static BOOL queue_op(int type, int slot, int side, HANDLE h, LPOVERLAPPED ov, BYTE *buf, DWORD len, DWORD done)
{
    OP *o;
    ops_init();
    if (!(o = (OP *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OP)))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    o->type = type; o->slot = slot; o->side = side; o->gen = g_ar->inst[slot].gen; o->cgen = g_ar->inst[slot].cgen;
    o->h = h; o->ov = ov; o->buf = buf; o->len = len; o->done = done;
    ov->Internal = S_PENDING_K; ov->InternalHigh = done;
    ResetEvent(ov->hEvent ? ov->hEvent : h);
    EnterCriticalSection(&g_ops_cs);
    o->next = g_ops; g_ops = o;
    LeaveCriticalSection(&g_ops_cs);
    SetEvent(g_work);
    SetLastError(ERROR_IO_PENDING);
    return FALSE;
}

/* Finish an operation that completed at once (overlapped caller): NT returns TRUE and signals. */
static BOOL done_now(HANDLE h, LPOVERLAPPED ov, DWORD n, LPDWORD out, DWORD status)
{
    if (out) *out = n;
    if (ov) {
        HANDLE ev = ov->hEvent;
        ov->InternalHigh = n; ov->Internal = status;
        if (status == S_OK_K) kex_iocp_done2(h, ov, ev, n, 0, TRUE);
        else if (status == S_BUF_OVERFLOW_K) kex_iocp_done2(h, ov, ev, n, ERROR_MORE_DATA, FALSE);   /* a warning: NT queues it */
        SetEvent(ev ? ev : h);
    }
    if (status == S_OK_K) return TRUE;
    SetLastError(status_to_err(status));
    return FALSE;
}

/* ------------------------------------------------------------------ CreateNamedPipe */
/* build 62: Chrome died in base/sync_socket_win.cc:67 CHECK(handle_a.is_valid()) - CreateNamedPipeW failed with
 * an error other than ERROR_PIPE_BUSY (BUSY makes Chrome retry - forever, if every slot is taken). Every failure
 * now goes to KEXCRASH with the error, the slots in use and the pipe name. */
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
static HANDLE np_fail(DWORD err, const char *name, int line)
{
    static LONG n;
    if (InterlockedIncrement(&n) <= 40) {
        int i, used = 0; char t[160];
        if (g_ar) for (i = 0; i < NP_MAX; i++) if (g_ar->inst[i].state != ST_FREE) used++;
        kex_crashnote("CreateNamedPipe FAILED (error, slots in use, slots, source line)", err, (DWORD)used, NP_MAX, (DWORD)line);
        lstrcpyA(t, "  pipe name: "); lstrcpynA(t + 13, name ? name : "?", 140);
        kex_crashnote(t, 0, 0, 0, 0);
        if (used >= NP_MAX - 2 && g_ar && n <= 2)        /* full: which pipes hold the slots */
            for (i = 0; i < NP_MAX; i++) {
                NPI *q = &g_ar->inst[i];
                lstrcpyA(t, "  slot holds: "); lstrcpynA(t + 14, q->name, 100);
                kex_crashnote(t, (DWORD)q->state, q->srv_pid, q->cli_pid, (DWORD)i);
            }
    }
    SetLastError(err);
    return INVALID_HANDLE_VALUE;
}
HANDLE KEXAPI kex_CreateNamedPipeA(LPCSTR path, DWORD open_mode, DWORD pipe_mode, DWORD max_inst,
                                   DWORD out_size, DWORD in_size, DWORD timeout, LPSECURITY_ATTRIBUTES sa)
{
    char name[NP_NAME], ev[24]; int i, same = 0, slot = -1; HANDLE h; SECURITY_ATTRIBUTES s98;
    BYTE *obj;
    if (!pipe_name_a(path, name)) return np_fail(ERROR_INVALID_NAME, path, __LINE__);
    if (!max_inst || (max_inst > 255 && max_inst != PIPE_UNLIMITED_INSTANCES) ||
        (!(pipe_mode & PIPE_TYPE_MESSAGE) && (pipe_mode & PIPE_READMODE_MESSAGE))) {
        return np_fail(ERROR_INVALID_PARAMETER, name, __LINE__);
    }
    if (!arena()) return np_fail(ERROR_NOT_ENOUGH_MEMORY, name, __LINE__);
    lock();
    reap();
    for (i = 0; i < NP_MAX; i++) {
        NPI *p = &g_ar->inst[i];
        if (p->state == ST_FREE) { if (slot < 0) slot = i; continue; }
        if (!strcmp(p->name, name)) same++;
    }
    if (same && (open_mode & FILE_FLAG_FIRST_PIPE_INSTANCE)) { unlock(); return np_fail(ERROR_ACCESS_DENIED, name, __LINE__); }
    if (same && max_inst != PIPE_UNLIMITED_INSTANCES && same >= (int)max_inst) { unlock(); return np_fail(ERROR_PIPE_BUSY, name, __LINE__); }
    if (slot < 0) { unlock(); return np_fail(ERROR_PIPE_BUSY, name, __LINE__); }
    {
        NPI *p = &g_ar->inst[slot];
        p->gen++;
        end_name(ev, slot, p->gen, 0);
        s98.nLength = sizeof(s98); s98.lpSecurityDescriptor = NULL; s98.bInheritHandle = sa ? sa->bInheritHandle : FALSE;
        h = CreateEventA(&s98, TRUE, FALSE, ev);
        if (!h || !(obj = kex_k32_object(h, K32_EVENT))) {
            DWORD le = GetLastError();
            if (h) CloseHandle(h);
            unlock(); kex_crashnote("  CreateEvent / object lookup for the pipe end failed (handle, error)", (DWORD)(ULONG_PTR)h, le, 0, 0);
            return np_fail(ERROR_NOT_ENOUGH_MEMORY, name, __LINE__);
        }
        drop_aliases((DWORD)obj, slot);                   /* a recycled event address must not alias (build 121: server ends too) */
        lstrcpynA(p->name, name, NP_NAME);
        p->open_mode = open_mode; p->pipe_mode = pipe_mode; p->max_inst = max_inst;
        p->out_size = out_size; p->in_size = in_size;
        p->srv_obj = (DWORD)obj; p->cli_obj = 0;
        p->srv_pid = GetCurrentProcessId(); p->cli_pid = 0;
        p->readmode[0] = pipe_mode & PIPE_READMODE_MESSAGE; p->readmode[1] = 0;
        inst_reset_data(p);
        p->state = ST_LISTENING;
    }
    unlock();
    changed();
    SetLastError(0);
    return h;
}

HANDLE KEXAPI kex_CreateNamedPipeW(LPCWSTR path, DWORD open_mode, DWORD pipe_mode, DWORD max_inst,
                                   DWORD out_size, DWORD in_size, DWORD timeout, LPSECURITY_ATTRIBUTES sa)
{
    char a[NP_NAME + 16], name[NP_NAME]; int i;
    if (!pipe_name_w(path, name)) { SetLastError(ERROR_INVALID_NAME); return INVALID_HANDLE_VALUE; }
    for (i = 0; path[i] && i < (int)sizeof(a) - 1; i++) a[i] = (char)path[i];
    a[i] = 0;
    return kex_CreateNamedPipeA(a, open_mode, pipe_mode, max_inst, out_size, in_size, timeout, sa);
}

/* ------------------------------------------------------------------ server side */
BOOL KEXAPI kex_ConnectNamedPipe(HANDLE h, LPOVERLAPPED ov)
{
    int side, slot; NPI *p;
    if (!arena()) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    for (;;) {
        lock();
        slot = find_end(h, &side);
        if (slot < 0 || side != 0) { unlock(); SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
        p = &g_ar->inst[slot];
        if (p->state == ST_CONNECTED) {
            unlock();
            if (ov) { ov->Internal = 0; ov->InternalHigh = 0; }   /* NT: not pending, event not signalled */
            SetLastError(ERROR_PIPE_CONNECTED); return FALSE;
        }
        if (p->state == ST_CLOSING) { unlock(); SetLastError(ERROR_NO_DATA); return FALSE; }
        if (ov) { BOOL r = queue_op(OP_CONNECT, slot, 0, h, ov, NULL, 0, 0); unlock(); return r; }
        unlock();
        nap();
    }
}

BOOL KEXAPI kex_DisconnectNamedPipe(HANDLE h)
{
    int side, slot;
    if (!arena()) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    lock();
    slot = find_end(h, &side);
    if (slot < 0 || side != 0) { unlock(); SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    {
        NPI *p = &g_ar->inst[slot];
        p->cli_obj = 0; p->cli_pid = 0; p->readmode[1] = 0;   /* the client handle stops being a pipe */
        inst_reset_data(p);
        p->state = ST_LISTENING;
    }
    unlock();
    changed();
    return TRUE;
}

/* ------------------------------------------------------------------ client side */
static HANDLE open_client(const char *name, DWORD access, LPSECURITY_ATTRIBUTES sa)
{
    int i, found = 0; char ev[24]; SECURITY_ATTRIBUTES s98; HANDLE h; BYTE *obj;
    if (!arena()) { SetLastError(ERROR_FILE_NOT_FOUND); return INVALID_HANDLE_VALUE; }
    lock();
    reap();
    for (i = 0; i < NP_MAX; i++) {
        NPI *p = &g_ar->inst[i];
        if (p->state == ST_FREE || strcmp(p->name, name)) continue;
        found++;
        if (p->state != ST_LISTENING) continue;
        p->cgen++;
        end_name(ev, i, p->cgen, 1);
        s98.nLength = sizeof(s98); s98.lpSecurityDescriptor = NULL; s98.bInheritHandle = sa ? sa->bInheritHandle : FALSE;
        h = CreateEventA(&s98, TRUE, FALSE, ev);
        if (!h || !(obj = kex_k32_object(h, K32_EVENT))) {
            DWORD le = GetLastError(); int used = 0, q;   /* build 83: browser FATAL platform_channel.cc:112 came from here */
            for (q = 0; q < NP_MAX; q++) if (g_ar->inst[q].state != ST_FREE) used++;
            if (h) CloseHandle(h);
            unlock();
            kex_crashnote("pipe client end: CreateEvent / object lookup failed (handle, error, slots in use, slot)", (DWORD)(ULONG_PTR)h, le, (DWORD)used, (DWORD)i);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY); return INVALID_HANDLE_VALUE;
        }
        drop_aliases((DWORD)obj, i);                      /* build 121: server ends too */
        p->cli_obj = (DWORD)obj; p->cli_pid = GetCurrentProcessId(); p->readmode[1] = 0;
        p->state = ST_CONNECTED;
        unlock();
        changed();
        SetLastError(0);
        return h;
    }
    unlock();
    SetLastError(found ? ERROR_PIPE_BUSY : ERROR_FILE_NOT_FOUND);
    return INVALID_HANDLE_VALUE;
}

BOOL KEXAPI kex_WaitNamedPipeA(LPCSTR path, DWORD timeout)
{
    char name[NP_NAME]; DWORD start = GetTickCount();
    if (!pipe_name_a(path, name)) { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    if (timeout == NMPWAIT_USE_DEFAULT_WAIT) timeout = 50;
    if (!arena()) { SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }
    for (;;) {
        int i, found = 0, listening = 0;
        lock();
        reap();
        for (i = 0; i < NP_MAX; i++) {
            NPI *p = &g_ar->inst[i];
            if (p->state == ST_FREE || strcmp(p->name, name)) continue;
            found++;
            if (p->state == ST_LISTENING) listening++;
        }
        unlock();
        if (listening) return TRUE;
        if (!found) { SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }
        if (timeout != NMPWAIT_WAIT_FOREVER && GetTickCount() - start >= timeout) { SetLastError(ERROR_SEM_TIMEOUT); return FALSE; }
        nap();
    }
}
BOOL KEXAPI kex_WaitNamedPipeW(LPCWSTR path, DWORD timeout)
{
    char a[NP_NAME + 16]; int i;
    if (!path) { SetLastError(ERROR_INVALID_NAME); return FALSE; }
    for (i = 0; path[i] && i < (int)sizeof(a) - 1; i++) a[i] = path[i] < 0x7F ? (char)path[i] : '?';
    a[i] = 0;
    return kex_WaitNamedPipeA(a, timeout);
}

/* ------------------------------------------------------------------ handle state / info */
BOOL KEXAPI kex_SetNamedPipeHandleState(HANDLE h, LPDWORD mode, LPDWORD max_coll, LPDWORD timeout)
{
    int side, slot;
    if (!arena()) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    lock();
    slot = find_end(h, &side);
    if (slot < 0) { unlock(); SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (mode) {
        NPI *p = &g_ar->inst[slot];
        if ((*mode & PIPE_READMODE_MESSAGE) && !(p->pipe_mode & PIPE_TYPE_MESSAGE)) { unlock(); SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        p->readmode[side] = *mode & PIPE_READMODE_MESSAGE;
    }
    unlock();
    return TRUE;
}

BOOL KEXAPI kex_GetNamedPipeInfo(HANDLE h, LPDWORD flags, LPDWORD out_size, LPDWORD in_size, LPDWORD max_inst)
{
    int side, slot; NPI *p;
    if (!arena()) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    lock();
    slot = find_end(h, &side);
    if (slot < 0) { unlock(); SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    p = &g_ar->inst[slot];
    if (flags) *flags = (side ? PIPE_CLIENT_END : PIPE_SERVER_END) | (p->pipe_mode & PIPE_TYPE_MESSAGE);
    if (out_size) *out_size = NP_BUF;
    if (in_size) *in_size = NP_BUF;
    if (max_inst) *max_inst = p->max_inst;
    unlock();
    return TRUE;
}

BOOL KEXAPI kex_GetNamedPipeClientProcessId(HANDLE h, PULONG pid)
{
    int side, slot;
    if (!pid || !arena()) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    lock(); slot = find_end(h, &side);
    if (slot < 0) { unlock(); SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    { DWORD kex_pid_nt(DWORD real); *pid = kex_pid_nt(g_ar->inst[slot].cli_pid); } unlock();   /* build 131 */
    return TRUE;
}
BOOL KEXAPI kex_GetNamedPipeServerProcessId(HANDLE h, PULONG pid)
{
    int side, slot;
    if (!pid || !arena()) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    lock(); slot = find_end(h, &side);
    if (slot < 0) { unlock(); SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    { DWORD kex_pid_nt(DWORD real); *pid = kex_pid_nt(g_ar->inst[slot].srv_pid); } unlock();   /* build 131 */
    return TRUE;
}

BOOL KEXAPI kex_PeekNamedPipe(HANDLE h, LPVOID buf, DWORD size, LPDWORD read, LPDWORD avail, LPDWORD left)
{
    int side, slot; NPI *p; RING *r; BOOL more; DWORD n, total;
    if (!is_event_handle(h)) return PeekNamedPipe(h, buf, size, read, avail, left);
    if (!arena()) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    lock();
    slot = find_end(h, &side);
    if (slot < 0) { unlock(); SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    p = &g_ar->inst[slot]; r = &p->ring[side];
    if (!r->used && (p->state != ST_CONNECTED || !alive(p, slot, !side))) {
        unlock(); SetLastError(p->state == ST_LISTENING ? ERROR_BAD_PIPE : ERROR_BROKEN_PIPE); return FALSE;
    }
    n = ring_get(r, (BYTE *)buf, buf ? size : 0, p->readmode[side] != 0, &more, FALSE);
    total = ring_get(r, NULL, 0xFFFFFFFFUL, p->readmode[side] != 0, &more, FALSE);
    if (read) *read = n;
    if (avail) *avail = r->used;
    if (left) *left = (p->readmode[side] && total > n) ? total - n : 0;
    unlock();
    return TRUE;
}

/* ------------------------------------------------------------------ read / write on pipe ends */
static BOOL pipe_read(HANDLE h, int slot, int side, BYTE *buf, DWORD n, LPDWORD out, LPOVERLAPPED ov)
{
    for (;;) {
        NPI *p; RING *r; BOOL more;
        lock();
        p = &g_ar->inst[slot]; r = &p->ring[side];
        if (r->used) {
            DWORD got = ring_get(r, buf, n, p->readmode[side] != 0, &more, TRUE);
            unlock(); changed();
            return done_now(h, ov, got, out, more ? S_BUF_OVERFLOW_K : S_OK_K);
        }
        if (p->state == ST_LISTENING) { unlock(); if (out) *out = 0; SetLastError(ERROR_PIPE_LISTENING); return FALSE; }
        if (p->state != ST_CONNECTED || !alive(p, slot, !side)) {
            if (p->state == ST_CONNECTED) note_broken(p, side);
            if (side == 0 && p->state == ST_CONNECTED) p->state = ST_CLOSING;
            unlock(); if (out) *out = 0; SetLastError(ERROR_BROKEN_PIPE); return FALSE;
        }
        if (ov) { BOOL r2 = queue_op(OP_READ, slot, side, h, ov, buf, n, 0); unlock(); if (out) *out = 0; return r2; }
        unlock();
        nap();
    }
}

/* build 80: the last pipe writes of this process, for the crash log. A renderer died at
 * child_process_sandbox_support_impl_win.cc:41 because the browser refused its LcidAndFirstDayOfWeek request
 * ("Locale larger than LOCALE_NAME_MAX_LENGTH", chrome.dll 13bdeb25: locale > 85 or default language > 85
 * UTF-16 characters) - the request is the renderer's last message before the CHECK, so it is in this ring. */
#define RW_N 4
#define RW_B 512
static struct { DWORD tick, n; int slot; BYTE b[RW_B]; } g_rw[RW_N];
static volatile LONG g_rw_lock, g_rw_next;
static void remember_write(int slot, const BYTE *buf, DWORD n)
{
    LONG i;
    if (!buf || !n || IsBadReadPtr(buf, n < RW_B ? n : RW_B)) return;
    kex_spin_acquire(&g_rw_lock);
    i = g_rw_next; g_rw_next = (i + 1) % RW_N;
    g_rw[i].tick = GetTickCount(); g_rw[i].n = n; g_rw[i].slot = slot;
    memcpy(g_rw[i].b, buf, n < RW_B ? n : RW_B);
    InterlockedExchange(&g_rw_lock, 0);
}
static int udec(char *d, DWORD v) { char t[12]; int i = 11, o = 0; t[i] = 0; do { t[--i] = (char)('0' + v % 10); v /= 10; } while (v); while (t[i]) d[o++] = t[i++]; d[o] = 0; return o; }
/* crashlog_ext.c: oldest first; each as UTF-16 text runs (>= 2 characters) and ASCII runs (>= 4) */
void kex_pipe_recent(void (*put)(const char *))
{
    LONG k, i; char t[640];
    for (k = 0; k < RW_N; k++) {
        DWORD n, j, m; int o = 0, run;
        i = (g_rw_next + k) % RW_N;
        if (!g_rw[i].n) continue;
        n = g_rw[i].n < RW_B ? g_rw[i].n : RW_B;
        o = 0; lstrcpyA(t, "    pipe write: slot "); o = lstrlenA(t); o += udec(t + o, (DWORD)g_rw[i].slot);
        lstrcpyA(t + o, ", bytes "); o += 8; o += udec(t + o, g_rw[i].n); lstrcpyA(t + o, ", tick "); o += 7;
        o += udec(t + o, g_rw[i].tick); lstrcpyA(t + o, "\r\n      utf16:"); put(t);
        for (j = 0; j + 1 < n; ) {          /* UTF-16LE printable runs */
            for (m = j; m + 1 < n && g_rw[i].b[m] >= 32 && g_rw[i].b[m] < 127 && !g_rw[i].b[m + 1]; m += 2) ;
            run = (int)(m - j) / 2;
            if (run >= 2) {
                o = 0; t[o++] = ' '; t[o++] = '"';
                for (; j < m && o < 600; j += 2) t[o++] = (char)g_rw[i].b[j];
                t[o++] = '"'; t[o++] = '('; o += udec(t + o, (DWORD)run); t[o++] = ')'; t[o] = 0; put(t);
            }
            j = m > j ? m : j + 1;
        }
        put("\r\n      ascii:");
        for (j = 0; j < n; ) {
            for (m = j; m < n && g_rw[i].b[m] >= 32 && g_rw[i].b[m] < 127; m++) ;
            if (m - j >= 4) {
                o = 0; t[o++] = ' '; t[o++] = '"';
                for (; j < m && o < 600; j++) t[o++] = (char)g_rw[i].b[j];
                t[o++] = '"'; t[o] = 0; put(t);
            }
            j = m > j ? m : j + 1;
        }
        put("\r\n");
    }
}

static BOOL pipe_write(HANDLE h, int slot, int side, const BYTE *buf, DWORD n, LPDWORD out, LPOVERLAPPED ov)
{
    DWORD done = 0;
    remember_write(slot, buf, n);
    for (;;) {
        NPI *p; RING *r;
        lock();
        p = &g_ar->inst[slot]; r = &p->ring[!side];
        if (p->state != ST_CONNECTED || !alive(p, slot, !side)) {
            DWORD e = p->state == ST_LISTENING ? ERROR_PIPE_LISTENING : ERROR_NO_DATA;
            if (side == 0 && p->state == ST_CONNECTED) p->state = ST_CLOSING;
            unlock(); if (out) *out = done; SetLastError(e); return FALSE;
        }
        while (done < n) {
            DWORD f = ring_free(r), k = n - done;
            if (!f) break;
            if (k > f) k = f;
            ring_put(r, buf + done, k, done + k < n);
            done += k;
        }
        if (done == n || n == 0) {
            if (n == 0 && (p->pipe_mode & PIPE_TYPE_MESSAGE) && ring_free(r)) ring_put(r, buf, 0, FALSE);  /* empty message */
            unlock(); changed();
            return done_now(h, ov, done, out, S_OK_K);
        }
        if (ov) { BOOL r2 = queue_op(OP_WRITE, slot, side, h, ov, (BYTE *)buf, n, done); unlock(); changed(); if (out) *out = 0; return r2; }
        unlock(); changed();
        nap();
    }
}

BOOL KEXAPI kex_TransactNamedPipe(HANDLE h, LPVOID in, DWORD in_size, LPVOID out, DWORD out_size,
                                  LPDWORD read, LPOVERLAPPED ov)
{
    int side, slot; DWORD w; BOOL ok;
    if (!arena()) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    lock(); slot = find_end(h, &side); unlock();
    if (slot < 0) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (!g_ar->inst[slot].readmode[side]) { SetLastError(ERROR_BAD_PIPE); return FALSE; }   /* NT: message read mode required */
    if (!pipe_write(h, slot, side, (const BYTE *)in, in_size, &w, NULL)) return FALSE;
    ok = pipe_read(h, slot, side, (BYTE *)out, out_size, read, NULL);      /* synchronous, as Crashpad uses it */
    if (ov) {
        DWORD e = ok ? 0 : GetLastError();
        ov->InternalHigh = read ? *read : 0;
        ov->Internal = ok ? S_OK_K : (e == ERROR_MORE_DATA ? S_BUF_OVERFLOW_K : S_PIPE_BROKEN_K);
        SetEvent(ov->hEvent ? ov->hEvent : h);
        if (!ok) SetLastError(e);
    }
    return ok;
}

/* ------------------------------------------------------------------ KERNEL32 replacements */
/* KernelEx 4.5 CreateFileA_fix behaviour for ordinary files (kexbases/Kernel32/file.c). */
void kex_fview_file_opened(HANDLE h, DWORD access);       /* fview_ext.c */
void kex_fview_written(HANDLE h, const BYTE *buf, DWORD n, DWORD off_lo, DWORD off_hi);
BOOL kex_fview_any(void);
/* after a successful WriteFile on an ordinary file: keep private read-only views of it current (fview_ext.c) */
static void file_written(HANDLE h, const BYTE *buf, DWORD n, LPOVERLAPPED ov)
{
    DWORD le;
    if (!n || !kex_fview_any()) return;
    le = GetLastError();
    if (ov) kex_fview_written(h, buf, n, ov->Offset, ov->OffsetHigh);
    else {
        LONG hi = 0; DWORD lo = SetFilePointer(h, 0, &hi, FILE_CURRENT);     /* position after the write */
        if (lo != 0xFFFFFFFF || GetLastError() == NO_ERROR) {
            unsigned __int64 pos = (((unsigned __int64)(DWORD)hi) << 32 | lo) - n;
            kex_fview_written(h, buf, n, (DWORD)pos, (DWORD)(pos >> 32));
        }
    }
    SetLastError(le);
}

/* build 125: "\\?\C:\..." (Win32 long-path prefix; Qt 5 puts it on every absolute path). Measured with
 * LPATH.EXE / FREAD.EXE: Windows 98's GetFileAttributes, FindFirstFile, CreateDirectory, MoveFile, DeleteFile and
 * GetFullPathName accept the prefix, but CreateFile returns a strange handle: GetFileType 0, no size, no file
 * pointer, and every ReadFile returns the file from its start again. Qt's QSettings read loop (read until 0
 * bytes) then never ended - VLC 3's Qt interface read vlc-qt-interface.ini forever, growing its buffer by about
 * 300 KB/s (SAMPLE.EXE + PEEK.EXE in the test VM: the buffer held "[General] updatedate=..." over and over) until
 * memory ran out. CreateFile now drops the prefix ("\\?\UNC\server\share" -> "\\server\share"). */
static LPCSTR strip_long_prefix(LPCSTR name, char *buf, int cb)
{
    if (!name || name[0] != '\\' || name[1] != '\\' || name[2] != '?' || name[3] != '\\') return name;
    if ((name[4] | 32) == 'u' && (name[5] | 32) == 'n' && (name[6] | 32) == 'c' && name[7] == '\\') {
        if (lstrlenA(name + 8) + 3 > cb) return name;
        buf[0] = '\\'; buf[1] = '\\'; lstrcpyA(buf + 2, name + 8);
        return buf;
    }
    return name + 4;
}

static HANDLE create_file_a_kex(LPCSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                                DWORD disp, DWORD flags, HANDLE templ)
{
    char unc[MAX_PATH * 2];
    name = strip_long_prefix(name, unc, sizeof(unc));
    if (access & ~0xF0010100UL) {
        DWORD old = access;
        access &= 0xF0010100UL;
        if (old & FILE_READ_DATA) access |= GENERIC_READ;
        if (old & (FILE_WRITE_DATA | FILE_APPEND_DATA)) access |= GENERIC_WRITE;
        if (old & FILE_EXECUTE) access |= GENERIC_EXECUTE;
        /* FILE_APPEND_DATA alone ("append only", Chromium's --log-file, base/logging.cc): 9x has no such right, so the
         * handle had no write access at all and the log stayed empty. Write access, positioned at the end. */
        if ((old & FILE_APPEND_DATA) && !(old & FILE_WRITE_DATA) && !(flags & (FILE_FLAG_OVERLAPPED | FILE_FLAG_BACKUP_SEMANTICS))) {
            HANDLE h = CreateFileA(name, access, share & ~FILE_SHARE_DELETE, sa, disp, flags, NULL);
            if (h != INVALID_HANDLE_VALUE) { DWORD le = GetLastError(); SetFilePointer(h, 0, NULL, FILE_END); SetLastError(le); }
            return h;
        }
    }
    share &= ~FILE_SHARE_DELETE;
    templ = NULL;
    {   /* directories (FILE_FLAG_BACKUP_SEMANTICS): see dirhandle_ext.c */
        HANDLE kex_dir_open(LPCSTR name, DWORD disp, DWORD flags);
        HANDLE d = kex_dir_open(name, disp, flags);
        if (d) return d;
    }
    if (flags & FILE_FLAG_OVERLAPPED) {
        DWORD le = GetLastError();
        HANDLE h = CreateFileA(name, access, share, sa, disp, flags, templ);
        if (h != INVALID_HANDLE_VALUE) return h;
        SetLastError(le);
        flags &= ~FILE_FLAG_OVERLAPPED;
    }
    {   HANDLE h = CreateFileA(name, access, share, sa, disp, flags, templ);
        /* build 50: Windows 98 refuses GENERIC_EXECUTE on files (error 87); NT programs open DLLs with
         * GENERIC_READ | GENERIC_EXECUTE (Chromium: its own chrome.dll). Reading is what they do with it. */
        if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_PARAMETER && (access & (GENERIC_EXECUTE | GENERIC_ALL))) {
            DWORD a2 = (access & ~(GENERIC_EXECUTE | GENERIC_ALL)) | GENERIC_READ | ((access & GENERIC_ALL) ? GENERIC_WRITE : 0);
            h = CreateFileA(name, a2, share, sa, disp, flags, templ);
        }
        return h; }
}

HANDLE KEXAPI kex_CreateFileA(LPCSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                              DWORD disp, DWORD flags, HANDLE templ)
{
    char pn[NP_NAME];
    if (pipe_name_a(name, pn) && arena())            /* \\.\pipe\x is always local; \\server\pipe\x goes to Win98 */
        return open_client(pn, access, sa);
    {
        HANDLE h = create_file_a_kex(name, access, share, sa, disp, flags, templ);
        DWORD le = GetLastError();
        { void kex_fpath_note(HANDLE h, LPCSTR name); if (h != INVALID_HANDLE_VALUE && !(flags & FILE_FLAG_BACKUP_SEMANTICS)) kex_fpath_note(h, name); }
        kex_fview_file_opened(h, access);                  /* fview_ext.c: can this handle write? */
        SetLastError(le);
        return h;
    }
}

HANDLE KEXAPI kex_CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                              DWORD disp, DWORD flags, HANDLE templ)
{
    char stack[MAX_PATH * 2], *a = stack; int n; HANDLE h; DWORD le; char pn[NP_NAME];
    UINT cp = AreFileApisANSI() ? CP_ACP : CP_OEMCP;
    if (!name) { SetLastError(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE; }
    if (pipe_name_w(name, pn) && arena())
        return open_client(pn, access, sa);
    n = WideCharToMultiByte(cp, 0, name, -1, NULL, 0, NULL, NULL);
    if (n <= 0) { SetLastError(ERROR_INVALID_NAME); return INVALID_HANDLE_VALUE; }
    if (n > (int)sizeof(stack) && !(a = (char *)HeapAlloc(GetProcessHeap(), 0, n))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return INVALID_HANDLE_VALUE; }
    WideCharToMultiByte(cp, 0, name, -1, a, n, NULL, NULL);
    h = create_file_a_kex(a, access, share, sa, disp, flags, templ);
    le = GetLastError();
    /* build 51: also "not found" when the program wanted to CREATE the file (a missing folder) */
    if (h == INVALID_HANDLE_VALUE && ((le != ERROR_FILE_NOT_FOUND && le != ERROR_PATH_NOT_FOUND && le != ERROR_FILE_EXISTS && le != ERROR_ALREADY_EXISTS) ||
                                      ((le == ERROR_FILE_NOT_FOUND || le == ERROR_PATH_NOT_FOUND) && disp != OPEN_EXISTING && disp != TRUNCATE_EXISTING)))
    { void kex_filefail(const char *api, const char *path, DWORD err, DWORD a, DWORD b); kex_filefail("CreateFileW (access, disposition)", a, le, access, disp); }
    { void kex_fpath_note(HANDLE h, LPCSTR name); if (h != INVALID_HANDLE_VALUE && !(flags & FILE_FLAG_BACKUP_SEMANTICS)) kex_fpath_note(h, a); }
    { void kex_dl_note(const char *api, const char *path, BOOL ok, DWORD err, DWORD x); kex_dl_note("CreateFileW", a, h != INVALID_HANDLE_VALUE, le, disp); }
    kex_fview_file_opened(h, access);                      /* fview_ext.c */
    if (a != stack) HeapFree(GetProcessHeap(), 0, a);
    SetLastError(le);
    return h;
}

/* Build 85: Windows 98 has no positional file I/O (OVERLAPPED offsets on disk files), so an NT read/write "at
 * offset X" is done here as SetFilePointer + ReadFile/WriteFile. Those two steps were not atomic: Chromium reads
 * one file handle from several threads at once (disk cache, extension and script files) and a second thread could
 * move the file pointer between the seek and the read - the read then returned bytes from the wrong place
 * (build 84 log: "SyntaxError: Invalid or unexpected token" / "Unexpected EOF" in scripts that are valid,
 * uBlock Origin Lite's background.js unreadable). Every seek+I/O pair on a handle now runs under a lock
 * chosen by the handle value (32 locks; handles that share a lock just wait for each other). */
#define FPOS_LOCKS 32
static CRITICAL_SECTION g_fpos[FPOS_LOCKS];
static volatile LONG g_fpos_state, g_fpos_busy[FPOS_LOCKS], g_fpos_contended;
/* Build 99: the lock is chosen by the FILE OBJECT, not the handle value. A DuplicateHandle copy (Chromium's
 * base::File::Duplicate) is another handle to the same Windows 98 file object and so shares its one file pointer;
 * keyed by handle value the two copies took different locks and a seek on one could land between the seek and the
 * read of the other. Which lock a thread took is remembered (per thread, nested) so unlock never has to look the
 * handle up again (it may have been closed meanwhile). */
BYTE *kex_k32_object(HANDLE h, int type);            /* chrome_ext.c */
#define K32OBJ_FILE_ 8
/* Build 102: ONE lock for every disk file. kextest (builds 99, 101) still read the wrong bytes through a
 * DuplicateHandle copy - "read at 269800: word 0 holds 160092" - with the file pointer where it should be
 * afterwards: on Windows 98 a duplicated file handle is not (always) the same K32 object, yet both reach the same
 * file underneath, so two locks let two reads of the same file run at once. There is no reliable way to tell from
 * a handle which other handles share its file, so all seek+read/write pairs on disk files are serialised. One disk,
 * one CPU: nothing is lost. */
static int fpos_ix(HANDLE h)
{
    (void)h; (void)kex_k32_object; return 0;
}
#define FPOS_HELD 256
static struct { DWORD tid; int ix; } g_held[FPOS_HELD];
static volatile LONG g_held_lk;
static void held_push(int i)
{
    DWORD me = GetCurrentThreadId(); int k;
    kex_spin_acquire(&g_held_lk);
    for (k = 0; k < FPOS_HELD; k++) if (!g_held[k].tid) { g_held[k].tid = me; g_held[k].ix = i; break; }
    InterlockedExchange(&g_held_lk, 0);
}
static int held_pop(void)
{
    DWORD me = GetCurrentThreadId(); int k, last = -1, i = -1;
    kex_spin_acquire(&g_held_lk);
    for (k = 0; k < FPOS_HELD; k++) if (g_held[k].tid == me) last = k;   /* the innermost = the last one pushed */
    if (last >= 0) { i = g_held[last].ix; g_held[last].tid = 0; }
    InterlockedExchange(&g_held_lk, 0);
    return i;
}
void kex_fpos_lock(HANDLE h)
{
    int i = fpos_ix(h);
    if (g_fpos_state != 2) {
        if (InterlockedCompareExchange(&g_fpos_state, 1, 0) == 0) {
            int k; for (k = 0; k < FPOS_LOCKS; k++) InitializeCriticalSection(&g_fpos[k]);
            InterlockedExchange(&g_fpos_state, 2);
        } else while (g_fpos_state != 2) Sleep(0);
    }
    if (InterlockedIncrement(&g_fpos_busy[i]) > 1) {       /* someone else is between seek and I/O on this lock */
        LONG n = InterlockedIncrement(&g_fpos_contended);
        if (n <= 5 || n == 100 || n == 1000) {
            void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
            kex_crashnote("positional file I/O: another thread was using the same file lock at once (handle, times so far)",
                          (DWORD)(ULONG_PTR)h, (DWORD)n, 0, 0);
        }
    }
    EnterCriticalSection(&g_fpos[i]);
    held_push(i);
}
void kex_fpos_unlock(HANDLE h)
{
    int i = held_pop();
    if (i < 0) i = fpos_ix(h);                             /* table full when it was taken (not expected) */
    LeaveCriticalSection(&g_fpos[i]);
    InterlockedDecrement(&g_fpos_busy[i]);
}

/* Build 99: proof, not assumption. After every emulated read/write at an offset (still under the lock) the file
 * pointer must stand exactly at offset + bytes moved. If it does not, someone moved it while we were using it -
 * the bytes came from (or went to) the wrong place. Logged with the file's path. */
static void fpos_check(HANDLE h, DWORD off, DWORD offhi, DWORD moved, int write)
{
    LONG hi = 0; DWORD cur, le = GetLastError();
    static volatile LONG n;
    cur = SetFilePointer(h, 0, &hi, FILE_CURRENT);
    if ((cur == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) || (cur == off + moved && (DWORD)hi == offhi)) { SetLastError(le); return; }
    if (InterlockedIncrement(&n) <= 40) {
        void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d); void kex_crashlog_text(const char *s);
        BOOL kex_fpath_get(HANDLE h, char *buf, DWORD cb); char t[MAX_PATH + 16];
        kex_crashnote(write ? "positional file I/O: FILE POINTER MOVED BY SOMEONE ELSE during a write - data went to the wrong place (handle, offset, bytes, pointer after)"
                            : "positional file I/O: FILE POINTER MOVED BY SOMEONE ELSE during a read - data came from the wrong place (handle, offset, bytes, pointer after)",
                      (DWORD)(ULONG_PTR)h, off, moved, cur);
        lstrcpyA(t, "    file: "); if (!kex_fpath_get(h, t + 10, MAX_PATH)) lstrcpyA(t + 10, "(path unknown)");
        kex_crashlog_text(t);
    }
    SetLastError(le);
}
void kex_fpos_check(HANDLE h, DWORD off, DWORD offhi, DWORD moved, int write) { fpos_check(h, off, offhi, moved, write); }
static int is_disk(HANDLE h)
{
    DWORD le = GetLastError(); int d = GetFileType(h) == FILE_TYPE_DISK;
    SetLastError(le); return d;
}

/* Build 92: NT fills the space between a file's old end and a write (or SetEndOfFile, or a file mapping)
 * further out with zeros. Windows 98 does not: the new part of the file holds whatever was on the disk
 * before (SetEndOfFile on 9x: "the contents ... between the old end and the new end are not defined").
 * Chromium relies on the zeros - its metrics files (BrowserMetrics .pma: "Corruption detected in
 * shared-memory segment", build 91 log) and disk cache entries are made by growing a file and then filling
 * parts of it. Old disk contents inside them read back as garbage (scripts: "SyntaxError: Invalid or
 * unexpected token" at line 1, build 91 log, every discord.com script and uBlock's background.js).
 * kex_zero_gap: if (lo,hi) is past the end of the disk file h, write zeros from the end up to it.
 * The caller holds kex_fpos_lock(h). The file pointer is left at (lo,hi) when it returns 1. */
static const BYTE g_zeros[16384];
static volatile LONG g_zero_notes;
int kex_zero_gap(HANDLE h, DWORD lo, DWORD hi)
{
    DWORD shi = 0, size, gap, le = GetLastError();
    if (hi) return 0;                                     /* FAT32: 4 GB files at most */
    if (GetFileType(h) != FILE_TYPE_DISK) { SetLastError(le); return 0; }
    size = GetFileSize(h, &shi);
    if ((size == 0xFFFFFFFF && GetLastError() != NO_ERROR) || shi || lo <= size) { SetLastError(le); return 0; }
    gap = lo - size;
    {   LONG n = InterlockedIncrement(&g_zero_notes);
        if (n <= 6 || n == 100 || n == 1000 || n == 10000) {
            void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
            kex_crashnote("file grown: the new part filled with zeros as on NT (handle, old size, new size, times so far)",
                          (DWORD)(ULONG_PTR)h, size, lo, (DWORD)n);
        }
    }
    if (gap > (256u << 20)) { SetLastError(le); return 0; }    /* not a real case: leave it to Windows */
    if (SetFilePointer(h, (LONG)size, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) { SetLastError(le); return 0; }
    while (gap) {
        DWORD w = gap > sizeof(g_zeros) ? sizeof(g_zeros) : gap, put = 0;
        if (!WriteFile(h, g_zeros, w, &put, NULL) || !put) break;
        if (kex_fview_any()) kex_fview_written(h, g_zeros, put, lo - gap, 0);
        gap -= put;
    }
    SetFilePointer(h, (LONG)lo, NULL, FILE_BEGIN);
    SetLastError(le);
    return 1;
}
/* the same at the file pointer (sequential writes after a seek past the end, SetEndOfFile) */
void kex_zero_to_pos(HANDLE h)
{
    LONG hi = 0; DWORD lo, le = GetLastError();
    if (GetFileType(h) != FILE_TYPE_DISK) { SetLastError(le); return; }
    kex_fpos_lock(h);
    lo = SetFilePointer(h, 0, &hi, FILE_CURRENT);
    if (lo != INVALID_SET_FILE_POINTER || GetLastError() == NO_ERROR) kex_zero_gap(h, lo, (DWORD)hi);
    kex_fpos_unlock(h);
    SetLastError(le);
}

/* KernelEx 4.5 ReadFile_fix / WriteFile_fix for ordinary handles: Win98 rejects OVERLAPPED on disk files,
 * so seek to the requested offset, do it synchronously and complete the OVERLAPPED. */
BOOL KEXAPI kex_ReadFile(HANDLE h, LPVOID buf, DWORD n, LPDWORD got, LPOVERLAPPED ov)
{
    DWORD le = GetLastError();
    if (is_event_handle(h) && arena()) {
        int side, slot;
        lock(); slot = find_end(h, &side); unlock();
        if (slot >= 0) return pipe_read(h, slot, side, (BYTE *)buf, n, got, ov);
        SetLastError(ERROR_PIPE_NOT_CONNECTED);          /* a disconnected client end */
        return FALSE;
    }
    if (!ov && is_disk(h)) {                             /* build 99: a sequential read may not split a seek+read pair */
        BOOL r; kex_fpos_lock(h); r = ReadFile(h, buf, n, got, NULL);
        { DWORD e = GetLastError(); kex_fpos_unlock(h); SetLastError(e); }
        return r;
    }
    if (ReadFile(h, buf, n, got, ov)) {
        if (ov) kex_iocp_done(h, ov, got ? *got : (DWORD)ov->InternalHigh, 0, TRUE);
        return TRUE;
    }
    if (ov && GetLastError() == ERROR_INVALID_PARAMETER) {
        LONG high = (LONG)ov->OffsetHigh; BOOL r;
        SetLastError(le);
        kex_fpos_lock(h);
        if (SetFilePointer(h, ov->Offset, &high, FILE_BEGIN) == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
            le = GetLastError(); kex_fpos_unlock(h); SetLastError(le);
            return FALSE;
        }
        if (ov->hEvent) ResetEvent(ov->hEvent);
        ov->Internal = S_PENDING_K; ov->InternalHigh = 0;
        r = ReadFile(h, buf, n, (LPDWORD)&ov->InternalHigh, NULL);
        le = GetLastError();
        if (r) fpos_check(h, ov->Offset, ov->OffsetHigh, (DWORD)ov->InternalHigh, 0);
        kex_fpos_unlock(h);
        ov->Internal = 0;
        if (ov->hEvent) SetEvent(ov->hEvent);
        if (r) kex_iocp_done(h, ov, (DWORD)ov->InternalHigh, 0, TRUE);   /* completion port packet, as on NT */
        SetLastError(le);
        if (got) *got = (DWORD)ov->InternalHigh;
        return r;
    }
    return FALSE;
}

BOOL KEXAPI kex_WriteFile(HANDLE h, LPCVOID buf, DWORD n, LPDWORD put, LPOVERLAPPED ov)
{
    DWORD le = GetLastError();
    if (is_event_handle(h) && arena()) {
        int side, slot;
        lock(); slot = find_end(h, &side); unlock();
        if (slot >= 0) return pipe_write(h, slot, side, (const BYTE *)buf, n, put, ov);
        SetLastError(ERROR_PIPE_NOT_CONNECTED);
        return FALSE;
    }
    if (!ov && is_disk(h)) {                             /* build 99: zero-fill + write as one step under the lock */
        BOOL r; kex_fpos_lock(h);
        kex_zero_to_pos(h);                              /* build 92 */
        r = WriteFile(h, buf, n, put, NULL);
        { DWORD e = GetLastError(); kex_fpos_unlock(h); SetLastError(e); }
        if (r) file_written(h, (const BYTE *)buf, put ? *put : n, NULL);
        return r;
    }
    if (WriteFile(h, buf, n, put, ov)) {
        if (ov) kex_iocp_done(h, ov, put ? *put : (DWORD)ov->InternalHigh, 0, TRUE);
        file_written(h, (const BYTE *)buf, put ? *put : n, ov);
        return TRUE;
    }
    if (ov && GetLastError() == ERROR_INVALID_PARAMETER) {
        LONG high = (LONG)ov->OffsetHigh; BOOL r;
        SetLastError(le);
        kex_fpos_lock(h);
        kex_zero_gap(h, ov->Offset, ov->OffsetHigh);    /* build 92: a write past the end - zeros in between */
        if (SetFilePointer(h, ov->Offset, &high, FILE_BEGIN) == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
            le = GetLastError(); kex_fpos_unlock(h); SetLastError(le);
            return FALSE;
        }
        if (ov->hEvent) ResetEvent(ov->hEvent);
        ov->Internal = S_PENDING_K; ov->InternalHigh = 0;
        r = WriteFile(h, buf, n, (LPDWORD)&ov->InternalHigh, NULL);
        le = GetLastError();
        if (r) fpos_check(h, ov->Offset, ov->OffsetHigh, (DWORD)ov->InternalHigh, 1);
        kex_fpos_unlock(h);
        ov->Internal = 0;
        if (ov->hEvent) SetEvent(ov->hEvent);
        if (r) kex_iocp_done(h, ov, (DWORD)ov->InternalHigh, 0, TRUE);   /* completion port packet, as on NT */
        if (r) file_written(h, (const BYTE *)buf, (DWORD)ov->InternalHigh, ov);
        SetLastError(le);
        if (put) *put = (DWORD)ov->InternalHigh;
        return r;
    }
    return FALSE;
}

BOOL KEXAPI kex_GetOverlappedResult(HANDLE h, LPOVERLAPPED ov, LPDWORD n, BOOL wait)
{
    DWORD st;
    if (!is_event_handle(h)) return GetOverlappedResult(h, ov, n, wait);
    if (!ov) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    while ((st = (DWORD)ov->Internal) == S_PENDING_K) {
        if (!wait) { SetLastError(ERROR_IO_INCOMPLETE); return FALSE; }
        WaitForSingleObject(ov->hEvent ? ov->hEvent : h, 50);
    }
    if (n) *n = (DWORD)ov->InternalHigh;
    if (st == S_OK_K) return TRUE;
    SetLastError(status_to_err(st));
    return FALSE;
}

static int cancel_ops(HANDLE h, LPOVERLAPPED ov)
{
    OP *o; int n = 0;
    if (!g_ops_cs_ok) return 0;
    EnterCriticalSection(&g_ops_cs);
    for (o = g_ops; o; o = o->next)
        if (o->h == h && (!ov || o->ov == ov)) { o->cancel = TRUE; n++; }
    LeaveCriticalSection(&g_ops_cs);
    if (n) SetEvent(g_work);
    return n;
}

BOOL KEXAPI kex_CancelIo(HANDLE h)
{
    if (is_event_handle(h)) { cancel_ops(h, NULL); return TRUE; }
    return CancelIo(h);
}

BOOL KEXAPI kex_CancelIoEx(HANDLE h, LPOVERLAPPED ov)
{
    if (is_event_handle(h)) {
        if (cancel_ops(h, ov)) return TRUE;
        SetLastError(ERROR_NOT_FOUND); return FALSE;
    }
    return CancelIo(h);                          /* 9x: no per-request cancel; cancel all on h */
}

/* name of one of our pipe ends ("crashpad_123", lower case, without \\.\pipe\) - for
 * GetFileInformationByHandleEx(FileNameInfo), which Crashpad's handler uses on its pipe (2026-11-02:
 * "exception_handler_server.cc:280 GetFileInformationByHandleEx: The network request is not supported") */
/* build 82 diagnostics (sec_ext.c CloseHandle, shm_ext.c DuplicateHandle): is h a pipe end of this process?
 * out: name; *server: 1 server end, 0 client end */
BOOL kex_pipe_end_info(HANDLE h, char *out, int cb, int *server)
{
    int side, slot; BOOL ok = FALSE;
    if (!g_ar || !is_event_handle(h)) return FALSE;
    lock(); slot = find_end(h, &side);
    if (slot >= 0) { lstrcpynA(out, g_ar->inst[slot].name, cb); *server = side == 0; ok = TRUE; }
    unlock();
    return ok;
}
BOOL kex_pipe_name(HANDLE h, char *out, int cb)
{
    int side, slot; BOOL ok = FALSE;
    if (!is_event_handle(h) || !arena()) return FALSE;
    lock(); slot = find_end(h, &side);
    if (slot >= 0) { lstrcpynA(out, g_ar->inst[slot].name, cb); ok = TRUE; }
    unlock();
    return ok;
}

DWORD KEXAPI kex_GetFileType(HANDLE h)
{
    { BOOL kex_dir_is(HANDLE h); if (kex_dir_is(h)) return FILE_TYPE_DISK; }
    if (is_event_handle(h) && arena()) {
        int side, slot; lock(); slot = find_end(h, &side); unlock();
        if (slot >= 0) return FILE_TYPE_PIPE;
    }
    return GetFileType(h);
}

BOOL KEXAPI kex_FlushFileBuffers(HANDLE h)
{
    if (is_event_handle(h) && arena()) {             /* pipes: wait until the peer has read everything */
        int side, slot; lock(); slot = find_end(h, &side); unlock();
        if (slot >= 0) {
            for (;;) {
                NPI *p; BOOL busy;
                lock(); p = &g_ar->inst[slot];
                busy = p->state == ST_CONNECTED && p->ring[!side].used && alive(p, slot, !side);
                unlock();
                if (!busy) return TRUE;
                nap();
            }
        }
    }
    return FlushFileBuffers(h);
}

/* build 121: CloseHandle of a pipe end (sec_ext.c). Before the close: which end it is. After a successful close: if
 * that end's name is gone (the last handle to its event closed), the slot forgets the event's address - Windows 98
 * hands that memory to the next object made, and a slot still holding it would claim that object as this pipe. */
BOOL kex_pipe_close_begin(HANDLE h, int *slot, int *side, DWORD *gen)
{
    int sd, sl;
    if (!g_ar || !is_event_handle(h)) return FALSE;
    lock(); sl = find_end(h, &sd);
    if (sl >= 0) { *slot = sl; *side = sd; *gen = end_gen(&g_ar->inst[sl], sd); }
    unlock();
    return sl >= 0;
}
void kex_pipe_close_end(int slot, int side, DWORD gen)
{
    NPI *p; BOOL gone = FALSE;
    if (!g_ar || slot < 0 || slot >= NP_MAX) return;
    lock(); p = &g_ar->inst[slot];
    if (p->state != ST_FREE && end_gen(p, side) == gen && !end_alive(slot, gen, side)) {
        if (side == 0) p->srv_obj = 0; else p->cli_obj = 0;
        gone = TRUE;
    }
    unlock();
    if (gone) changed();
}
