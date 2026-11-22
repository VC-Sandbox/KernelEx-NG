/* tpwork_ext.c - Vista thread-pool WORK and WAIT objects, callback instances, CopyFile2 / CreateFile2 (build 131).
 *
 * Measured: the Visual C++ v14 14.52 runtime (installed by the "2017-present" setup this build makes work) imports
 * statically from KERNEL32: CreateThreadpoolWork, SubmitThreadpoolWork, CloseThreadpoolWork, CreateThreadpoolWait,
 * SetThreadpoolWait, CloseThreadpoolWait, FreeLibraryWhenCallbackReturns, CopyFile2, CreateFile2, CreateSymbolicLinkW
 * (GPA.EXE: missing in every KernelEx configuration). Every program using MSVCP140/CONCRT140 then failed to start -
 * the installed Pale Moon 35: "MSVCP140.DLL is linked to missing export KERNEL32.DLL:SubmitThreadpoolWork".
 * kexnt had only the timer objects (w10_ext.c).
 *
 * Work: each SubmitThreadpoolWork queues one callback; worker threads (started on demand, at most 4) run them.
 * Wait: one waiter thread watches every armed wait object's handle (WaitForMultipleObjects, 63 at a time) with its
 * timeout; when the handle is signalled or the timeout passes the callback is queued once (WAIT_OBJECT_0 /
 * WAIT_TIMEOUT), as on NT (a wait object fires once per SetThreadpoolWait).
 * Instances: FreeLibraryWhenCallbackReturns / SetEventWhenCallbackReturns / ReleaseMutexWhenCallbackReturns /
 * ReleaseSemaphoreWhenCallbackReturns / LeaveCriticalSectionWhenCallbackReturns are carried out after the callback;
 * CallbackMayRunLong answers TRUE (a new worker is started if all are busy). Environments (TP_CALLBACK_ENVIRON) are
 * accepted and not used: one process-wide pool, as the default pool on NT. Written from the documentation. */
#include "kexnt_common.h"

typedef VOID (CALLBACK *T_WORKCB)(PVOID inst, PVOID ctx, PVOID work);
typedef VOID (CALLBACK *T_WAITCB)(PVOID inst, PVOID ctx, PVOID wait, DWORD result);
typedef VOID (CALLBACK *T_SIMPLECB)(PVOID inst, PVOID ctx);

typedef struct KINST { HMODULE freelib; HANDLE setev, relmutex, relsem; LONG semcount; LPCRITICAL_SECTION leavecs; } KINST;
enum { K_WORK = 1, K_WAIT = 2, K_SIMPLE = 3 };
typedef struct KOBJ { int kind; PVOID fn, ctx; LONG queued, running, closed; HANDLE h; ULONGLONG due; LONG armed; } KOBJ;
typedef struct KITEM { struct KITEM *next; KOBJ *o; DWORD result; } KITEM;

static CRITICAL_SECTION g_cs; static volatile LONG g_state;
static HANDLE g_qsem, g_wwake; static KITEM *g_head, *g_tail;
static LONG g_workers, g_idle; static DWORD g_waiter_tid;
#define MAX_WORKERS 4
#define MAX_WAITS 256
static KOBJ *g_waits[MAX_WAITS];

static ULONGLONG ms64(void)
{
    static DWORD last, high; DWORD t = GetTickCount();
    if (t < last) high++;
    last = t;
    return ((ULONGLONG)high << 32) | t;
}
static void kfree(void *p) { HeapFree(GetProcessHeap(), 0, p); }
static void obj_release_if_done(KOBJ *o)              /* g_cs held */
{
    if (o->closed && !o->queued && !o->running) {
        int i; for (i = 0; i < MAX_WAITS; i++) if (g_waits[i] == o) g_waits[i] = NULL;
        kfree(o);
    }
}
static void run_instance(KINST *in)
{
    if (in->setev) SetEvent(in->setev);
    if (in->relsem) ReleaseSemaphore(in->relsem, in->semcount, NULL);
    if (in->relmutex) ReleaseMutex(in->relmutex);
    if (in->leavecs) LeaveCriticalSection(in->leavecs);
    if (in->freelib) FreeLibrary(in->freelib);
}
static DWORD WINAPI worker(LPVOID p)
{
    (void)p;
    for (;;) {
        KITEM *it; KOBJ *o; KINST in;
        InterlockedIncrement(&g_idle);
        WaitForSingleObject(g_qsem, INFINITE);
        InterlockedDecrement(&g_idle);
        EnterCriticalSection(&g_cs);
        it = g_head;
        if (it) { g_head = it->next; if (!g_head) g_tail = NULL; it->o->queued--; it->o->running++; }
        LeaveCriticalSection(&g_cs);
        if (!it) continue;                             /* cancelled after it was counted */
        o = it->o; memset(&in, 0, sizeof(in));
        if (o->kind == K_WORK) ((T_WORKCB)o->fn)(&in, o->ctx, o);
        else if (o->kind == K_WAIT) ((T_WAITCB)o->fn)(&in, o->ctx, o, it->result);
        else ((T_SIMPLECB)o->fn)(&in, o->ctx);
        run_instance(&in);
        kfree(it);
        EnterCriticalSection(&g_cs);
        o->running--;
        if (o->kind == K_SIMPLE) o->closed = 1;
        obj_release_if_done(o);
        LeaveCriticalSection(&g_cs);
    }
}
static void add_worker_if_needed(void)                 /* g_cs held */
{
    if (g_idle == 0 && g_workers < MAX_WORKERS) {
        HANDLE h = CreateThread(NULL, 0x100000, worker, NULL, 0, NULL);   /* full-size stack, as NT's pool threads */
        if (h) { CloseHandle(h); g_workers++; }
    }
}
static BOOL pool_init(void)
{
    while (g_state != 2) {
        if (InterlockedCompareExchange(&g_state, 1, 0) == 0) {
            InitializeCriticalSection(&g_cs);
            g_qsem = CreateSemaphoreA(NULL, 0, 0x7FFFFFFF, NULL);
            g_wwake = CreateEventA(NULL, FALSE, FALSE, NULL);
            g_state = 2;
        } else Sleep(0);
    }
    return g_qsem && g_wwake;
}
static void enqueue(KOBJ *o, DWORD result)             /* g_cs held */
{
    KITEM *it = (KITEM *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*it));
    if (!it) return;
    it->o = o; it->result = result;
    if (g_tail) g_tail->next = it; else g_head = it;
    g_tail = it; o->queued++;
    add_worker_if_needed();
    ReleaseSemaphore(g_qsem, 1, NULL);
}
static void cancel_queued(KOBJ *o)                     /* g_cs held: drop o's callbacks that have not started */
{
    KITEM **pp = &g_head, *prev = NULL;
    while (*pp) {
        KITEM *it = *pp;
        if (it->o == o) { *pp = it->next; if (g_tail == it) g_tail = prev; o->queued--; kfree(it); }
        else { prev = it; pp = &it->next; }
    }
}
static BOOL in_pool_callback_of(KOBJ *o) { (void)o; return FALSE; }
static void wait_callbacks(KOBJ *o, BOOL cancel)
{
    if (!o) return;
    EnterCriticalSection(&g_cs);
    if (cancel) { cancel_queued(o); if (o->kind == K_WAIT) o->armed = 0; }
    LeaveCriticalSection(&g_cs);
    if (in_pool_callback_of(o)) return;
    for (;;) {
        LONG busy;
        EnterCriticalSection(&g_cs); busy = o->queued + o->running; LeaveCriticalSection(&g_cs);
        if (!busy) break;
        Sleep(1);
    }
}
static VOID close_obj(KOBJ *o)
{
    if (!o) return;
    EnterCriticalSection(&g_cs);
    o->closed = 1; if (o->kind == K_WAIT) o->armed = 0;
    obj_release_if_done(o);
    LeaveCriticalSection(&g_cs);
    SetEvent(g_wwake);
}
static KOBJ *new_obj(int kind, PVOID fn, PVOID ctx)
{
    KOBJ *o;
    if (!fn) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    if (!pool_init() || !(o = (KOBJ *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*o)))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    o->kind = kind; o->fn = fn; o->ctx = ctx;
    return o;
}

/* ---- work ---- */
PVOID KEXAPI kex_CreateThreadpoolWork(T_WORKCB fn, PVOID ctx, PVOID env) { (void)env; return new_obj(K_WORK, (PVOID)fn, ctx); }
VOID KEXAPI kex_SubmitThreadpoolWork(PVOID w)
{
    KOBJ *o = (KOBJ *)w;
    if (!o) return;
    EnterCriticalSection(&g_cs); enqueue(o, 0); LeaveCriticalSection(&g_cs);
}
VOID KEXAPI kex_WaitForThreadpoolWorkCallbacks(PVOID w, BOOL cancel) { wait_callbacks((KOBJ *)w, cancel); }
VOID KEXAPI kex_CloseThreadpoolWork(PVOID w) { close_obj((KOBJ *)w); }
BOOL KEXAPI kex_TrySubmitThreadpoolCallback(T_SIMPLECB fn, PVOID ctx, PVOID env)
{
    KOBJ *o = new_obj(K_SIMPLE, (PVOID)fn, ctx);
    (void)env;
    if (!o) return FALSE;
    EnterCriticalSection(&g_cs); enqueue(o, 0); LeaveCriticalSection(&g_cs);
    return TRUE;
}

/* ---- wait ---- */
static DWORD WINAPI waiter(LPVOID p)
{
    (void)p;
    for (;;) {
        HANDLE hs[64]; KOBJ *os[64]; int n = 0, i; DWORD tmo = INFINITE, r; ULONGLONG now;
        hs[n++] = g_wwake;
        EnterCriticalSection(&g_cs);
        now = ms64();
        for (i = 0; i < MAX_WAITS && n < 64; i++) {
            KOBJ *o = g_waits[i];
            if (!o || !o->armed || o->closed) continue;
            if (o->due && o->due <= now) { o->armed = 0; enqueue(o, WAIT_TIMEOUT); continue; }
            if (o->due && o->due - now < tmo) tmo = (DWORD)(o->due - now);
            if (o->h) { hs[n] = o->h; os[n] = o; n++; }
        }
        LeaveCriticalSection(&g_cs);
        r = WaitForMultipleObjects(n, hs, FALSE, tmo);
        if (r > WAIT_OBJECT_0 && r < WAIT_OBJECT_0 + (DWORD)n) {
            KOBJ *o = os[r - WAIT_OBJECT_0];
            EnterCriticalSection(&g_cs);
            if (o->armed && !o->closed) { o->armed = 0; enqueue(o, WAIT_OBJECT_0); }
            LeaveCriticalSection(&g_cs);
        } else if (r == WAIT_FAILED) Sleep(10);         /* a handle was closed under us: rebuild the list */
    }
}
PVOID KEXAPI kex_CreateThreadpoolWait(T_WAITCB fn, PVOID ctx, PVOID env)
{
    KOBJ *o = new_obj(K_WAIT, (PVOID)fn, ctx); int i;
    (void)env;
    if (!o) return NULL;
    EnterCriticalSection(&g_cs);
    for (i = 0; i < MAX_WAITS && g_waits[i]; i++) ;
    if (i == MAX_WAITS) { LeaveCriticalSection(&g_cs); kfree(o); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    g_waits[i] = o;
    if (!g_waiter_tid) { HANDLE h = CreateThread(NULL, 0x10000, waiter, NULL, 0, &g_waiter_tid); if (h) CloseHandle(h); }
    LeaveCriticalSection(&g_cs);
    return o;
}
VOID KEXAPI kex_SetThreadpoolWait(PVOID w, HANDLE h, const FILETIME *timeout)
{
    KOBJ *o = (KOBJ *)w; ULONGLONG due = 0;
    if (!o) return;
    if (h && timeout) {
        LONGLONG v = (LONGLONG)(((ULONGLONG)timeout->dwHighDateTime << 32) | timeout->dwLowDateTime);
        if (v < 0) due = ms64() + (ULONGLONG)(-v) / 10000;
        else {
            FILETIME n; LONGLONG nv; GetSystemTimeAsFileTime(&n);
            nv = (LONGLONG)(((ULONGLONG)n.dwHighDateTime << 32) | n.dwLowDateTime);
            due = ms64() + (v > nv ? (ULONGLONG)(v - nv) / 10000 : 0);
            if (!due) due = 1;
        }
    }
    EnterCriticalSection(&g_cs);
    o->h = h; o->due = due; o->armed = h != NULL;
    LeaveCriticalSection(&g_cs);
    SetEvent(g_wwake);
}
VOID KEXAPI kex_WaitForThreadpoolWaitCallbacks(PVOID w, BOOL cancel) { wait_callbacks((KOBJ *)w, cancel); }
VOID KEXAPI kex_CloseThreadpoolWait(PVOID w) { close_obj((KOBJ *)w); }

/* ---- callback instance requests ---- */
VOID KEXAPI kex_FreeLibraryWhenCallbackReturns(PVOID inst, HMODULE m) { if (inst) ((KINST *)inst)->freelib = m; }
VOID KEXAPI kex_SetEventWhenCallbackReturns(PVOID inst, HANDLE e) { if (inst) ((KINST *)inst)->setev = e; }
VOID KEXAPI kex_ReleaseMutexWhenCallbackReturns(PVOID inst, HANDLE m) { if (inst) ((KINST *)inst)->relmutex = m; }
VOID KEXAPI kex_ReleaseSemaphoreWhenCallbackReturns(PVOID inst, HANDLE s, DWORD n) { if (inst) { ((KINST *)inst)->relsem = s; ((KINST *)inst)->semcount = (LONG)n; } }
VOID KEXAPI kex_LeaveCriticalSectionWhenCallbackReturns(PVOID inst, LPCRITICAL_SECTION cs) { if (inst) ((KINST *)inst)->leavecs = cs; }
BOOL KEXAPI kex_CallbackMayRunLong(PVOID inst)
{
    (void)inst;
    if (g_state == 2) { EnterCriticalSection(&g_cs); add_worker_if_needed(); LeaveCriticalSection(&g_cs); }
    return TRUE;
}
VOID KEXAPI kex_DisassociateCurrentThreadFromCallback(PVOID inst) { (void)inst; }

/* ---- files (Windows 8) ---- */
typedef struct { DWORD dwSize, dwFileAttributes, dwFileFlags, dwSecurityQosFlags; LPSECURITY_ATTRIBUTES lpSecurityAttributes; HANDLE hTemplateFile; } KCF2;
HANDLE KEXAPI kex_CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl);
HANDLE KEXAPI kex_CreateFile2(LPCWSTR name, DWORD access, DWORD share, DWORD disp, const KCF2 *ex)
{
    DWORD flags = ex ? (ex->dwFileAttributes | ex->dwFileFlags | ex->dwSecurityQosFlags) : 0;
    return kex_CreateFileW(name, access, share, ex ? ex->lpSecurityAttributes : NULL, disp, flags, ex ? ex->hTemplateFile : NULL);
}
typedef struct { DWORD dwSize, dwCopyFlags; BOOL *pfCancel; PVOID pProgressRoutine, pvCallbackContext; } KCF2P;
HRESULT KEXAPI kex_CopyFile2(LPCWSTR src, LPCWSTR dst, const KCF2P *p)
{
    char a[MAX_PATH * 2], b[MAX_PATH * 2];             /* Windows 98's CopyFileW is a stub: through the A function */
    BOOL fail_if = p && (p->dwCopyFlags & 0x00000001);   /* COPY_FILE_FAIL_IF_EXISTS */
    if (!src || !dst) return E_INVALIDARG;
    if (!WideCharToMultiByte(CP_ACP, 0, src, -1, a, sizeof(a), NULL, NULL) ||
        !WideCharToMultiByte(CP_ACP, 0, dst, -1, b, sizeof(b), NULL, NULL)) return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
    return CopyFileA(a, b, fail_if) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}
/* Windows 98 file systems have no symbolic links: what NT says on FAT */
BOOLEAN KEXAPI kex_CreateSymbolicLinkW(LPCWSTR link, LPCWSTR target, DWORD flags)
{ (void)link; (void)target; (void)flags; SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOLEAN KEXAPI kex_CreateSymbolicLinkA(LPCSTR link, LPCSTR target, DWORD flags)
{ (void)link; (void)target; (void)flags; SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }

/* ---- build 131: more that Pale Moon 35's xul.dll imports statically (gaps.py over its import table) ---- */
VOID KEXAPI kex_GetNativeSystemInfo(LPSYSTEM_INFO si) { GetSystemInfo(si); }     /* 32-bit Windows: the same */
/* GetVolumePathNameW: the mount point a path is on - on Windows 98 always its drive root ("C:\") or "\\server\share\" */
BOOL KEXAPI kex_GetVolumePathNameW(LPCWSTR path, LPWSTR out, DWORD n)
{
    DWORD k = 0, slashes = 0;
    if (!path || !out || n < 4) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (path[0] && path[1] == L':') { if (n < 4) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
        out[0] = path[0]; out[1] = L':'; out[2] = L'\\'; out[3] = 0; return TRUE; }
    if (path[0] == L'\\' && path[1] == L'\\') {            /* UNC: \\server\share\ */
        for (k = 0; path[k] && k + 2 < n; k++) { out[k] = path[k]; if (path[k] == L'\\' && ++slashes == 4) { k++; break; } }
        if (slashes < 4 && k + 1 < n) out[k++] = L'\\';
        out[k] = 0; return TRUE;
    }
    {   char cur[MAX_PATH]; if (!GetCurrentDirectoryA(MAX_PATH, cur) || cur[1] != ':') { SetLastError(ERROR_INVALID_NAME); return FALSE; }
        out[0] = (WCHAR)(BYTE)cur[0]; out[1] = L':'; out[2] = L'\\'; out[3] = 0; return TRUE; }
}
BOOL KEXAPI kex_GetVolumePathNameA(LPCSTR path, LPSTR out, DWORD n)
{
    WCHAR w[MAX_PATH], o[MAX_PATH];
    if (!path || !out) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!MultiByteToWideChar(CP_ACP, 0, path, -1, w, MAX_PATH)) return FALSE;
    if (!kex_GetVolumePathNameW(w, o, MAX_PATH)) return FALSE;
    return WideCharToMultiByte(CP_ACP, 0, o, -1, out, (int)n, NULL, NULL) != 0;
}
/* QueryWorkingSet: Windows 98 has no working-set lists; NT fills NumberOfEntries first - report none */
BOOL KEXAPI kex_K32QueryWorkingSet(HANDLE hp, PVOID pv, DWORD cb)
{
    (void)hp;
    if (!pv || cb < sizeof(ULONG_PTR)) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
    *(ULONG_PTR *)pv = 0;
    return TRUE;
}
/* GetLastInputInfo (USER32, Windows 2000): Windows 98 keeps no last-input time for programs; answered as "input just
 * now", so idle detectors (Pale Moon's idle service) see an active user rather than failing. */
typedef struct { UINT cbSize; DWORD dwTime; } KLASTINPUT;
BOOL KEXAPI kex_GetLastInputInfo(KLASTINPUT *p)
{
    if (!p || p->cbSize < sizeof(*p)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    p->dwTime = GetTickCount();
    return TRUE;
}
