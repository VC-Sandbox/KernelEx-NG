/*
 * job_ext.c - KernelEx-NG build 96: job objects with NT's "kill on job close".
 *
 * Windows 98 has no job objects; KernelEx 4.5 answers CreateJobObject with a dummy handle and every other job
 * call with "done". Chromium puts every helper process (tabs, GPU, utilities) into a job with
 * JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: on NT, when the browser ends - normally, by a crash, or killed - the job's
 * last handle closes and Windows ends every process in it. On Windows 98 the helpers lived on after the browser
 * was gone, kept chrome.dll and the profile files open ("in use", "write protected" until a restart).
 *
 * Here a job is a real kernel object (an unnamed event), so CloseHandle / DuplicateHandle / inheritance work.
 * kexnt keeps the job's members (process handles of its own) and its limit flags, and ends the members:
 *   - when the last handle of the job is closed (K32 reference count of the event),
 *   - when the owning process ends (ExitProcess, TerminateProcess of itself, kexnt process detach),
 *   - TerminateJobObject.
 * If the owner dies in a way kexnt never sees (Windows 98's "illegal operation" box, Ctrl+Alt+Del End Task),
 * every member watches its owner itself: AssignProcessToJobObject records (member pid, owner, kill flag) in a
 * small shared table and gives the member a handle to the owner process; the member's kexnt starts a thread
 * that waits on it and ends its own process when the owner is gone and the job said "kill on close".
 * Only programs kexnt serves (modern programs) are affected; Windows 9x programs never reach this code.
 */
#include "kexnt_common.h"

BYTE *kex_k32_object(HANDLE h, int type);          /* chrome_ext.c */
DWORD kex_pid_of(HANDLE ph);                      /* proctime_ext.c */
FARPROC kex_prev_impl(const char *dll, const char *name);
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

#define K32_EVENT 2
#define JOB_KILL_ON_CLOSE 0x00002000UL
#define NJOB 32
#define NMEM 160

typedef struct {
    HANDLE ev;                    /* the handle CreateJobObject returned (kept for lookups) */
    BYTE  *obj;                   /* K32 event object: identifies the job behind any handle */
    BYTE   limit[112];            /* JOBOBJECT_EXTENDED_LIMIT_INFORMATION as last set */
    int    n;
    HANDLE mh[NMEM];              /* members: our own process handles */
    DWORD  mpid[NMEM];
    LONG   total;                 /* processes ever assigned */
} JOB;
static JOB g_job[NJOB];
static CRITICAL_SECTION g_jcs; static volatile LONG g_jcs_state;
static void jlock(void)
{
    if (g_jcs_state != 2) {
        if (InterlockedCompareExchange(&g_jcs_state, 1, 0) == 0) { InitializeCriticalSection(&g_jcs); InterlockedExchange(&g_jcs_state, 2); }
        else while (g_jcs_state != 2) Sleep(0);
    }
    EnterCriticalSection(&g_jcs);
}
static void junlock(void) { LeaveCriticalSection(&g_jcs); }
static DWORD limit_flags(const JOB *j) { return *(const DWORD *)(j->limit + 16); }

static JOB *job_of(HANDLE h)      /* lock held */
{
    BYTE *o; int i;
    if (!h || h == INVALID_HANDLE_VALUE) return NULL;
    for (i = 0; i < NJOB; i++) if (g_job[i].ev == h) return &g_job[i];
    o = kex_k32_object(h, K32_EVENT);
    if (!o) return NULL;
    for (i = 0; i < NJOB; i++) if (g_job[i].obj == o) return &g_job[i];
    return NULL;
}

/* ---------------------------------------------------------------- shared table: who watches whom */
typedef struct { DWORD child, owner, owner_h, kill, job; } JW;
#define NJW 512
typedef struct { DWORD magic; JW e[NJW]; } JWT;
static JWT *g_jw; static HANDLE g_jw_mtx;
static BOOL jw_open(BOOL create)
{
    HANDLE m;
    if (g_jw) return TRUE;
    if (!g_jw_mtx) g_jw_mtx = CreateMutexA(NULL, FALSE, "KXJOB_LOCK");
    m = create ? CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(JWT), "KXJOB_TABLE")
               : OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, "KXJOB_TABLE");
    if (!m || !g_jw_mtx) return FALSE;
    g_jw = (JWT *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0);   /* mapping handle kept for the process' life */
    return g_jw != NULL;
}
static BOOL pid_alive(DWORD pid)
{
    HANDLE p = OpenProcess(SYNCHRONIZE, FALSE, pid); BOOL a;
    if (!p) return FALSE;
    a = WaitForSingleObject(p, 0) != WAIT_OBJECT_0;
    CloseHandle(p);
    return a;
}
/* the owner tells member `child` (still suspended or just started) to watch it */
static void jw_register(HANDLE child_ph, DWORD child, DWORD jobid, DWORD kill)
{
    HANDLE self, hc = NULL; int i, slot = -1;
    if (!child || !jw_open(TRUE)) return;
    self = OpenProcess(SYNCHRONIZE | PROCESS_DUP_HANDLE, FALSE, GetCurrentProcessId());
    if (self) { DuplicateHandle(GetCurrentProcess(), self, child_ph, &hc, SYNCHRONIZE, FALSE, 0); CloseHandle(self); }
    if (!hc) return;
    WaitForSingleObject(g_jw_mtx, 5000);
    for (i = 0; i < NJW; i++) if (g_jw->e[i].child == child) { slot = i; break; }
    if (slot < 0) for (i = 0; i < NJW; i++) if (!g_jw->e[i].child) { slot = i; break; }
    if (slot < 0) for (i = 0; i < NJW; i++) if (!pid_alive(g_jw->e[i].child)) { slot = i; break; }
    if (slot >= 0) {
        g_jw->e[slot].child = child; g_jw->e[slot].owner = GetCurrentProcessId();
        g_jw->e[slot].owner_h = (DWORD)(ULONG_PTR)hc; g_jw->e[slot].kill = kill; g_jw->e[slot].job = jobid;
    }
    ReleaseMutex(g_jw_mtx);
}
static void jw_set_kill(DWORD jobid, DWORD kill)
{
    int i;
    if (!g_jw) return;
    WaitForSingleObject(g_jw_mtx, 5000);
    for (i = 0; i < NJW; i++)
        if (g_jw->e[i].owner == GetCurrentProcessId() && g_jw->e[i].job == jobid) g_jw->e[i].kill = kill;
    ReleaseMutex(g_jw_mtx);
}
/* member side */
static DWORD WINAPI watch_owner(LPVOID hv)
{
    HANDLE h = (HANDLE)hv; DWORD me = GetCurrentProcessId(), owner = 0, kill = 0; int i;
    WaitForSingleObject(h, INFINITE);
    WaitForSingleObject(g_jw_mtx, 5000);
    for (i = 0; i < NJW; i++) if (g_jw->e[i].child == me) { owner = g_jw->e[i].owner; kill = g_jw->e[i].kill; g_jw->e[i].child = 0; break; }
    ReleaseMutex(g_jw_mtx);
    if (kill) {
        kex_crashnote("job: the process that owned this process's job has ended - ending too, as NT does (kill on job close) (owner)",
                      owner, 0, 0, 0);
        TerminateProcess(GetCurrentProcess(), 0);
    }
    return 0;
}
void kex_job_child_init(void)
{
    DWORD me = GetCurrentProcessId(), tid; int i; HANDLE hc = NULL;
    if (!jw_open(FALSE)) return;
    WaitForSingleObject(g_jw_mtx, 5000);
    for (i = 0; i < NJW; i++) if (g_jw->e[i].child == me) { hc = (HANDLE)(ULONG_PTR)g_jw->e[i].owner_h; break; }
    ReleaseMutex(g_jw_mtx);
    if (hc) { HANDLE t = CreateThread(NULL, 0x4000, watch_owner, hc, 0, &tid); if (t) CloseHandle(t); }
}

/* ---------------------------------------------------------------- ending members */
static int kill_members(JOB *j, UINT code)    /* lock held */
{
    int k, n = 0;
    for (k = 0; k < j->n; k++) {
        if (j->mh[k]) {
            if (WaitForSingleObject(j->mh[k], 0) != WAIT_OBJECT_0) { TerminateProcess(j->mh[k], code); n++; }
            CloseHandle(j->mh[k]); j->mh[k] = NULL;
        }
    }
    j->n = 0;
    return n;
}
static void job_free(JOB *j) { jw_set_kill((DWORD)(ULONG_PTR)j->obj, 0); ZeroMemory(j, sizeof(*j)); }

/* CloseHandle (sec_ext.c), before the handle is closed */
void kex_job_close(HANDLE h)
{
    JOB *j; BYTE *o;
    if (g_jcs_state != 2) return;
    jlock();
    if ((j = job_of(h)) != NULL) {
        o = j->obj;
        if (*(volatile WORD *)(o + 2) <= 1) {           /* the last handle of the job */
            if (limit_flags(j) & JOB_KILL_ON_CLOSE) {
                int n = kill_members(j, 0);
                kex_crashnote("job: last handle closed, kill-on-close: processes ended (job, ended)", (DWORD)(ULONG_PTR)h, (DWORD)n, 0, 0);
            }
            job_free(j);
        } else if (j->ev == h) j->ev = NULL;
    }
    junlock();
}
/* the owning process ends (crashlog_ext.c ExitProcess / TerminateProcess(self), kexnt process detach) */
void kex_job_process_exit(void)
{
    int i, n = 0;
    if (g_jcs_state != 2) return;
    jlock();
    for (i = 0; i < NJOB; i++)
        if (g_job[i].obj && (limit_flags(&g_job[i]) & JOB_KILL_ON_CLOSE)) n += kill_members(&g_job[i], 0);
    junlock();
    if (n) kex_crashnote("job: this process ends, kill-on-close jobs: processes ended", (DWORD)n, 0, 0, 0);
}

/* ---------------------------------------------------------------- the API */
static HANDLE job_create(LPSECURITY_ATTRIBUTES sa)
{
    SECURITY_ATTRIBUTES s; HANDLE h; int i; JOB *j = NULL;
    if (sa) { s.nLength = sizeof(s); s.lpSecurityDescriptor = NULL; s.bInheritHandle = sa->bInheritHandle; }
    h = CreateEventA(sa ? &s : NULL, TRUE, FALSE, NULL);
    if (!h) return NULL;
    jlock();
    for (i = 0; i < NJOB; i++) if (!g_job[i].obj) { j = &g_job[i]; break; }
    if (j) { ZeroMemory(j, sizeof(*j)); j->ev = h; j->obj = kex_k32_object(h, K32_EVENT); }
    junlock();
    if (!j || !j->obj) { if (j) ZeroMemory(j, sizeof(*j)); CloseHandle(h); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    { static LONG c; if (InterlockedIncrement(&c) <= 8) kex_crashnote("job: CreateJobObject (handle, caller)", (DWORD)(ULONG_PTR)h, (DWORD)(ULONG_PTR)__builtin_return_address(0), 0, 0); }
    SetLastError(0);
    return h;
}
HANDLE KEXAPI kex_CreateJobObjectW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name) { (void)name; return job_create(sa); }
HANDLE KEXAPI kex_CreateJobObjectA(LPSECURITY_ATTRIBUTES sa, LPCSTR name)  { (void)name; return job_create(sa); }

BOOL KEXAPI kex_AssignProcessToJobObject(HANDLE job, HANDLE proc)
{
    JOB *j; HANDLE d = NULL; DWORD pid, kill; int k;
    jlock();
    if (!(j = job_of(job))) { junlock(); SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    pid = kex_pid_of(proc);
    if (!DuplicateHandle(GetCurrentProcess(), proc, GetCurrentProcess(), &d, PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, 0)) {
        DWORD le = GetLastError(); junlock(); SetLastError(le); return FALSE;
    }
    for (k = 0; k < j->n; k++)                          /* reuse the slot of a member that has ended */
        if (j->mh[k] && WaitForSingleObject(j->mh[k], 0) == WAIT_OBJECT_0) { CloseHandle(j->mh[k]); j->mh[k] = NULL; }
    for (k = 0; k < j->n && j->mh[k]; k++) ;
    if (k == NMEM) { junlock(); CloseHandle(d); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    j->mh[k] = d; j->mpid[k] = pid; if (k == j->n) j->n++;
    j->total++;
    kill = (limit_flags(j) & JOB_KILL_ON_CLOSE) ? 1 : 0;
    junlock();
    jw_register(proc, pid, (DWORD)(ULONG_PTR)j->obj, kill);
    { static LONG c; if (InterlockedIncrement(&c) <= 20) kex_crashnote("job: process assigned (job, process id, kill on close, members)", (DWORD)(ULONG_PTR)job, pid, kill, (DWORD)j->n); }
    SetLastError(0);
    return TRUE;
}

BOOL KEXAPI kex_SetInformationJobObject(HANDLE job, int cls, LPVOID info, DWORD len)
{
    JOB *j; DWORD id = 0, kill = 0; BOOL known;
    jlock();
    j = job_of(job); known = j != NULL;
    if (j && info && (cls == 2 || cls == 9)) {           /* basic / extended limit information */
        DWORD n = len < sizeof(j->limit) ? len : sizeof(j->limit);
        if (cls == 2 && n > 48) n = 48;
        memcpy(j->limit, info, n);
        id = (DWORD)(ULONG_PTR)j->obj; kill = (limit_flags(j) & JOB_KILL_ON_CLOSE) ? 1 : 0;
    }
    junlock();
    if (!known) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (id) jw_set_kill(id, kill);
    return TRUE;                                         /* other classes (UI limits, CPU rates): accepted, no effect */
}

BOOL KEXAPI kex_QueryInformationJobObject(HANDLE job, int cls, LPVOID info, DWORD len, LPDWORD ret)
{
    JOB *j; int k, live = 0; DWORD need = 0;
    jlock();
    j = job ? job_of(job) : NULL;
    if (!j) { junlock(); SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    for (k = 0; k < j->n; k++) if (j->mh[k] && WaitForSingleObject(j->mh[k], 0) != WAIT_OBJECT_0) live++;
    switch (cls) {
    case 2: case 9:
        need = cls == 2 ? 48 : 112;
        if (len < need || !info) break;
        memcpy(info, j->limit, need);
        break;
    case 1:                                              /* basic accounting: times 0, process counts */
        need = 48;
        if (len < need || !info) break;
        ZeroMemory(info, need);
        ((DWORD *)info)[8] = (DWORD)j->total; ((DWORD *)info)[9] = (DWORD)live;
        break;
    case 3: {                                            /* basic process id list */
        DWORD fit = len >= 8 ? (len - 8) / 4 : 0, o = 0;
        need = 8;
        if (len < 8 || !info) break;
        for (k = 0; k < j->n; k++) if (j->mh[k] && WaitForSingleObject(j->mh[k], 0) != WAIT_OBJECT_0) {
            if (o < fit) { DWORD kex_pid_nt(DWORD real); ((DWORD *)info)[2 + o] = kex_pid_nt(j->mpid[k]); }   /* build 131 */
            o++;
        }
        ((DWORD *)info)[0] = (DWORD)live; ((DWORD *)info)[1] = o < fit ? o : fit;
        need = 8 + 4 * (o < fit ? o : fit);
        break;
    }
    default:
        junlock(); SetLastError(ERROR_NOT_SUPPORTED); return FALSE;
    }
    junlock();
    if (len < need) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
    if (ret) *ret = need;
    return TRUE;
}

BOOL KEXAPI kex_TerminateJobObject(HANDLE job, UINT code)
{
    JOB *j;
    jlock();
    if (!(j = job_of(job))) { junlock(); SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    kill_members(j, code);
    junlock();
    return TRUE;
}

BOOL KEXAPI kex_IsProcessInJob(HANDLE proc, HANDLE job, PBOOL result)
{
    DWORD pid; int i, k; BOOL in = FALSE;
    if (!result) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    pid = kex_pid_of(proc);
    jlock();
    for (i = 0; i < NJOB && !in; i++) {
        if (!g_job[i].obj) continue;
        if (job && job_of(job) != &g_job[i]) continue;
        for (k = 0; k < g_job[i].n; k++) if (g_job[i].mh[k] && g_job[i].mpid[k] == pid) { in = TRUE; break; }
    }
    junlock();
    if (!in && !job && jw_open(FALSE)) {                 /* a process another program put into a job */
        WaitForSingleObject(g_jw_mtx, 5000);
        for (i = 0; i < NJW; i++) if (g_jw->e[i].child == pid && pid) { in = TRUE; break; }
        ReleaseMutex(g_jw_mtx);
    }
    *result = in;
    return TRUE;
}
