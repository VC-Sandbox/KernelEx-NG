/*
 * lockfile_ext.c - KernelEx-NG: LockFileEx / UnlockFileEx with shared locks on Windows 98 SE.
 *
 * Windows 98 only has LockFile: exclusive byte-range locks. KernelEx 4.5's LockFileEx turns every request into
 * an exclusive LockFile of the whole range. SQLite's NT code path (taken because KernelEx reports NT) takes its
 * SHARED lock with LockFileEx(shared) over 510 bytes - two connections to one database then exclude each other:
 * Mypal 29 (2026-11-01): "Could not clone connection", NS_ERROR_STORAGE_BUSY on mozIStorageConnection.clone,
 * Places/IndexedDB/search service all fail and the address bar cannot run.
 *
 * Shared locks use the scheme SQLite itself used on Windows 95/98: a reader locks ONE byte of the range,
 * chosen at random (another byte if that one is taken by another reader). An exclusive lock of the whole range
 * still conflicts with every reader; readers rarely conflict with each other and then simply pick another byte.
 * This works across processes too, because the bytes are real LockFile locks. The byte each shared lock took is
 * remembered (handle, offset, length) so UnlockFileEx releases the right one.
 * Without LOCKFILE_FAIL_IMMEDIATELY the call waits (retries) as NT does. lpOverlapped->hEvent is set on success.
 */
#include "kexnt_common.h"

#define LOCKFILE_FAIL_IMMEDIATELY_ 0x1
#define LOCKFILE_EXCLUSIVE_LOCK_   0x2
#define MAX_SHARED 512

typedef struct { HANDLE h; ULONGLONG off, len, byte; } shlock;
static shlock g_sh[MAX_SHARED];
static int g_nsh;
static CRITICAL_SECTION g_lock_cs;
static LONG g_lock_init;
static LONG g_lock_dbg = 0, g_lock_dbg_n;   /* 1: note every LockFileEx/UnlockFileEx (first 300); registry LockTrace */
static DWORD g_seed = 0x9E3779B9UL;

static void init(void)
{
    if (g_lock_init == 2) return;
    if (!InterlockedExchange(&g_lock_init, 1)) {
        HKEY k; DWORD v = 0, n = sizeof(v);
        InitializeCriticalSection(&g_lock_cs);
        /* build 132: HKLM\Software\KernelEx\KexNG "LockTrace" (DWORD) = 1 notes every lock call (first 300) */
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS) {
            if (RegQueryValueExA(k, "LockTrace", NULL, NULL, (BYTE *)&v, &n) == ERROR_SUCCESS && v == 1) g_lock_dbg = 1;
            RegCloseKey(k);
        }
        g_lock_init = 2; return;
    }
    while (g_lock_init != 2) Sleep(1);
}

static DWORD rnd(void)
{
    g_seed ^= GetTickCount() + GetCurrentThreadId();
    g_seed ^= g_seed << 13; g_seed ^= g_seed >> 17; g_seed ^= g_seed << 5;
    return g_seed;
}

/* Win98's LockFile takes a 32-bit range: offset + length must stay below 4 GB, otherwise it fails
 * (ERROR_INVALID_PARAMETER). base::File::Lock locks (0, 0xFFFFFFFFFFFFFFFF) - "the whole file, whatever its
 * size" (leveldb LOCK files: "LockFile::1", Chromium's "Profile error occurred", build 21). Clamp to what 9x
 * can address; nothing above 4 GB exists on FAT32 anyway. */
static ULONGLONG clamp_len(ULONGLONG off, ULONGLONG len)
{
    if (off >= 0xFFFFFFFFULL) return 0;
    if (len > 0xFFFFFFFFULL - off) len = 0xFFFFFFFFULL - off;
    return len;
}

static BOOL try_lock(HANDLE h, BOOL excl, ULONGLONG off, ULONGLONG len, ULONGLONG *byte)
{
    int i;
    len = clamp_len(off, len);
    if (!len) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (excl || len <= 1) {
        *byte = (ULONGLONG)-1;
        return LockFile(h, (DWORD)off, (DWORD)(off >> 32), (DWORD)len, (DWORD)(len >> 32));
    }
    for (i = 0; i < 16; i++) {
        ULONGLONG b = off + (rnd() % len);
        if (LockFile(h, (DWORD)b, (DWORD)(b >> 32), 1, 0)) { *byte = b; return TRUE; }
        if (GetLastError() != ERROR_LOCK_VIOLATION) return FALSE;
    }
    SetLastError(ERROR_LOCK_VIOLATION);
    return FALSE;
}

static void note_fail(const char *what, HANDLE h, ULONGLONG a, ULONGLONG b)
{
    static LONG k; DWORD le = GetLastError(); void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
    if (InterlockedIncrement(&k) <= 40) kex_crashnote(what, (DWORD)(ULONG_PTR)h, (DWORD)a, (DWORD)b, le);
    SetLastError(le);
}

static void note_dbg(const char *what, HANDLE h, ULONGLONG a, ULONGLONG b, ULONGLONG c)
{
    DWORD le = GetLastError(); void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
    if (InterlockedIncrement(&g_lock_dbg_n) <= 300) kex_crashnote(what, (DWORD)(ULONG_PTR)h, (DWORD)a, (DWORD)b, (DWORD)c);
    SetLastError(le);
}


/* ---- build 132: shared locks of ONE byte (SQLite WAL index "-shm": the DMS byte and the read-mark bytes) ----
 * Measured (Pale Moon 35, lock trace): every Places connection takes a SHARED lock on byte 0x80 of places.sqlite-shm
 * (winLockSharedMemory: exclusive, unlock, then shared). The random-byte scheme above needs a range to pick from, so
 * a 1-byte shared lock became an EXCLUSIVE Windows 98 LockFile: the second connection got SQLITE_BUSY and Pale Moon
 * said its bookmarks/history file was "in use by another application" (Firefox 115: PlacesUtils errors).
 * Such locks are kept in a table shared by all processes (named mapping), keyed by the file's full path (kexnt
 * records it per handle, fpath_ext.c): any number of shared holders; an exclusive lock through kexnt fails while
 * another handle holds a shared entry; a shared lock fails while anyone holds a real (exclusive) lock on that byte.
 * Entries of ended processes are dropped when seen. Files whose path kexnt does not know keep the old behaviour. */
BOOL kex_fpath_get(HANDLE h, char *buf, DWORD cb);   /* fpath_ext.c */
#define NLT 1024
typedef struct { DWORD pid; HANDLE h; DWORD key; ULONGLONG off; } LT;
typedef struct { LT e[NLT]; } LTAB;
static LTAB *g_lt; static HANDLE g_lt_mx;
static BOOL lt_open(void)
{
    if (g_lt) return TRUE;
    if (!g_lt_mx && !(g_lt_mx = CreateMutexA(NULL, FALSE, "KXNT_LOCKTAB_MX"))) return FALSE;
    {   HANDLE m = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(LTAB), "KXNT_LOCKTAB");
        LTAB *t = m ? (LTAB *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(LTAB)) : NULL;
        if (!t) return FALSE;
        g_lt = t; }
    return TRUE;
}
static DWORD path_key(HANDLE h)
{
    char p[MAX_PATH]; DWORD k = 2166136261UL; const char *c;
    if (!kex_fpath_get(h, p, sizeof(p)) || !p[0]) return 0;
    for (c = p; *c; c++) { char ch = *c; if (ch >= 'a' && ch <= 'z') ch -= 32; if (ch == '/') ch = '\\'; k = (k ^ (BYTE)ch) * 16777619UL; }
    return k ? k : 1;
}
static BOOL pid_alive(DWORD pid)
{
    HANDLE p; DWORD code = 0; BOOL alive;
    if (pid == GetCurrentProcessId()) return TRUE;
    if (!(p = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid))) return FALSE;
    alive = GetExitCodeProcess(p, &code) && code == STILL_ACTIVE;
    CloseHandle(p);
    return alive;
}
/* lock held: does another handle hold a shared entry inside [off, off+len)? drops dead entries */
static BOOL lt_conflict(DWORD key, HANDLE h, ULONGLONG off, ULONGLONG len)
{
    int i; DWORD me = GetCurrentProcessId();
    for (i = 0; i < NLT; i++) {
        LT *e = &g_lt->e[i];
        if (!e->pid || e->key != key || e->off < off || e->off >= off + len) continue;
        if (e->pid == me && e->h == h) continue;
        if (!pid_alive(e->pid)) { e->pid = 0; continue; }
        return TRUE;
    }
    return FALSE;
}
/* shared 1-byte lock: 1 = done (ok), 0 = refused (last error set), -1 = not handled here */
static int lt_lock_shared(HANDLE h, ULONGLONG off)
{
    DWORD key = path_key(h); int i, fr = -1;
    if (!key || !lt_open()) return -1;
    WaitForSingleObject(g_lt_mx, INFINITE);
    if (!LockFile(h, (DWORD)off, (DWORD)(off >> 32), 1, 0)) {          /* someone holds it exclusively */
        DWORD le = GetLastError(); ReleaseMutex(g_lt_mx); SetLastError(le); return 0;
    }
    UnlockFile(h, (DWORD)off, (DWORD)(off >> 32), 1, 0);
    for (i = 0; i < NLT; i++) if (!g_lt->e[i].pid) { fr = i; break; }
    if (fr < 0) { ReleaseMutex(g_lt_mx); return -1; }                   /* table full: old behaviour */
    g_lt->e[fr].h = h; g_lt->e[fr].key = key; g_lt->e[fr].off = off; g_lt->e[fr].pid = GetCurrentProcessId();
    ReleaseMutex(g_lt_mx);
    return 1;
}
/* exclusive lock through kexnt (table mutex held): another handle has a shared 1-byte entry in the range? */
static BOOL lt_conflict_h(HANDLE h, ULONGLONG off, ULONGLONG len)
{
    DWORD key = path_key(h);
    return key && lt_conflict(key, h, off, len);
}
/* unlock: TRUE if this handle had a 1-byte shared entry at off (removed) */
static BOOL lt_unlock(HANDLE h, ULONGLONG off)
{
    int i; DWORD me = GetCurrentProcessId(); BOOL found = FALSE;
    if (!g_lt) return FALSE;
    WaitForSingleObject(g_lt_mx, INFINITE);
    for (i = 0; i < NLT; i++) if (g_lt->e[i].pid == me && g_lt->e[i].h == h && g_lt->e[i].off == off) { g_lt->e[i].pid = 0; found = TRUE; break; }
    ReleaseMutex(g_lt_mx);
    return found;
}

/* ---- build 132: SetEndOfFile on a file another handle of this process has locked ----
 * Measured (SQLite 3.54.1, Pale Moon 35's mozsqlite3.dll; probe SQL354.EXE): WAL failed with "disk I/O error",
 * os_win.c winShmMap2 -> winHandleTruncate -> SetEndOfFile error 33 (ERROR_LOCK_VIOLATION). Since 3.4x SQLite opens the
 * wal-index ("-shm") twice: one handle per connection takes the locks, a shared handle grows and maps the file. NT
 * grows a file whatever byte-range locks other handles hold; Windows 98 refuses while another handle has a lock in it.
 * So the real locks this process holds are remembered; when SetEndOfFile is refused with a lock violation, this
 * process's locks on the same file (other handles, same path) are released, the size is set, and they are taken
 * again - all under the cross-process lock mutex that every exclusive lock through kexnt also takes, so no other
 * kexnt process can take those bytes in between. */
#define NRL 512
typedef struct { HANDLE h; ULONGLONG off, len; } RL;
static RL g_rl[NRL]; static int g_nrl;
static void rl_add(HANDLE h, ULONGLONG off, ULONGLONG len)     /* g_lock_cs held */
{ if (g_nrl < NRL) { g_rl[g_nrl].h = h; g_rl[g_nrl].off = off; g_rl[g_nrl].len = len; g_nrl++; } }
static void rl_del(HANDLE h, ULONGLONG off, ULONGLONG len)     /* g_lock_cs held */
{ int i; for (i = g_nrl - 1; i >= 0; i--) if (g_rl[i].h == h && g_rl[i].off == off && g_rl[i].len == len) { g_rl[i] = g_rl[--g_nrl]; return; } }
BOOL kex_lockfile_eof_retry(HANDLE h)
{
    DWORD key; int i, n = 0, idx[64]; BOOL ok;
    if (g_lock_init != 2 || !g_nrl || !(key = path_key(h)) || !lt_open()) return FALSE;
    WaitForSingleObject(g_lt_mx, INFINITE);
    EnterCriticalSection(&g_lock_cs);
    for (i = 0; i < g_nrl && n < 64; i++)
        if (g_rl[i].h != h && path_key(g_rl[i].h) == key &&
            UnlockFile(g_rl[i].h, (DWORD)g_rl[i].off, (DWORD)(g_rl[i].off >> 32), (DWORD)g_rl[i].len, (DWORD)(g_rl[i].len >> 32)))
            idx[n++] = i;
    ok = n ? SetEndOfFile(h) : FALSE;
    {   DWORD le = GetLastError(); int bad = 0;
        for (i = 0; i < n; i++) if (!LockFile(g_rl[idx[i]].h, (DWORD)g_rl[idx[i]].off, (DWORD)(g_rl[idx[i]].off >> 32), (DWORD)g_rl[idx[i]].len, (DWORD)(g_rl[idx[i]].len >> 32))) bad++;
        LeaveCriticalSection(&g_lock_cs);
        ReleaseMutex(g_lt_mx);
        { static LONG k; if (InterlockedIncrement(&k) <= 20) note_fail(ok ? "lock: SetEndOfFile done with this process's other locks on the file lifted (handle, lifted, not retaken, -)" : "lock: SetEndOfFile still refused (handle, lifted, not retaken, -)", h, (ULONGLONG)n, (ULONGLONG)bad); }
        SetLastError(le);
    }
    return ok;
}

BOOL KEXAPI kex_LockFileEx(HANDLE h, DWORD flags, DWORD reserved, DWORD lenLo, DWORD lenHi, LPOVERLAPPED ov)
{
    ULONGLONG off, len = ((ULONGLONG)lenHi << 32) | lenLo, byte;
    BOOL excl = (flags & LOCKFILE_EXCLUSIVE_LOCK_) != 0, ok;
    if (reserved || !ov) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!len) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    off = ((ULONGLONG)ov->OffsetHigh << 32) | ov->Offset;
    init();
    for (;;) {
        if (!excl && len == 1) {                                       /* build 132: real shared 1-byte locks */
            int r = lt_lock_shared(h, off);
            if (r >= 0) {
                if (g_lock_dbg) note_dbg(r ? "lock: shared 1-byte lock ok (handle, offset, flags, -)" : "lock: shared 1-byte lock refused (handle, offset, flags, error)", h, off, flags, r ? 0 : GetLastError());
                if (r) { if (ov->hEvent) SetEvent(ov->hEvent); return TRUE; }
                if ((flags & LOCKFILE_FAIL_IMMEDIATELY_) || GetLastError() != ERROR_LOCK_VIOLATION) return FALSE;
                Sleep(10); continue;
            }
        }
        {   BOOL mx = excl && (g_lt || lt_open());
            if (mx) WaitForSingleObject(g_lt_mx, INFINITE);       /* build 132: exclusive locks under the table mutex */
            if (mx && lt_conflict_h(h, off, len)) {                 /* someone holds it shared (1-byte entries) */
                ReleaseMutex(g_lt_mx);
                SetLastError(ERROR_LOCK_VIOLATION);
                if (g_lock_dbg) note_dbg("lock: exclusive lock refused, shared 1-byte holders (handle, offset, length, -)", h, off, len, 0);
                if (flags & LOCKFILE_FAIL_IMMEDIATELY_) return FALSE;
                Sleep(10); continue;
            }
            EnterCriticalSection(&g_lock_cs);
            ok = try_lock(h, excl, off, len, &byte);
            if (ok) { if (byte == (ULONGLONG)-1) rl_add(h, off, clamp_len(off, len)); else rl_add(h, byte, 1); }
            if (mx) ReleaseMutex(g_lt_mx);
        }
        if (ok && byte != (ULONGLONG)-1) {
            if (g_nsh < MAX_SHARED) { g_sh[g_nsh].h = h; g_sh[g_nsh].off = off; g_sh[g_nsh].len = len; g_sh[g_nsh].byte = byte; g_nsh++; }
            else { UnlockFile(h, (DWORD)byte, (DWORD)(byte >> 32), 1, 0); ok = FALSE; SetLastError(ERROR_NOT_ENOUGH_MEMORY); }
        }
        LeaveCriticalSection(&g_lock_cs);
        if (g_lock_dbg) note_dbg(ok ? "lock: LockFileEx ok (handle, offset, length|flags<<24, byte)" : "lock: LockFileEx failed (handle, offset, length|flags<<24, error)", h, off, (len & 0xFFFFFF) | (flags << 24), ok ? byte : GetLastError());
        if (ok) { if (ov->hEvent) SetEvent(ov->hEvent); return TRUE; }
        if ((flags & LOCKFILE_FAIL_IMMEDIATELY_) || GetLastError() != ERROR_LOCK_VIOLATION) return FALSE;
        Sleep(10);                                      /* NT waits for the lock; so do we */
    }
}

BOOL KEXAPI kex_UnlockFileEx(HANDLE h, DWORD reserved, DWORD lenLo, DWORD lenHi, LPOVERLAPPED ov)
{
    ULONGLONG off, len = ((ULONGLONG)lenHi << 32) | lenLo;
    int i; BOOL ok;
    if (reserved || !ov) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    off = ((ULONGLONG)ov->OffsetHigh << 32) | ov->Offset;
    init();
    if (len == 1 && lt_unlock(h, off)) {                               /* build 132: a shared 1-byte entry */
        if (g_lock_dbg) note_dbg("lock: shared 1-byte unlock (handle, offset, -, -)", h, off, 0, 0);
        return TRUE;
    }
    EnterCriticalSection(&g_lock_cs);
    for (i = g_nsh - 1; i >= 0; i--)
        if (g_sh[i].h == h && g_sh[i].off == off && g_sh[i].len == len) break;
    if (i >= 0) {
        ULONGLONG b = g_sh[i].byte;
        g_sh[i] = g_sh[--g_nsh];
        ok = UnlockFile(h, (DWORD)b, (DWORD)(b >> 32), 1, 0);
        if (ok) rl_del(h, b, 1);
        if (!ok) note_fail("lock: UnlockFileEx of a shared lock failed (handle, offset, its byte, error)", h, off, b);
    } else {
        len = clamp_len(off, len);
        ok = UnlockFile(h, (DWORD)off, (DWORD)(off >> 32), (DWORD)len, (DWORD)(len >> 32));
        if (ok) rl_del(h, off, len);
        if (!ok) note_fail("lock: UnlockFileEx of an exclusive range failed (handle, offset, length, error)", h, off, len);
    }
    LeaveCriticalSection(&g_lock_cs);
    /* build 131: NT says ERROR_NOT_LOCKED (158) for a range this handle does not hold; Windows 98 says
     * ERROR_LOCK_VIOLATION (33). SQLite (winUnlockReadLock) expects 158 - anything else it logs as SQLITE_IOERR_UNLOCK */
    if (!ok && GetLastError() == ERROR_LOCK_VIOLATION) SetLastError(158 /* ERROR_NOT_LOCKED */);
    if (g_lock_dbg) note_dbg(ok ? "lock: UnlockFileEx ok (handle, offset, length, -)" : "lock: UnlockFileEx failed (handle, offset, length, error)", h, off, len, ok ? 0 : GetLastError());
    return ok;
}

/* build 131: CloseHandle - Windows drops the handle's locks; forget its shared-lock bytes, or a later file that gets
 * the same handle value would "unlock" a byte it never locked (and keep its own real one) */
void kex_lockfile_close(HANDLE h)
{
    int i, n = 0;
    if (g_lt) {                                                        /* build 132: its shared 1-byte entries */
        DWORD me = GetCurrentProcessId();
        WaitForSingleObject(g_lt_mx, INFINITE);
        for (i = 0; i < NLT; i++) if (g_lt->e[i].pid == me && g_lt->e[i].h == h) g_lt->e[i].pid = 0;
        ReleaseMutex(g_lt_mx);
    }
    if (g_lock_init != 2) return;
    EnterCriticalSection(&g_lock_cs);
    for (i = g_nrl - 1; i >= 0; i--) if (g_rl[i].h == h) g_rl[i] = g_rl[--g_nrl];   /* build 132 */
    if (!g_nsh) { LeaveCriticalSection(&g_lock_cs); return; }
    for (i = g_nsh - 1; i >= 0; i--) if (g_sh[i].h == h) { g_sh[i] = g_sh[--g_nsh]; n++; }
    LeaveCriticalSection(&g_lock_cs);
    if (n) note_fail("lock: handle closed with shared locks still held (handle, count, -, -)", h, n, 0);
}
