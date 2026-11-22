/*
 * fpath_ext.c - KernelEx-NG (build 50): which file a handle belongs to.
 *
 * Windows 98 keeps no path per file handle, so NT calls that work on an open handle had nothing to go on:
 * SetFileInformationByHandle(FileDispositionInfo) - "delete when closed", which Chromium sets and clears on its
 * download, cache and temporary files (base::File::DeleteOnClose) - and GetFinalPathNameByHandle. Every Chromium
 * download failed with "Something went wrong" (KEXCRASH: class 4 refused, 40+ times per run).
 * kexnt's CreateFileA/W remember the full path of each disk file they open (hash table, heap strings); the
 * disposition flag is kept here and the file is deleted when kexnt's CloseHandle closes that handle.
 */
#include "kexnt_common.h"

#define FP_N 4096                                  /* open slots; Chromium has a few hundred files open */
typedef struct { HANDLE h; char *path; BOOL del; } FP;
static FP g_fp[FP_N];
static volatile LONG g_fplk;

static DWORD slot0(HANDLE h) { return ((DWORD)(ULONG_PTR)h >> 2) * 2654435761UL % FP_N; }

void kex_fpath_note(HANDLE h, LPCSTR name)
{
    char full[MAX_PATH], *fp; DWORD n, i, s; char *p;
    if (h == INVALID_HANDLE_VALUE || !h || !name) return;
    n = GetFullPathNameA(name, MAX_PATH, full, &fp);
    if (!n || n >= MAX_PATH) return;
    if (!(p = (char *)HeapAlloc(GetProcessHeap(), 0, n + 1))) return;
    lstrcpyA(p, full);
    kex_spin_acquire(&g_fplk);
    for (i = 0, s = slot0(h); i < FP_N; i++, s = (s + 1) % FP_N)
        if (!g_fp[s].h || g_fp[s].h == h) {          /* a stale entry for a reused handle value is replaced */
            char *old = g_fp[s].h == h ? g_fp[s].path : NULL;
            g_fp[s].h = h; g_fp[s].path = p; g_fp[s].del = FALSE; p = old;
            break;
        }
    InterlockedExchange(&g_fplk, 0);
    if (p) HeapFree(GetProcessHeap(), 0, p);         /* the old string, or ours if the table is full */
}

static int find(HANDLE h)
{
    DWORD i, s;
    for (i = 0, s = slot0(h); i < FP_N && g_fp[s].h; i++, s = (s + 1) % FP_N) if (g_fp[s].h == h) return (int)s;
    return -1;
}

/* path of an open handle into buf (ANSI), FALSE if unknown */
BOOL kex_fpath_get(HANDLE h, char *buf, DWORD cb)
{
    int s; BOOL ok = FALSE;
    kex_spin_acquire(&g_fplk);
    if ((s = find(h)) >= 0 && (DWORD)lstrlenA(g_fp[s].path) < cb) { lstrcpyA(buf, g_fp[s].path); ok = TRUE; }
    InterlockedExchange(&g_fplk, 0);
    return ok;
}

BOOL kex_fpath_set_delete(HANDLE h, BOOL del)
{
    int s; BOOL ok = FALSE;
    kex_spin_acquire(&g_fplk);
    if ((s = find(h)) >= 0) { g_fp[s].del = del; ok = TRUE; }
    InterlockedExchange(&g_fplk, 0);
    return ok;
}

/* kex_CloseHandle, after Windows closed h: forget it, delete the file if it was marked (open-addressing removal) */
void kex_fpath_closed(HANDLE h)
{
    int s; char *path = NULL; BOOL del = FALSE; DWORD i, j, k;
    kex_spin_acquire(&g_fplk);
    if ((s = find(h)) >= 0) {
        path = g_fp[s].path; del = g_fp[s].del;
        g_fp[s].h = NULL; g_fp[s].path = NULL; g_fp[s].del = FALSE;
        /* re-insert the cluster after s so lookups do not stop at the hole */
        for (i = 1, j = ((DWORD)s + 1) % FP_N; i < FP_N && g_fp[j].h; i++, j = (j + 1) % FP_N) {
            FP e = g_fp[j]; g_fp[j].h = NULL; g_fp[j].path = NULL; g_fp[j].del = FALSE;
            for (k = slot0(e.h); g_fp[k].h; k = (k + 1) % FP_N) ;
            g_fp[k] = e;
        }
    }
    InterlockedExchange(&g_fplk, 0);
    if (path) {
        if (del) { DWORD a = GetFileAttributesA(path); if (a != 0xFFFFFFFF && (a & FILE_ATTRIBUTE_READONLY)) SetFileAttributesA(path, a & ~FILE_ATTRIBUTE_READONLY); DeleteFileA(path); }
        HeapFree(GetProcessHeap(), 0, path);
    }
}

/* ---- build 51: what Chromium's download does on disk. Pass-through wrappers (KernelEx's implementation or
 * Windows' own) that write to KEXCRASH: every move/rename (first 30, with result), and failed deletes /
 * directory creations. */
void kex_dl_note(const char *api, const char *path, BOOL ok, DWORD err, DWORD x);
FARPROC kex_prev_impl(const char *dll, const char *name);
void kex_filefail(const char *api, const char *path, DWORD err, DWORD a, DWORD b);
void kex_crashlog_text(const char *s);
static void w2a(LPCWSTR w, char *a, int cb) { a[0] = 0; if (w) WideCharToMultiByte(CP_ACP, 0, w, -1, a, cb, NULL, NULL); a[cb - 1] = 0; }
static void note_move(const char *api, LPCWSTR from, LPCWSTR to, BOOL ok, DWORD err, DWORD flags)
{
    static volatile LONG n; char t[2 * MAX_PATH + 120], a[MAX_PATH], b[MAX_PATH]; int l; DWORD v; int i;
    if (InterlockedIncrement(&n) > 30) return;
    w2a(from, a, MAX_PATH); w2a(to, b, MAX_PATH);
    lstrcpyA(t, "--- file move: "); lstrcatA(t, api); lstrcatA(t, ok ? " ok" : " FAILED error ");
    if (!ok) { char d[12]; int k = 11; d[k] = 0; v = err; do { d[--k] = (char)('0' + v % 10); v /= 10; } while (v); lstrcatA(t, d + k); }
    lstrcatA(t, " flags "); l = lstrlenA(t); for (i = 3; i >= 0; i--) t[l++] = "0123456789abcdef"[(flags >> (i * 4)) & 15]; t[l] = 0;
    lstrcatA(t, "  "); lstrcatA(t, a); lstrcatA(t, " -> "); lstrcatA(t, b);
    kex_crashlog_text(t);
}
BOOL KEXAPI kex_MoveFileExW(LPCWSTR from, LPCWSTR to, DWORD flags)
{
    typedef BOOL (WINAPI *T)(LPCWSTR, LPCWSTR, DWORD); static T p; BOOL r; DWORD le;
    if (!p) p = (T)(void *)kex_prev_impl("KERNEL32.DLL", "MoveFileExW");
    if (!p) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    r = p(from, to, flags); le = GetLastError();
    note_move("MoveFileExW", from, to, r, le, flags);
    { char a[MAX_PATH]; w2a(to, a, MAX_PATH); kex_dl_note("MoveFileExW (to)", a, r, le, flags); }
    SetLastError(le); return r;
}
BOOL KEXAPI kex_MoveFileW(LPCWSTR from, LPCWSTR to)
{
    typedef BOOL (WINAPI *T)(LPCWSTR, LPCWSTR); static T p; BOOL r; DWORD le;
    if (!p) p = (T)(void *)kex_prev_impl("KERNEL32.DLL", "MoveFileW");
    if (!p) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    r = p(from, to); le = GetLastError();
    note_move("MoveFileW", from, to, r, le, 0);
    SetLastError(le); return r;
}
BOOL KEXAPI kex_DeleteFileW(LPCWSTR name)
{
    typedef BOOL (WINAPI *T)(LPCWSTR); static T p; BOOL r; DWORD le;
    if (!p) p = (T)(void *)kex_prev_impl("KERNEL32.DLL", "DeleteFileW");
    if (!p) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    r = p(name); le = GetLastError();
    if (!r && le != ERROR_FILE_NOT_FOUND && le != ERROR_PATH_NOT_FOUND) { char a[MAX_PATH]; w2a(name, a, MAX_PATH); kex_filefail("DeleteFileW", a, le, 0, 0); }
    SetLastError(le); return r;
}
BOOL KEXAPI kex_CreateDirectoryW(LPCWSTR name, LPSECURITY_ATTRIBUTES sa)
{
    typedef BOOL (WINAPI *T)(LPCWSTR, LPSECURITY_ATTRIBUTES); static T p; BOOL r; DWORD le;
    if (!p) p = (T)(void *)kex_prev_impl("KERNEL32.DLL", "CreateDirectoryW");
    if (!p) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    r = p(name, sa); le = GetLastError();
    {   char a[MAX_PATH]; w2a(name, a, MAX_PATH);
        if (!r && le != ERROR_ALREADY_EXISTS) kex_filefail("CreateDirectoryW", a, le, 0, 0);
        { void kex_dl_note(const char *api, const char *path, BOOL ok, DWORD err, DWORD x); kex_dl_note("CreateDirectoryW", a, r, le, 0); } }
    SetLastError(le); return r;
}

/* build 54: everything that touches a download (path contains "download", ".crdownload" or "unconfirmed"),
 * successes too, first 60 - Chromium's downloads fail without any failing call logged so far. */
void kex_dl_note(const char *api, const char *path, BOOL ok, DWORD err, DWORD x)
{
    static volatile LONG n; char t[MAX_PATH + 120], low[MAX_PATH]; int i; DWORD v; char d[12]; int k;
    if (!path) return;
    for (i = 0; path[i] && i < MAX_PATH - 1; i++) low[i] = (path[i] >= 'A' && path[i] <= 'Z') ? (char)(path[i] + 32) : path[i];
    low[i] = 0;
    { const char *pat[3] = { "download", ".crdownload", "unconfirmed" }; int m, hit = 0;
      for (m = 0; m < 3 && !hit; m++) { const char *q = low; int L = lstrlenA(pat[m]);
        for (; *q && !hit; q++) { int j; for (j = 0; j < L && q[j] == pat[m][j]; j++) ; if (j == L) hit = 1; } }
      if (!hit) return; }
    if (InterlockedIncrement(&n) > 60) return;
    lstrcpyA(t, "--- download file: "); lstrcatA(t, api); lstrcatA(t, ok ? " ok" : " FAILED error ");
    if (!ok) { k = 11; d[k] = 0; v = err; do { d[--k] = (char)('0' + v % 10); v /= 10; } while (v); lstrcatA(t, d + k); }
    lstrcatA(t, " ("); k = 11; d[k] = 0; v = x; do { d[--k] = (char)('0' + v % 10); v /= 10; } while (v); lstrcatA(t, d + k); lstrcatA(t, ") ");
    lstrcatA(t, path);
    kex_crashlog_text(t);
}
