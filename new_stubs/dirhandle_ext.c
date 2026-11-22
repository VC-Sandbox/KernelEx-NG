/*
 * dirhandle_ext.c - KernelEx-NG: handles to directories (CreateFile + FILE_FLAG_BACKUP_SEMANTICS).
 *
 * NT opens a directory with CreateFile when FILE_FLAG_BACKUP_SEMANTICS is given; programs then ask the handle
 * for times/attributes (GetFileInformationByHandle, GetFileTime) and close it. Windows 98 cannot open
 * directories at all: CreateFile fails with ERROR_ACCESS_DENIED. Mozilla's OS.File.stat() does exactly this;
 * in Mypal 29 the search service died on it ("Win error 5 during operation open on file
 * ...\browser\searchplugins"), and with it the address bar (2026-11-02).
 * A directory handle here is a real kernel object (an event, so CloseHandle/DuplicateHandle work) remembered
 * with the directory's full path; the file-information calls answer from FindFirstFile / GetFileAttributes.
 */
#include "kexnt_common.h"

#define MAX_DIRH 64
static struct { HANDLE h; char path[MAX_PATH]; } g_dh[MAX_DIRH];
static volatile LONG g_dh_lock;
static void dlock(void) { kex_spin_acquire((volatile LONG *)&g_dh_lock); }
static void dunlock(void) { InterlockedExchange((LONG *)&g_dh_lock, 0); }

/* CreateFileA path for directories: returns a handle, or NULL if this is not a directory request. */
HANDLE kex_dir_open(LPCSTR name, DWORD disp, DWORD flags)
{
    char full[MAX_PATH], *fp; DWORD a; HANDLE h; int i;
    if (!(flags & FILE_FLAG_BACKUP_SEMANTICS) || !name) return NULL;
    if (disp != OPEN_EXISTING && disp != OPEN_ALWAYS) return NULL;
    a = GetFileAttributesA(name);
    if (a == 0xFFFFFFFF || !(a & FILE_ATTRIBUTE_DIRECTORY)) return NULL;
    if (!GetFullPathNameA(name, sizeof(full), full, &fp)) return NULL;
    if (!(h = CreateEventA(NULL, TRUE, TRUE, NULL))) return NULL;
    dlock();
    for (i = 0; i < MAX_DIRH; i++) if (!g_dh[i].h) { g_dh[i].h = h; lstrcpynA(g_dh[i].path, full, MAX_PATH); break; }
    dunlock();
    if (i == MAX_DIRH) { CloseHandle(h); return NULL; }
    SetLastError(0);
    return h;
}

static BOOL dir_path(HANDLE h, char *out)
{
    int i; BOOL f = FALSE;
    if (!h || h == INVALID_HANDLE_VALUE) return FALSE;
    dlock();
    for (i = 0; i < MAX_DIRH; i++) if (g_dh[i].h == h) { if (out) lstrcpyA(out, g_dh[i].path); f = TRUE; break; }
    dunlock();
    return f;
}

BOOL kex_dir_is(HANDLE h) { return dir_path(h, NULL); }

/* ReadDirectoryChangesW (build 21). Win98's KERNEL32 export fails it. With an OVERLAPPED the request is
 * accepted and stays pending (no change is ever reported); closing the directory handle completes it with
 * ERROR_OPERATION_ABORTED - event, OVERLAPPED status and completion-port packet - as NT does. Chromium's
 * FilePathWatcher (base/files/file_path_watcher_win.cc) relies on exactly that to retire a watch. */
#define MAX_RDC 64
static struct { HANDLE h; LPOVERLAPPED ov; } g_rdc[MAX_RDC];
void kex_iocp_done(HANDLE h, LPOVERLAPPED ov, DWORD bytes, DWORD err, BOOL immediate);   /* iocp_ext.c */
BOOL KEXAPI kex_ReadDirectoryChangesW(HANDLE h, LPVOID buf, DWORD len, BOOL subtree, DWORD filter, LPDWORD ret,
                                       LPOVERLAPPED ov, LPOVERLAPPED_COMPLETION_ROUTINE routine)
{
    int i;
    (void)buf; (void)subtree; (void)filter; (void)routine;
    if (!dir_path(h, NULL)) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (!len || !ov) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }   /* a synchronous call would wait forever */
    dlock();
    for (i = 0; i < MAX_RDC; i++) if (!g_rdc[i].h) { g_rdc[i].h = h; g_rdc[i].ov = ov; break; }
    dunlock();
    if (i == MAX_RDC) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    ov->Internal = 0x103; ov->InternalHigh = 0;                                 /* STATUS_PENDING */
    if (ov->hEvent) ResetEvent(ov->hEvent);
    if (ret) *ret = 0;
    return TRUE;
}

void kex_dir_close(HANDLE h)
{
    int i; LPOVERLAPPED done[MAX_RDC]; int nd = 0;
    if (!h) return;                                   /* build 131: 0 marks an empty slot */
    dlock();
    for (i = 0; i < MAX_DIRH; i++) if (g_dh[i].h == h) { g_dh[i].h = NULL; break; }
    for (i = 0; i < MAX_RDC; i++) if (g_rdc[i].h == h) { done[nd++] = g_rdc[i].ov; g_rdc[i].h = NULL; }
    dunlock();
    for (i = 0; i < nd; i++) {
        void kex_iocp_done2(HANDLE h, LPOVERLAPPED ov, HANDLE ev, DWORD bytes, DWORD err, BOOL immediate);
        HANDLE ev = done[i]->hEvent;                                             /* before signalling (build 37) */
        done[i]->InternalHigh = 0; done[i]->Internal = 0xC0000120;               /* STATUS_CANCELLED */
        kex_iocp_done2(h, done[i], ev, 0, ERROR_OPERATION_ABORTED, FALSE);
        if (ev) SetEvent(ev);
    }
}

static BOOL dir_info(HANDLE h, BY_HANDLE_FILE_INFORMATION *fi)
{
    char p[MAX_PATH], root[4]; WIN32_FIND_DATAA fd; HANDLE f; DWORD serial = 0, hash = 2166136261UL; int n; const char *s;
    if (!dir_path(h, p)) return FALSE;
    memset(fi, 0, sizeof(*fi));
    n = lstrlenA(p);
    while (n > 3 && p[n - 1] == '\\') p[--n] = 0;               /* "C:\dir\" -> "C:\dir" for FindFirstFile */
    f = FindFirstFileA(p, &fd);
    if (f != INVALID_HANDLE_VALUE) {
        FindClose(f);
        fi->dwFileAttributes = fd.dwFileAttributes;
        fi->ftCreationTime = fd.ftCreationTime; fi->ftLastAccessTime = fd.ftLastAccessTime; fi->ftLastWriteTime = fd.ftLastWriteTime;
    } else
        fi->dwFileAttributes = GetFileAttributesA(p) | FILE_ATTRIBUTE_DIRECTORY;   /* a drive root */
    if (p[0] && p[1] == ':') { root[0] = p[0]; root[1] = ':'; root[2] = '\\'; root[3] = 0;
        GetVolumeInformationA(root, NULL, 0, &serial, NULL, NULL, NULL, 0); }
    fi->dwVolumeSerialNumber = serial;
    fi->nNumberOfLinks = 1;
    for (s = p; *s; s++) { char c = *s; if (c >= 'a' && c <= 'z') c -= 32; hash = (hash ^ (BYTE)c) * 16777619UL; }
    fi->nFileIndexLow = hash; fi->nFileIndexHigh = 0x4B58;      /* stable per path, never 0 */
    return TRUE;
}

BOOL KEXAPI kex_GetFileInformationByHandle(HANDLE h, BY_HANDLE_FILE_INFORMATION *fi)
{
    if (!fi) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (kex_dir_is(h)) return dir_info(h, fi);
    return GetFileInformationByHandle(h, fi);
}

BOOL KEXAPI kex_GetFileTime(HANDLE h, FILETIME *c, FILETIME *a, FILETIME *w)
{
    BY_HANDLE_FILE_INFORMATION fi;
    if (!kex_dir_is(h)) return GetFileTime(h, c, a, w);
    if (!dir_info(h, &fi)) return FALSE;
    if (c) *c = fi.ftCreationTime;
    if (a) *a = fi.ftLastAccessTime;
    if (w) *w = fi.ftLastWriteTime;
    return TRUE;
}

BOOL KEXAPI kex_SetFileTime(HANDLE h, const FILETIME *c, const FILETIME *a, const FILETIME *w)
{
    if (kex_dir_is(h)) return TRUE;                       /* 9x keeps no settable directory times: accept */
    return SetFileTime(h, c, a, w);
}

DWORD KEXAPI kex_GetFileSize(HANDLE h, LPDWORD hi)
{
    if (kex_dir_is(h)) { if (hi) *hi = 0; SetLastError(0); return 0; }
    return GetFileSize(h, hi);
}
