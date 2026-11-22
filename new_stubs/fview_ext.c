/* fview_ext.c - read-only views of files that are also written with WriteFile (2026-11-10, build 23).
 *
 * On NT a mapped view of a file and ReadFile/WriteFile on the same file share one cache: what WriteFile
 * stores is immediately visible in the view. On Windows 98 they do not (the pager reads the file into its own
 * pages; WriteFile goes through VCACHE), so a view shows stale data after a write.
 * SQLite relies on the NT behaviour: with memory-mapped I/O it READS the database through a PAGE_READONLY
 * view of the very handle it WRITES with (sqlite3.c winMapfile/winWrite). Chromium turns that on for every
 * database (sql/database.cc: "PRAGMA mmap_size=268435456"), so on Win98 a fresh profile's databases failed
 * right after their first write ("Failed to set up eq_classes table", "Profile error occurred").
 *
 * Here: a PAGE_READONLY mapping made from a file handle that was opened for writing gets, per view, a private
 * copy of that file range (VirtualAlloc: 64 KB aligned like NT views) instead of a Win98 view, and every
 * WriteFile through that handle is copied into the views that overlap it. Files opened read-only
 * (resources, ICU data, ...) and writable mappings keep real Win98 views.
 * Limits: writes through another handle or another process are not seen (they are not on Win98 either).
 */
#include "kexnt_common.h"
#include <string.h>
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
BOOL KEXAPI kex_ReadFile(HANDLE h, LPVOID buf, DWORD n, LPDWORD got, LPOVERLAPPED ov);   /* pipe_ext.c */

#define NWR    8192            /* handle/4 slots: handles opened for writing */
#define NSEC   128
#define NVIEW  256
#define MAX_VIEW (64UL * 1024 * 1024)

static BYTE g_wr[NWR];
typedef struct { HANDLE sec, file; } FSEC;
typedef struct { BYTE *base; DWORD size; HANDLE file; DWORD off; } FVIEW;
static FSEC g_sec[NSEC];
static FVIEW g_view[NVIEW];
static volatile LONG g_lock, g_nsec, g_nview;

static void lk(void) { kex_spin_acquire(&g_lock); }
static void ulk(void) { InterlockedExchange((LONG *)&g_lock, 0); }
static DWORD slot(HANDLE h) { return (DWORD)(ULONG_PTR)h >> 2; }

/* CreateFile succeeded (pipe_ext.c): remember whether the handle can write. */
void kex_fview_file_opened(HANDLE h, DWORD access)
{
    DWORD s = slot(h);
    if (h == INVALID_HANDLE_VALUE || s >= NWR) return;
    g_wr[s] = (access & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA)) ? 1 : 2;   /* 2 = read-only */
}
/* build 66: what kexnt knows about a file handle - 1 writable, 2 read-only, 0 unknown (NtQueryObject) */
int kex_fview_access(HANDLE h) { DWORD s = slot(h); return (h && h != INVALID_HANDLE_VALUE && s < NWR) ? g_wr[s] : 0; }
/* DuplicateHandle in this process: the copy has the source's rights (same access) or the asked ones */
void kex_fview_dup(HANDLE src, HANDLE dst, BOOL same, DWORD access)
{
    DWORD s = slot(src), d = slot(dst);
    if (!dst || dst == INVALID_HANDLE_VALUE || d >= NWR) return;
    if (same) g_wr[d] = s < NWR ? g_wr[s] : 0;
    else if (s < NWR && g_wr[s]) g_wr[d] = (g_wr[s] == 1 && (access & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA))) ? 1 : 2;
    else g_wr[d] = 0;
}

/* CreateFileMapping succeeded (shm_ext.c). */
void kex_fview_section(HANDLE sec, HANDLE file, DWORD protect)
{
    int i;
    if (!sec || !file || file == INVALID_HANDLE_VALUE || (protect & 0xFF) != PAGE_READONLY) return;
    if (slot(file) >= NWR || g_wr[slot(file)] != 1 || GetFileType(file) != FILE_TYPE_DISK) return;
    lk();
    for (i = 0; i < NSEC; i++) if (!g_sec[i].sec) { g_sec[i].sec = sec; g_sec[i].file = file; g_nsec++; break; }
    ulk();
    { static LONG n; if (InterlockedIncrement(&n) <= 40) kex_trace("fview: read-only mapping of a writable file", (DWORD)(ULONG_PTR)sec, (DWORD)(ULONG_PTR)file, i < NSEC, 0); }
}

/* MapViewOfFile: a private, filled view - or NULL to let Win98 map it. */
LPVOID kex_fview_map(HANDLE sec, DWORD access, DWORD hi, DWORD lo, SIZE_T n)
{
    HANDLE file = NULL; int i; BYTE *b; DWORD size, got = 0, fsz, fhi = 0; LONG ph = 0; DWORD pl; OVERLAPPED ov; BOOL ok;
    if (!g_nsec || access != FILE_MAP_READ || hi) return NULL;
    lk();
    for (i = 0; i < NSEC; i++) if (g_sec[i].sec == sec) { file = g_sec[i].file; break; }
    ulk();
    if (!file) return NULL;
    fsz = GetFileSize(file, &fhi);
    if (fsz == 0xFFFFFFFF || fhi || lo >= fsz) return NULL;
    size = n ? (DWORD)n : fsz - lo;
    if (!size || size > MAX_VIEW) return NULL;
    if (!(b = (BYTE *)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return NULL;
    pl = SetFilePointer(file, 0, &ph, FILE_CURRENT);            /* the file position is the program's: keep it */
    ZeroMemory(&ov, sizeof(ov)); ov.Offset = lo;
    ok = kex_ReadFile(file, b, size < fsz - lo ? size : fsz - lo, &got, &ov);
    if (pl != 0xFFFFFFFF || GetLastError() == NO_ERROR) SetFilePointer(file, (LONG)pl, &ph, FILE_BEGIN);
    if (!ok) { VirtualFree(b, 0, MEM_RELEASE); kex_trace("fview: reading the file failed", (DWORD)(ULONG_PTR)file, lo, size, GetLastError()); return NULL; }
    lk();
    for (i = 0; i < NVIEW; i++) if (!g_view[i].base) { g_view[i].base = b; g_view[i].size = size; g_view[i].file = file; g_view[i].off = lo; g_nview++; break; }
    ulk();
    if (i == NVIEW) { VirtualFree(b, 0, MEM_RELEASE); return NULL; }
    { static LONG c; if (InterlockedIncrement(&c) <= 60) kex_trace("fview: private view", (DWORD)(ULONG_PTR)b, lo, size, (DWORD)(ULONG_PTR)file); }
    SetLastError(0);
    return b;
}

/* UnmapViewOfFile: TRUE if a was one of ours (released). */
BOOL kex_fview_unmap(LPCVOID a)
{
    int i; BOOL f = FALSE;
    if (!g_nview || !a) return FALSE;
    lk();
    for (i = 0; i < NVIEW; i++) if (g_view[i].base == (const BYTE *)a) { g_view[i].base = NULL; g_nview--; f = TRUE; break; }
    ulk();
    if (f) VirtualFree((LPVOID)a, 0, MEM_RELEASE);
    return f;
}

/* WriteFile(h, buf, n) stored n bytes at off: show them in the views of h. */
void kex_fview_written(HANDLE h, const BYTE *buf, DWORD n, DWORD off_lo, DWORD off_hi)
{
    int i;
    if (!g_nview || !n || off_hi) return;
    lk();
    for (i = 0; i < NVIEW; i++) {
        FVIEW *v = &g_view[i]; DWORD a, b;
        if (!v->base || v->file != h) continue;
        a = off_lo > v->off ? off_lo : v->off;
        b = (off_lo + n < v->off + v->size) ? off_lo + n : v->off + v->size;
        if (off_lo + n < off_lo) b = v->off + v->size;            /* wrapped past 4 GB */
        if (a < b) memcpy(v->base + (a - v->off), buf + (a - off_lo), b - a);
    }
    ulk();
}
BOOL kex_fview_any(void) { return g_nview != 0; }

/* CloseHandle. */
void kex_fview_close(HANDLE h)
{
    int i;
    if (slot(h) < NWR) g_wr[slot(h)] = 0;
    if (!g_nsec && !g_nview) return;
    lk();
    for (i = 0; i < NSEC; i++) {
        if (g_sec[i].sec == h) { g_sec[i].sec = NULL; g_sec[i].file = NULL; g_nsec--; }
        else if (g_sec[i].sec && g_sec[i].file == h) g_sec[i].file = NULL;      /* its file is gone: later views are Win98's */
    }
    for (i = 0; i < NVIEW; i++) if (g_view[i].base && g_view[i].file == h) g_view[i].file = NULL;   /* a snapshot from now on */
    ulk();
}

/* FlushViewOfFile (build 24). SQLite's winSync calls FlushViewOfFile(view, 0) after every commit when the database
 * is memory-mapped and treats failure as SQLITE_IOERR_MMAP ("disk I/O error"). Win98 refuses it for our private
 * views (plain memory) and for KEXALIAS addresses. A private view never holds unwritten data (every write went
 * through WriteFile), so flushing it is a no-op; an alias is flushed through the real view. */
LPVOID kex_alias_real(LPCVOID a);                         /* shm_ext.c */
BOOL KEXAPI kex_FlushViewOfFile(LPCVOID a, SIZE_T n)
{
    int i; BOOL mine = FALSE; LPVOID real;
    if (g_nview && a) {
        lk();
        for (i = 0; i < NVIEW; i++)
            if (g_view[i].base && (const BYTE *)a >= g_view[i].base && (const BYTE *)a < g_view[i].base + g_view[i].size) { mine = TRUE; break; }
        ulk();
        if (mine) return TRUE;
    }
    if ((real = kex_alias_real(a)) != NULL) a = real;
    if (FlushViewOfFile(a, n)) return TRUE;
    { static LONG c; DWORD le = GetLastError();
      if (InterlockedIncrement(&c) <= 20) kex_trace("FlushViewOfFile failed", (DWORD)(ULONG_PTR)a, (DWORD)n, le, 0);
      SetLastError(le); }
    return FALSE;
}

/* SetEndOfFile (build 24). With a mapping of the file open, NT refuses with ERROR_USER_MAPPED_FILE, which SQLite's
 * winTruncate expects and ignores (it truncates later). Win98 refuses with its own error code, which SQLite turns
 * into SQLITE_IOERR_TRUNCATE. For files that have one of our read-only mappings, report NT's code. */
BOOL KEXAPI kex_SetEndOfFile(HANDLE h)
{
    int i; BOOL mapped = FALSE; DWORD le;
    { void kex_zero_to_pos(HANDLE h); kex_zero_to_pos(h); }   /* build 92: growing = zeros, as on NT */
    if (SetEndOfFile(h)) return TRUE;
    le = GetLastError();
    if (le == ERROR_LOCK_VIOLATION) {                           /* build 132: locks of this process's other handles */
        BOOL kex_lockfile_eof_retry(HANDLE h);                  /* lockfile_ext.c */
        if (kex_lockfile_eof_retry(h)) return TRUE;
        le = GetLastError();
    }
    if (g_nsec) {
        lk();
        for (i = 0; i < NSEC; i++) if (g_sec[i].sec && g_sec[i].file == h) { mapped = TRUE; break; }
        ulk();
    }
    { static LONG c; if (InterlockedIncrement(&c) <= 20) kex_trace("SetEndOfFile failed (handle, error, mapped)", (DWORD)(ULONG_PTR)h, le, mapped, 0); }
    SetLastError(mapped ? 1224 /* ERROR_USER_MAPPED_FILE */ : le);
    return FALSE;
}
