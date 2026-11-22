/*
 * shm_ext.c - CreateFileMappingA/W with NT semantics on Windows 98 SE (KernelEx-NG).
 *
 * Chromium's shared-memory code (base/memory/platform_shared_memory_region_win.cc) does
 *   CreateFileMapping(INVALID_HANDLE_VALUE, &sa_with_empty_dacl, PAGE_READWRITE, 0, size, NULL);
 *   DuplicateHandle(... FILE_MAP_READ | FILE_MAP_WRITE | SECTION_QUERY ...); CloseHandle(original);
 *   if (GetLastError() == ERROR_ALREADY_EXISTS) fail;
 * On NT a successful CreateFileMapping leaves the last error at ERROR_ALREADY_EXISTS for an existing
 * named object and at ERROR_SUCCESS otherwise. Win98's KERNEL32 does not reset it, so any stale value
 * (183 from an earlier CreateDirectory, say) made Chromium's crash reporter CHECK-fail.
 * Also handled here (documented NT-only inputs Win98 does not understand):
 *   - security descriptors: dropped (Win98 has no object security), bInheritHandle kept;
 *   - PAGE_EXECUTE_* protections -> the matching non-execute protection;
 *   - SEC_LARGE_PAGES / SEC_WRITECOMBINE / SEC_IMAGE_NO_EXECUTE (and other unknown high bits) dropped;
 *   - "Local\" / "Global\" namespace prefixes stripped (Win98 has one namespace, and '\' is not
 *     allowed in its object names).
 * kexnt's own import of CreateFileMappingA is the native Win98 one (as LoadLibraryExA in loader_ext.c).
 */
#include "kexnt_common.h"
#include <string.h>


#define K_SECTION_ALL_FWD 0x000F001FUL
static void sech_set(HANDLE h, DWORD access);
static volatile LONG g_n_create, g_n_map, g_n_unmap, g_n_unmap_fail, g_n_noslot, g_n_alias_fail;
int kex_trace_enabled(void);   /* crashlog_ext.c: the section census / view call chains cost time - TRACEON only (build 39c) */
static void sec_created(HANDLE h, DWORD size, DWORD ebp);
static void sec_dup(HANDLE from, HANDLE to);
static void sec_mapped(HANDLE h, void *view, DWORD off);
static DWORD fix_protect(DWORD f)
{
    DWORD page = f & 0xFF, sec = f & 0xFFFFFF00UL;
    switch (page) {
    case PAGE_EXECUTE_READ:      page = PAGE_READONLY;  break;
    case PAGE_EXECUTE_READWRITE: page = PAGE_READWRITE; break;
    case PAGE_EXECUTE_WRITECOPY: page = PAGE_WRITECOPY; break;
    }
    sec &= (SEC_COMMIT | SEC_RESERVE | SEC_IMAGE | SEC_NOCACHE);
    /* SEC_IMAGE_NO_EXECUTE (0x11000000) becomes plain SEC_IMAGE through the mask above */
    return page | sec;
}

static BOOL prefix_ci(const char *s, const char *pre)
{
    for (; *pre; s++, pre++) {
        char a = *s, b = *pre;
        if (a >= 'a' && a <= 'z') a -= 32;
        if (b >= 'a' && b <= 'z') b -= 32;
        if (a != b) return FALSE;
    }
    return TRUE;
}

static const char *strip_ns(const char *n)
{
    if (!n) return NULL;
    if (prefix_ci(n, "Local\\")) return n + 6;
    if (prefix_ci(n, "Global\\")) return n + 7;
    if (prefix_ci(n, "Session\\")) {                          /* Session\<n>\name */
        const char *p = n + 8;
        while (*p && *p != '\\') p++;
        if (*p) return p + 1;
    }
    return n;
}

/* Build 85 log (renderer killed by Chrome's "out of memory" while decoding an image): the shared arena
 * (80000000-BFFFFFFF, 1 GB for ALL programs together - every Win98 file mapping lives there) had 119 MB free,
 * largest hole 79 MB. In it, once per Chrome process: a 24856 KB and a 10440 KB mapping = resources.pak
 * (25451408 bytes) and icudtl.dat (10688512 bytes). Windows 98 makes a new mapping object - and a new copy in
 * the shared arena - for every unnamed CreateFileMapping, even of the same file; NT shares the file's pages.
 * Here a read-only mapping of a big file opened read-only gets a name made from the file's path, size and
 * last-write time, so every process that maps the same unchanged file gets the SAME mapping object (Windows 98
 * then maps it at one address for all of them). Returns the name in buf, or NULL to keep the call unchanged. */
BOOL kex_fpath_get(HANDLE h, char *buf, DWORD cb);   /* fpath_ext.c */
int kex_fview_access(HANDLE h);                      /* fview_ext.c: 2 = opened read-only */
static LPCSTR ro_share_name(HANDLE file, DWORD protect, DWORD size_hi, DWORD size_lo, char *buf)
{
    char path[MAX_PATH + 8]; DWORD hi = 0, lo, hash = 2166136261u, i; FILETIME wt;
    BY_HANDLE_FILE_INFORMATION fi;
    if (file == INVALID_HANDLE_VALUE || !file || (protect & 0xFF) != PAGE_READONLY || size_hi) return NULL;
    if (kex_fview_access(file) != 2) return NULL;                    /* only handles we saw opened read-only */
    lo = GetFileSize(file, &hi);
    if (lo == 0xFFFFFFFF || hi || lo < (1u << 20) || (size_lo && size_lo != lo)) return NULL;
    if (!GetFileInformationByHandle(file, &fi)) return NULL;
    wt = fi.ftLastWriteTime;
    if (!kex_fpath_get(file, path, sizeof(path)) || !path[0]) return NULL;
    {   /* build 87: only the program's own files (resources.pak, icudtl.dat, chrome.dll - never written while it
         * runs), not profile files that are rewritten (a stale shared mapping would show old contents) */
        char exe[MAX_PATH]; int k, sl = -1;
        if (!GetModuleFileNameA(NULL, exe, MAX_PATH)) return NULL;
        for (k = 0; exe[k]; k++) if (exe[k] == '\\') sl = k;
        if (sl <= 0 || CompareStringA(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, path, sl + 1, exe, sl + 1) != CSTR_EQUAL) return NULL;
    }
    for (i = 0; path[i]; i++) { BYTE c = (BYTE)path[i]; if (c >= 'a' && c <= 'z') c -= 32; if (c == '/') c = '\\'; hash = (hash ^ c) * 16777619u; }
    {   static const char hx[] = "0123456789ABCDEF"; DWORD v[4]; int k, b; char *o = buf;
        v[0] = hash; v[1] = lo; v[2] = wt.dwHighDateTime; v[3] = wt.dwLowDateTime;
        lstrcpyA(o, "KexNG_RO_"); o += 9;
        for (k = 0; k < 4; k++) { for (b = 28; b >= 0; b -= 4) *o++ = hx[(v[k] >> b) & 15]; if (k < 2) *o++ = '_'; }
        *o = 0;
    }
    return buf;
}

HANDLE KEXAPI kex_CreateFileMappingA(HANDLE file, LPSECURITY_ATTRIBUTES sa, DWORD protect,
                                     DWORD size_hi, DWORD size_lo, LPCSTR name)
{
    SECURITY_ATTRIBUTES s98, *ps = NULL; HANDLE h; DWORD e; char shared[64]; LPCSTR use = strip_ns(name);
    if (sa) { s98.nLength = sizeof(s98); s98.lpSecurityDescriptor = NULL; s98.bInheritHandle = sa->bInheritHandle; ps = &s98; }
    if (!name && ro_share_name(file, protect, size_hi, size_lo, shared)) use = shared;
    /* build 92: a mapping bigger than its file grows the file - NT fills the new part with zeros, 98 does not */
    if (file && file != INVALID_HANDLE_VALUE && (size_lo || size_hi) &&
        ((protect & 0xFF) == PAGE_READWRITE || (protect & 0xFF) == PAGE_EXECUTE_READWRITE)) {
        void kex_fpos_lock(HANDLE h); void kex_fpos_unlock(HANDLE h); int kex_zero_gap(HANDLE h, DWORD lo, DWORD hi);
        LONG ohi = 0; DWORD olo;
        kex_fpos_lock(file);
        olo = SetFilePointer(file, 0, &ohi, FILE_CURRENT);
        if (kex_zero_gap(file, size_lo, size_hi)) SetFilePointer(file, (LONG)olo, &ohi, FILE_BEGIN);
        kex_fpos_unlock(file);
    }
    SetLastError(ERROR_SUCCESS);
    h = CreateFileMappingA(file, ps, fix_protect(protect), size_hi, size_lo, use);
    if (use == shared) {
        DWORD le = GetLastError();
        static LONG n; if (InterlockedIncrement(&n) <= 8) {
            void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
            kex_crashnote("read-only file mapping shared between processes (handle, file size, 1 = reused another process's mapping, error)",
                          (DWORD)(ULONG_PTR)h, GetFileSize(file, NULL), le == ERROR_ALREADY_EXISTS ? 1 : 0, h ? 0 : le);
            {   /* build 121: which file (a 288 MB one could not be mapped in build 120) */
                BOOL kex_fpath_get(HANDLE h, char *buf, DWORD cb); void kex_crashlog_text(const char *s); char t[MAX_PATH + 16];
                lstrcpyA(t, "    file: "); if (!kex_fpath_get(file, t + 10, MAX_PATH)) lstrcpyA(t + 10, "(path unknown)");
                kex_crashlog_text(t);
            }
        }
        if (!h) { SetLastError(ERROR_SUCCESS); h = CreateFileMappingA(file, ps, fix_protect(protect), size_hi, size_lo, NULL); }
        else SetLastError(ERROR_SUCCESS);           /* the caller asked for an unnamed mapping: never "already exists" */
    }
    e = GetLastError();
    if (h) {
        void kex_fview_section(HANDLE sec, HANDLE file, DWORD protect);   /* fview_ext.c */
        int kex_imgsec_created(HANDLE sec, HANDLE file, DWORD protect);  /* imgsec_ext.c: SEC_IMAGE -> image layout views */
        if (kex_imgsec_created(h, file, protect) < 0) { CloseHandle(h); SetLastError(ERROR_BAD_EXE_FORMAT); return NULL; }
        sech_set(h, K_SECTION_ALL_FWD);
        if (file == INVALID_HANDLE_VALUE) {
            InterlockedIncrement((LONG *)&g_n_create);
            if (e != ERROR_ALREADY_EXISTS) sec_created(h, size_lo, (DWORD)(ULONG_PTR)__builtin_frame_address(0));
        }
        if (!name) kex_fview_section(h, file, protect);
        SetLastError(e == ERROR_ALREADY_EXISTS ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS);
    }
    else {
        /* build 119: Discord's renderer died of "out of memory" (e0000008, 2.7 MB asked) with no failed VirtualAlloc -
         * a section that could not be made is the other way Chromium's shared memory says so */
        static LONG nf; void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
        if (InterlockedIncrement(&nf) <= 30)
            kex_crashnote("CreateFileMapping FAILED (size, error, file 1 = page file, caller)", size_lo, e,
                          file == INVALID_HANDLE_VALUE ? 1 : 0, (DWORD)(ULONG_PTR)__builtin_return_address(0));
        if (e == ERROR_SUCCESS) SetLastError(ERROR_INVALID_PARAMETER);
    }
    return h;
}

HANDLE KEXAPI kex_CreateFileMappingW(HANDLE file, LPSECURITY_ATTRIBUTES sa, DWORD protect,
                                     DWORD size_hi, DWORD size_lo, LPCWSTR name)
{
    char buf[MAX_PATH * 2], *a = NULL;
    if (name) {
        if (!WideCharToMultiByte(CP_ACP, 0, name, -1, buf, sizeof(buf), NULL, NULL)) {
            SetLastError(ERROR_FILENAME_EXCED_RANGE); return NULL;
        }
        a = buf;
    }
    return kex_CreateFileMappingA(file, sa, protect, size_hi, size_lo, a);
}

/* ---------------------------------------------------------------- section handle access (2026-11-02)
 * Windows 98 grants every handle full access and DuplicateHandle never refuses a wider access mask. Chromium
 * checks that a read-only shared memory region really is read-only: it tries
 * DuplicateHandle(..., FILE_MAP_WRITE, ...) and expects that to fail for a handle it duplicated with
 * FILE_MAP_READ | SECTION_QUERY (base::subtle::PlatformSharedMemoryRegion, CheckPlatformHandlePermissions...);
 * when it succeeds, Take() fails and a CHECK on the result stops the browser (expected_internal.h:310,
 * 2026-11-02). kexnt remembers the access of each section handle of this process (CreateFileMapping: all;
 * OpenFileMapping: the requested access; DuplicateHandle: requested or same) and refuses a duplicate that
 * asks for specific rights the source does not have, as NT does. Handles kexnt has not seen are untouched. */
#define K_SECTION_QUERY       0x0001
#define K_SECTION_MAP_WRITE   0x0002
#define K_SECTION_MAP_READ    0x0004
#define K_SECTION_MAP_EXECUTE 0x0008
#define K_SECTION_ALL         0x000F001FUL
typedef struct { HANDLE h; DWORD access; } KSECH;
static KSECH g_sech[512];
static CRITICAL_SECTION g_sech_cs; static volatile LONG g_sech_init;
static void sech_lock(void)
{
    if (InterlockedCompareExchange(&g_sech_init, 1, 0) == 0) { InitializeCriticalSection(&g_sech_cs); g_sech_init = 2; }
    while (g_sech_init != 2) Sleep(1);
    EnterCriticalSection(&g_sech_cs);
}
static void sech_set(HANDLE h, DWORD access)
{
    int i, free_slot = -1;
    if (!h) return;
    sech_lock();
    for (i = 0; i < 512; i++) {
        if (g_sech[i].h == h) { g_sech[i].access = access; LeaveCriticalSection(&g_sech_cs); return; }
        if (!g_sech[i].h && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) { g_sech[free_slot].h = h; g_sech[free_slot].access = access; }
    LeaveCriticalSection(&g_sech_cs);
}
static BOOL sech_get(HANDLE h, DWORD *access)
{
    int i; BOOL r = FALSE;
    if (!g_sech_init || !h) return FALSE;
    sech_lock();
    for (i = 0; i < 512; i++) if (g_sech[i].h == h) { *access = g_sech[i].access; r = TRUE; break; }
    LeaveCriticalSection(&g_sech_cs);
    return r;
}
/* A section handle this process did not create, open or duplicate itself (inherited from the parent, as
 * Chromium's children receive every region): Windows 98 keeps the access the handle was made with in its handle
 * table entry, which inheritance copies. Use that when it looks like a FILE_MAP_* mask, else `dflt`. (build 14) */
BOOL kex_handle_facts(HANDLE h, BYTE *type, DWORD *access, BOOL *inherit);   /* procspawn_ext.c */
static BOOL table_section_access(HANDLE h, DWORD *access)
{
    BYTE t = 0; DWORD a = 0;
    if (!kex_handle_facts(h, &t, &a, NULL) || t != 0xD) return FALSE;
    a &= 0xFFFF;
    if (!(a & (FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_COPY))) return FALSE;   /* not an access mask we can read */
    *access = a;
    return TRUE;
}
DWORD kex_section_access(HANDLE h, DWORD dflt)    /* chrome_ext.c kex_NtQueryObject */
{
    DWORD a;
    if (sech_get(h, &a)) return a;
    if (table_section_access(h, &a)) return a;
    return dflt;
}
static void sec_closed_locked(HANDLE h);
void kex_section_forget(HANDLE h)                 /* sec_ext.c kex_CloseHandle */
{
    int i;
    if (!g_sech_init || !h) return;
    sech_lock();
    sec_closed_locked(h);
    for (i = 0; i < 512; i++) if (g_sech[i].h == h) { g_sech[i].h = NULL; break; }
    LeaveCriticalSection(&g_sech_cs);
}
static DWORD section_rights(DWORD a)               /* generic -> specific rights (section generic mapping) */
{
    if (a & GENERIC_ALL) a |= K_SECTION_ALL;
    if (a & GENERIC_READ) a |= STANDARD_RIGHTS_READ | K_SECTION_QUERY | K_SECTION_MAP_READ;
    if (a & GENERIC_WRITE) a |= STANDARD_RIGHTS_WRITE | K_SECTION_MAP_WRITE;
    if (a & GENERIC_EXECUTE) a |= STANDARD_RIGHTS_EXECUTE | K_SECTION_MAP_EXECUTE;
    if ((a & 0xFFFF) == 0x001F) a |= K_SECTION_ALL;    /* FILE_MAP_ALL_ACCESS */
    return a & ~(GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE);
}
static BOOL is_self_process(HANDLE p)
{
    return p == GetCurrentProcess() || p == (HANDLE)(LONG_PTR)-1;
}

HANDLE KEXAPI kex_OpenFileMappingA(DWORD access, BOOL inherit, LPCSTR name)
{
    HANDLE h = OpenFileMappingA(access, inherit, strip_ns(name));
    if (h) sech_set(h, section_rights(access));
    return h;
}
HANDLE KEXAPI kex_OpenFileMappingW(DWORD access, BOOL inherit, LPCWSTR name)
{
    char buf[MAX_PATH * 2];
    if (!name) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    if (!WideCharToMultiByte(CP_ACP, 0, name, -1, buf, sizeof(buf), NULL, NULL)) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return NULL; }
    return kex_OpenFileMappingA(access, inherit, buf);
}

FARPROC kex_prev_impl(const char *dll, const char *name);   /* gdiguard_ext.c */
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
BOOL KEXAPI kex_DuplicateHandle(HANDLE sp, HANDLE h, HANDLE tp, LPHANDLE out, DWORD access, BOOL inherit, DWORD opts)
{
    typedef BOOL (WINAPI *T_DH)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
    static T_DH dh;
    DWORD granted = 0, want; BOOL known, r; BOOL fdisk = FALSE; char fdisk_path[MAX_PATH];
    if (!dh) dh = (T_DH)(void *)kex_prev_impl("KERNEL32.DLL", "DuplicateHandle");
    if (!dh) dh = (T_DH)(void *)DuplicateHandle;
    if (h == (HANDLE)(ULONG_PTR)0xCAFE) {   /* build 131: kexnt's token placeholder (nttoken_ext.c / KernelEx's token
                                              * stubs) - its copy is the placeholder again (Chromium sandbox: RestrictedToken) */
        if (!out || IsBadWritePtr(out, sizeof(*out))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        *out = h;
        return TRUE;
    }
    {   /* build 94: a handle operation inside a process that has already ended crashes Windows 98's KERNEL32 in the
         * CALLER (its environment block is gone). NT refuses it: the dead process has no handle table any more. */
        int kex_process_alive(HANDLE ph);
        int sa = is_self_process(sp) ? 1 : kex_process_alive(sp);
        int ta = (!tp || is_self_process(tp)) ? 1 : kex_process_alive(tp);
        if (sa == 0 || ta == 0) {
            static LONG k; if (InterlockedIncrement(&k) <= 20)
                kex_crashnote("DuplicateHandle with a process that has ended: refused as on NT (handle, options, source alive, target alive)",
                              (DWORD)(ULONG_PTR)h, opts, (DWORD)sa, (DWORD)ta);
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    known = is_self_process(sp) && (sech_get(h, &granted) || table_section_access(h, &granted));
    want = (opts & DUPLICATE_SAME_ACCESS) ? granted : section_rights(access);
    if (known && !(opts & DUPLICATE_SAME_ACCESS) && ((want & 0xFFFF) & ~(granted & 0xFFFF))) {
        if (opts & DUPLICATE_CLOSE_SOURCE) { kex_section_forget(h); CloseHandle(h); }   /* NT closes it anyway */
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    {   /* build 99: which disk file goes to another process (looked at before a DUPLICATE_CLOSE_SOURCE closes it) */
        BOOL kex_fpath_get(HANDLE h, char *buf, DWORD cb); DWORD le0 = GetLastError();
        fdisk = h && tp && is_self_process(sp) && !is_self_process(tp) && GetFileType(h) == FILE_TYPE_DISK;
        if (fdisk && !kex_fpath_get(h, fdisk_path, MAX_PATH)) lstrcpyA(fdisk_path, "(path unknown)");
        SetLastError(le0);
    }
    {   /* build 82: pipe ends handed to other processes (Chromium/ipcz introductions) - with the outcome */
        BOOL kex_pipe_end_info(HANDLE h, char *out, int cb, int *server); char nm[48]; int srv = 0;
        BOOL pe = is_self_process(sp) && !is_self_process(tp) && kex_pipe_end_info(h, nm, sizeof(nm), &srv);
        r = dh(sp, h, tp, out, access, inherit, opts);
        if (pe || (!r && (!is_self_process(tp) || !is_self_process(sp)))) {
            static LONG k; char t[200]; DWORD le = GetLastError();
            if (InterlockedIncrement(&k) <= 60) {
                lstrcpyA(t, pe ? (srv ? "pipe SERVER end duplicated to another process (ok, error, options, target process) " : "pipe client end duplicated to another process (ok, error, options, target process) ")
                              : "DuplicateHandle between processes FAILED (ok, error, options, handle) ");
                if (pe) lstrcatA(t, nm);
                {   DWORD kex_pid_of(HANDLE ph);    /* build 87: which process got the end */
                    kex_crashnote(t, (DWORD)r, r ? 0 : le, opts, pe ? kex_pid_of(tp) : (DWORD)(ULONG_PTR)h); }
            }
            SetLastError(le);
        }
    }
    if (r && fdisk) {
        /* build 99: a disk file handed to another process shares ONE file pointer with it on Windows 98 (as on NT);
         * kexnt's seek+read locks are per process - note who gets which file so a cross-process race can be seen */
        static LONG k; DWORD le = GetLastError();
        if (InterlockedIncrement(&k) <= 40) {
            void kex_crashlog_text(const char *s);
            DWORD kex_pid_of(HANDLE ph); char t[MAX_PATH + 16];
            kex_crashnote("disk file handle duplicated to another process (handle, target process, options, new handle)",
                          (DWORD)(ULONG_PTR)h, kex_pid_of(tp), opts, out ? (DWORD)(ULONG_PTR)*out : 0);
            lstrcpyA(t, "    file: "); lstrcpyA(t + 10, fdisk_path);
            kex_crashlog_text(t);
        }
        SetLastError(le);
    }
    if (r && out && is_self_process(sp) && is_self_process(tp)) {   /* build 66: file rights travel with the copy */
        void kex_fview_dup(HANDLE src, HANDLE dst, BOOL same, DWORD access);
        kex_fview_dup(h, *out, (opts & DUPLICATE_SAME_ACCESS) != 0, access);
    }
    if (r && out && is_self_process(sp) && is_self_process(tp)) sec_dup(h, *out);   /* before the source is forgotten */
    if (r && (opts & DUPLICATE_CLOSE_SOURCE) && is_self_process(sp) && !known) kex_section_forget(h);
    if (r && known) {
        if (opts & DUPLICATE_CLOSE_SOURCE) kex_section_forget(h);
        if (out && is_self_process(tp)) sech_set(*out, want);
    }

    return r;
}

/* ---------------------------------------------------------------- view bookkeeping (diagnostics, 2026-11-02)
 * Windows 98 maps every view of a section into the shared arena at ONE address per section: mapping the same
 * section twice in a process returns the same address both times (NT returns two different views). Chromium in
 * --single-process mode maps regions twice (browser and renderer side) and its SharedMemoryTracker, keyed by
 * the view address, then CHECK-fails when the second mapping is released (shared_memory_tracker.cc:62).
 * kexnt counts live views per address and traces a duplicate so such cases show up in KEXTRACE. */
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);   /* crashlog_ext.c */
typedef struct { void *addr; LONG count; LONG exposed; DWORD bytes; DWORD st[6]; } KVIEW;   /* exposed: handed out at its real address */
#define NVIEWS 1024
static KVIEW g_views[NVIEWS];
/* build 37: shared-arena accounting for the out-of-memory report (crashlog_ext.c mem_summary) */
void kex_shm_note_unmap(BOOL ok) { InterlockedIncrement((LONG *)&g_n_unmap); if (!ok) InterlockedIncrement((LONG *)&g_n_unmap_fail); }
static void view_stack(DWORD ebp, DWORD st[6])
{
    int k; DWORD lim = ebp + 0x100000;
    for (k = 0; k < 6; k++) st[k] = 0;
    for (k = 0; k < 6 && ebp >= 0x10000 && ebp < lim && !IsBadReadPtr((void *)ebp, 8); k++) {
        DWORD next = ((DWORD *)ebp)[0];
        st[k] = ((DWORD *)ebp)[1];
        if (next <= ebp) break;
        ebp = next;
    }
}
void kex_crashlog_dupview(void *a, LONG count, DWORD h, DWORD off, DWORD n, DWORD ebp);   /* crashlog_ext.c */
static LONG view_add(void *a, DWORD h, DWORD off, DWORD n, DWORD ebp)
{
    int i, free_slot = -1;
    if (!a) return 0;
    sech_lock();
    for (i = 0; i < NVIEWS; i++) {
        if (g_views[i].addr == a) {
            LONG c = ++g_views[i].count;
            LeaveCriticalSection(&g_sech_cs);
            kex_trace("MapViewOfFile: SAME address as a live view of this process (9x maps a section once)", (DWORD)(ULONG_PTR)a, (DWORD)c, h, off);
            kex_crashlog_dupview(a, c, h, off, n, ebp);
            return c;
        }
        if (!g_views[i].addr && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) {
        g_views[free_slot].addr = a; g_views[free_slot].count = 1; g_views[free_slot].exposed = 0;
        g_views[free_slot].bytes = n;
        if (kex_trace_enabled()) {
            MEMORY_BASIC_INFORMATION m;
            if (VirtualQuery(a, &m, sizeof(m)) && m.RegionSize) g_views[free_slot].bytes = (DWORD)m.RegionSize;
            view_stack(ebp, g_views[free_slot].st);
        } else ZeroMemory(g_views[free_slot].st, sizeof(g_views[free_slot].st));
    } else InterlockedIncrement((LONG *)&g_n_noslot);
    LeaveCriticalSection(&g_sech_cs);
    return 1;
}
/* Returns the number of views of this address the process still holds after this release (0: really unmap).
 * Windows 98 has one view per section and process: unmapping the first of two "views" would pull the memory from
 * under the other user, so kex_UnmapViewOfFile only unmaps for the last one. */
LONG kex_view_release2(LPCVOID a, BOOL via_alias)
{
    int i; LONG left = 0;
    if (!g_sech_init || !a) return 0;
    sech_lock();
    for (i = 0; i < NVIEWS; i++) if (g_views[i].addr == a) {
        if (!via_alias) g_views[i].exposed = 0;            /* the program gave back the real address */
        if ((left = --g_views[i].count) <= 0) { g_views[i].addr = NULL; g_views[i].exposed = 0; left = 0; }
        break;
    }
    LeaveCriticalSection(&g_sech_cs);
    return left;
}
LONG kex_view_release(LPCVOID a) { return kex_view_release2(a, TRUE); }
/* build 37: does Windows 98 count MapViewOfFile calls per process? The census showed 401 MB of sections that
 * Chromium had closed AND unmapped still occupying the shared arena - exactly the sections it maps twice (Mojo/ipcz
 * buffers, discardable segments, media frames). kexnt called the real UnmapViewOfFile once per address, i.e. once
 * for two real MapViewOfFile calls. Probe once: section, two views, close the handle, unmap once - if the memory is
 * still there, Windows counts views and every real map needs its own real unmap. 1 = counts, 0 = does not. */
static volatile LONG g_view_refcount = -1;
static FARPROC k32_export(const char *name)        /* KERNEL32's own export, from its export table (no hook between) */
{
    BYTE *b = (BYTE *)GetModuleHandleA("KERNEL32.DLL");
    IMAGE_NT_HEADERS *nt; IMAGE_EXPORT_DIRECTORY *ex; DWORD *names, *funcs; WORD *ords; DWORD i;
    if (!b || ((IMAGE_DOS_HEADER *)b)->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    ex = (IMAGE_EXPORT_DIRECTORY *)(b + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names = (DWORD *)(b + ex->AddressOfNames); funcs = (DWORD *)(b + ex->AddressOfFunctions); ords = (WORD *)(b + ex->AddressOfNameOrdinals);
    for (i = 0; i < ex->NumberOfNames; i++)
        if (!strcmp((const char *)(b + names[i]), name)) return (FARPROC)(b + funcs[ords[i]]);
    return NULL;
}
BOOL kex_real_unmap(LPCVOID a)                     /* Windows' own UnmapViewOfFile (build 38c) */
{
    typedef BOOL (WINAPI *T_UV)(LPCVOID); static T_UV f;
    if (!f) f = (T_UV)(void *)k32_export("UnmapViewOfFile");
    return f ? f(a) : UnmapViewOfFile(a);
}
int kex_shm_refcounted(void)
{
    LONG v = g_view_refcount;
    if (v < 0) {   /* build 38c: Windows' own exports - kexnt's imports of these resolve to the kexnt versions (a
                    * second map got a KEXALIAS alias, so the probe always said 0) */
        typedef HANDLE (WINAPI *T_CFM)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
        typedef LPVOID (WINAPI *T_MV)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
        typedef BOOL (WINAPI *T_UV)(LPCVOID);
        typedef BOOL (WINAPI *T_CH)(HANDLE);
        T_CFM cfm = (T_CFM)(void *)k32_export("CreateFileMappingA");
        T_MV mv = (T_MV)(void *)k32_export("MapViewOfFile");
        T_UV uv = (T_UV)(void *)k32_export("UnmapViewOfFile");
        T_CH ch = (T_CH)(void *)k32_export("CloseHandle");
        HANDLE s = cfm && mv && uv && ch ? cfm(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x2000, NULL) : NULL;
        BYTE *a = s ? (BYTE *)mv(s, FILE_MAP_WRITE, 0, 0, 0) : NULL, *b = NULL;
        MEMORY_BASIC_INFORMATION m;
        v = 0;
        if (a) {
            b = (BYTE *)mv(s, FILE_MAP_WRITE, 0, 0, 0);
            ch(s); s = NULL;
            uv(a);
            if (b == a && VirtualQuery(a, &m, sizeof(m)) == sizeof(m) && m.State == MEM_COMMIT) { v = 1; uv(a); }
            else if (b && b != a) uv(b);
        }
        if (s) ch(s);
        g_view_refcount = v;
        kex_trace("UnmapViewOfFile: Windows counts views per process (1) / not (0)", (DWORD)v, (DWORD)(ULONG_PTR)a, (DWORD)(ULONG_PTR)b, 0);
    }
    return (int)v;
}   /* internal undo: exposure unchanged */
/* build 32: Chromium unmaps AlignDown(view, 64 KB) (shared_memory_mapping.cc). Instead of giving every Windows 98
 * view that is not 64 KB aligned a KEXALIAS alias (which locks the region's RAM for its whole life - on YouTube the
 * VxD ran out and a second view came back at the same address: shared_memory_tracker.cc:62), the unmap side now
 * finds the real view from that aligned address, as long as only one live view lies in that 64 KB window. */
#define NALIAS 1024
typedef struct { BYTE *alias; BYTE *src; DWORD bytes; void *view; DWORD reserved; } KALIAS;
static KALIAS g_alias[NALIAS];
static int window_views(DWORD win, void *except)        /* lock held: exposed views whose 64 KB window is `win` */
{
    int i, n = 0;
    for (i = 0; i < NVIEWS; i++)
        if (g_views[i].addr && g_views[i].exposed && g_views[i].addr != except &&
            ((DWORD)(ULONG_PTR)g_views[i].addr & ~0xFFFFUL) == win) n++;
    return n;
}
/* build 33: only views handed out at their real address ("exposed") count. An address the program gives back is
 * either such a view itself, or the AlignDown of exactly one of them - map time makes sure no 64 KB window ever
 * holds two exposed views (build 32 unmapped the wrong one: a view at W and another at W+5000h, Chromium gave
 * back W for the second -> the first was pulled from under its user, crash reading a3d902f8). */
LPCVOID kex_view_from_aligned(LPCVOID a)                /* mem_ext.c kex_UnmapViewOfFile */
{
    int i; void *hit = NULL; int n = 0;
    if (!g_sech_init || !a || ((DWORD)(ULONG_PTR)a & 0xFFFF)) return a;
    sech_lock();
    for (i = 0; i < NVIEWS; i++) if (g_views[i].addr == a && g_views[i].exposed) { LeaveCriticalSection(&g_sech_cs); return a; }
    for (i = 0; i < NVIEWS; i++)
        if (g_views[i].addr && g_views[i].exposed && ((DWORD)(ULONG_PTR)g_views[i].addr & ~0xFFFFUL) == (DWORD)(ULONG_PTR)a) { hit = g_views[i].addr; n++; }
    LeaveCriticalSection(&g_sech_cs);
    return n == 1 ? hit : a;
}
/* lock taken here: TRUE if r may be handed out as is (no other exposed view in its 64 KB window); marks it exposed */
static BOOL try_expose(void *r)
{
    int i; BOOL ok;
    if (!g_sech_init) return TRUE;
    sech_lock();
    ok = window_views((DWORD)(ULONG_PTR)r & ~0xFFFFUL, r) == 0;
    if (ok) {                                          /* nor an alias starting in that window (VxD before version 3) */
        int k;
        for (k = 0; k < NALIAS; k++)
            if (g_alias[k].alias && ((DWORD)(ULONG_PTR)g_alias[k].alias & ~0xFFFFUL) == ((DWORD)(ULONG_PTR)r & ~0xFFFFUL)) { ok = FALSE; break; }
    }
    if (ok) for (i = 0; i < NVIEWS; i++) if (g_views[i].addr == r) { g_views[i].exposed = 1; break; }
    LeaveCriticalSection(&g_sech_cs);
    return ok;
}
/* ---------------------------------------------------------------- second views through KEXALIAS.VXD (build 15)
 * Chromium's Mojo/ipcz data pipes map the same region twice in the creating process (ipcz_driver/data_pipe.cc:
 * consumer + producer mapping) and base::SharedMemoryTracker keys mappings by address: with Windows 98's single
 * address per section the browser died at shared_memory_tracker.cc:62 as soon as a WebUI page was served.
 * kexnt's helper VxD (vxd_alias/kexalias.c) gives a second, third ... view its own address: new shared-arena
 * pages pointing at the SAME physical pages (the source pages stay locked while the alias lives), so all views
 * see each other's writes immediately, as on NT. Without the VxD the old behaviour remains (same address). */
static HANDLE g_alias_dev = INVALID_HANDLE_VALUE;
static LONG g_alias_tried;
static HANDLE alias_dev(void)
{
    if (!InterlockedExchange(&g_alias_tried, 1)) {
        char path[MAX_PATH + 8], *slash = NULL; int i; HMODULE me = NULL;
        MEMORY_BASIC_INFORMATION m;
        if (VirtualQuery((LPCVOID)alias_dev, &m, sizeof(m))) me = (HMODULE)m.AllocationBase;
        lstrcpyA(path, "\\\\.\\");
        if (me && GetModuleFileNameA(me, path + 4, MAX_PATH - 20)) {
            for (i = 4; path[i]; i++) if (path[i] == '\\') slash = path + i;
            if (slash) { lstrcpyA(slash + 1, "KEXALIAS.VXD"); g_alias_dev = CreateFileA(path, 0, 0, NULL, 0, 0, NULL); }
        }
        if (g_alias_dev == INVALID_HANDLE_VALUE) g_alias_dev = CreateFileA("\\\\.\\KEXALIAS.VXD", 0, 0, NULL, 0, 0, NULL);
        kex_trace("KEXALIAS.VXD", (DWORD)(ULONG_PTR)g_alias_dev, g_alias_dev == INVALID_HANDLE_VALUE ? GetLastError() : 0, 0, 0);
    }
    return g_alias_dev;
}
/* KEXALIAS.VXD version (IOCTL 3), 0 if unknown */
static DWORD alias_version(void)
{
    static volatile LONG v = -1;
    if (v < 0) {
        DWORD o = 0, got = 0; HANDLE d = alias_dev();
        if (d == INVALID_HANDLE_VALUE || !DeviceIoControl(d, 3, NULL, 0, &o, sizeof(o), &got, NULL)) o = 0;
        InterlockedExchange(&v, (LONG)o);
        kex_trace("KEXALIAS.VXD version", o, 0, 0, 0);
    }
    return (DWORD)v;
}
/* A new address for the view `r` (already counted in g_views), or NULL. */
static void *alias_view(void *r, SIZE_T want)
{
    MEMORY_BASIC_INFORMATION m; DWORD in[2], o[2] = {0, 0}, out, got = 0; BYTE *src; DWORD bytes; int i;
    HANDLE d = alias_dev();
    if (d == INVALID_HANDLE_VALUE || !VirtualQuery(r, &m, sizeof(m)) || !m.AllocationBase) return NULL;
    src = (BYTE *)m.AllocationBase;
    {   /* build 38c: the whole allocation - Windows 98 splits a section's VirtualQuery regions where its pages differ
         * (touched / not yet touched), so one RegionSize can be just 4 KB (kextest: second view sized 4096).
         * build 39: committed pages only - reserved pages cannot be locked, the alias failed.
         * build 41: pages of the view the program asked for that Windows still shows as not committed are read once
         * (Windows commits them on first touch), then counted - kextest got a 24 KB alias of a 32 KB view. Only up to
         * the requested size (whole view: at most 1 MB), so a huge section is never faulted in. */
        BYTE *p = src, *lim = (BYTE *)r + (want ? want : 0x100000);
        bytes = 0;
        while (VirtualQuery(p, &m, sizeof(m)) == sizeof(m) && m.RegionSize && m.AllocationBase == src && m.State != MEM_FREE) {
            if (m.State != MEM_COMMIT) {
                BYTE *e = p + m.RegionSize, *q;
                if (p >= lim) break;
                if (e > lim) e = lim;
                for (q = p; q < e; q += 4096) if (IsBadReadPtr(q, 1)) break;
                if (VirtualQuery(p, &m, sizeof(m)) != sizeof(m) || m.State != MEM_COMMIT || m.AllocationBase != src) break;
                kex_trace("KEXALIAS: touched pages to commit them", (DWORD)(ULONG_PTR)p, (DWORD)m.RegionSize, 0, 0);
            }
            bytes += (DWORD)m.RegionSize; p += m.RegionSize;
        }
        if (!bytes) return NULL;
    }
    in[0] = (DWORD)(ULONG_PTR)src; in[1] = bytes;
    if (!DeviceIoControl(d, 1, in, sizeof(in), o, sizeof(o), &got, NULL) || !(out = o[0]) || !o[1]) {
        kex_trace("KEXALIAS: alias FAILED", in[0], bytes, GetLastError(), 0);
        InterlockedIncrement((LONG *)&g_n_alias_fail);
        { void kex_crashlog_text(const char *s); static LONG once; if (!InterlockedExchange(&once, 1)) kex_crashlog_text("--- KEXALIAS: making a second view FAILED (see KEXTRACE 'KEXALIAS: alias FAILED')"); }
        { void kex_crashlog_memreport(const char *why); kex_crashlog_memreport("first failed second view (shared arena full?)"); }
        return NULL;
    }
    sech_lock();
    for (i = 0; i < NALIAS && g_alias[i].alias; i++) ;
    if (i < NALIAS) { g_alias[i].alias = (BYTE *)(ULONG_PTR)out; g_alias[i].src = src; g_alias[i].bytes = bytes; g_alias[i].view = r; g_alias[i].reserved = o[1]; }
    LeaveCriticalSection(&g_sech_cs);
    if (i >= NALIAS) {                                     /* no room to remember it: undo */
        DWORD un[4]; un[0] = out; un[1] = in[0]; un[2] = bytes; un[3] = o[1];
        DeviceIoControl(d, 2, un, sizeof(un), NULL, 0, &got, NULL);
        return NULL;
    }
    kex_trace("KEXALIAS: second view", (DWORD)(ULONG_PTR)r, out + (DWORD)((BYTE *)r - src), bytes, 0);
    return (BYTE *)(ULONG_PTR)out + ((BYTE *)r - src);
}
/* mem_ext.c kex_UnmapViewOfFile: TRUE when `a` was one of our aliases (it is gone now, *view = the real view to
 * release), FALSE otherwise. */
BOOL kex_alias_release(LPCVOID a, void **view)
{
    int i; KALIAS k; DWORD un[4], got;
    if (!g_sech_init || !a) return FALSE;
    sech_lock();
    for (i = 0; i < NALIAS; i++)
        if (g_alias[i].alias && (BYTE *)a >= g_alias[i].alias && (BYTE *)a < g_alias[i].alias + g_alias[i].bytes) break;
    if (i >= NALIAS) { LeaveCriticalSection(&g_sech_cs); return FALSE; }
    k = g_alias[i]; g_alias[i].alias = NULL;
    LeaveCriticalSection(&g_sech_cs);
    un[0] = (DWORD)(ULONG_PTR)k.alias; un[1] = (DWORD)(ULONG_PTR)k.src; un[2] = k.bytes; un[3] = k.reserved;
    {   /* build 101: pages written only through the alias are "clean" in the section's own page table - once the
         * alias is gone Windows 98 may drop them unsaved and the other process reads zeros (build 100: Discord's
         * scripts reached V8 as zeros). KEXALIAS.VXD 4 re-dirties them through the section's address before it
         * removes the alias and reports how many; an older VxD gets the same done here, for every page. */
        DWORD res[2] = { 0xFFFFFFFF, 0xFFFFFFFF }; static LONG notes; static volatile LONG tot_dirty, tot_fixed;
        if (alias_version() < 4) {
            MEMORY_BASIC_INFORMATION m; DWORD off;
            for (off = 0; off < k.bytes; off += 4096) {
                BYTE *pg = k.src + off;
                if (VirtualQuery(pg, &m, sizeof(m)) == sizeof(m) && m.State == MEM_COMMIT &&
                    ((m.Protect & 0xFF) == PAGE_READWRITE || (m.Protect & 0xFF) == PAGE_EXECUTE_READWRITE))
                    __atomic_fetch_or((volatile LONG *)pg, 0, __ATOMIC_SEQ_CST);
            }
        }
        DeviceIoControl(g_alias_dev, 2, un, sizeof(un), res, sizeof(res), &got, NULL);
        if (res[0] != 0xFFFFFFFF) {
            LONG d = InterlockedExchangeAdd(&tot_dirty, (LONG)res[0]) + (LONG)res[0];
            LONG f = InterlockedExchangeAdd(&tot_fixed, (LONG)res[1]) + (LONG)res[1];
            if (res[1] && InterlockedIncrement(&notes) <= 30) {
                void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
                kex_crashnote("KEXALIAS: second view released - pages written only through it re-marked as changed (alias, pages written, of them unsaved, total unsaved so far)",
                              (DWORD)(ULONG_PTR)k.alias, res[0], res[1], (DWORD)f);
            }
            (void)d;
        }
    }
    *view = k.view;
    return TRUE;
}

/* fview_ext.c kex_FlushViewOfFile: the real Win98 view address behind an alias address (NULL if not an alias). */
LPVOID kex_alias_real(LPCVOID a)
{
    int i; LPVOID r = NULL;
    if (!g_sech_init || !a) return NULL;
    sech_lock();
    for (i = 0; i < NALIAS; i++)
        if (g_alias[i].alias && (BYTE *)a >= g_alias[i].alias && (BYTE *)a < g_alias[i].alias + g_alias[i].bytes) {
            r = g_alias[i].src + ((BYTE *)a - g_alias[i].alias);
            break;
        }
    LeaveCriticalSection(&g_sech_cs);
    return r;
}

/* mem_ext.c kex_VirtualQuery: an address inside one of our aliases is described as a view of its own
 * (AllocationBase = the alias, RegionSize = up to its end, MEM_MAPPED) - Chromium sizes every mapping as
 * RegionSize - (view - AllocationBase) (platform_shared_memory_mapper_win.cc) and CHECKs the result
 * (shared_memory_mapping.cc:48). The VxD's reservation starts below the 64 KB-aligned alias. (build 18) */
BOOL kex_alias_query(LPCVOID a, PMEMORY_BASIC_INFORMATION m)
{
    int i; BOOL r = FALSE;
    if (!g_sech_init || !a || !m) return FALSE;
    sech_lock();
    for (i = 0; i < NALIAS; i++)
        if (g_alias[i].alias && (BYTE *)a >= g_alias[i].alias && (BYTE *)a < g_alias[i].alias + g_alias[i].bytes) {
            BYTE *page = (BYTE *)((ULONG_PTR)a & ~(ULONG_PTR)0xFFF);
            m->BaseAddress = page;
            m->AllocationBase = g_alias[i].alias;
            m->AllocationProtect = PAGE_READWRITE;
            m->RegionSize = (SIZE_T)(g_alias[i].alias + ((g_alias[i].bytes + 0xFFF) & ~0xFFFUL) - page);
            m->State = MEM_COMMIT;
            m->Protect = PAGE_READWRITE;
            m->Type = MEM_MAPPED;
            r = TRUE;
            break;
        }
    LeaveCriticalSection(&g_sech_cs);
    return r;
}

LPVOID KEXAPI kex_MapViewOfFileEx(HANDLE h, DWORD access, DWORD hi, DWORD lo, SIZE_T n, LPVOID base)
{
    typedef LPVOID (WINAPI *T_MVX)(HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID);
    static T_MVX f;
    LPVOID r, a;
    if (!f) f = (T_MVX)(void *)kex_prev_impl("KERNEL32.DLL", "MapViewOfFileEx");
    if (!f) f = (T_MVX)(void *)MapViewOfFileEx;
    {   LPVOID kex_imgsec_map(HANDLE sec, DWORD access, DWORD hi, DWORD lo, SIZE_T n, LPVOID base, BOOL *ours);   /* imgsec_ext.c */
        BOOL ours; r = kex_imgsec_map(h, access, hi, lo, n, base, &ours); if (ours) return r; }
    {   /* fview_ext.c: read-only view of a file that is written with WriteFile -> a private, kept-current copy */
        LPVOID kex_fview_map(HANDLE sec, DWORD access, DWORD hi, DWORD lo, SIZE_T n);
        if (!base && (r = kex_fview_map(h, access, hi, lo, n)) != NULL) return r;
    }
    r = f(h, access, hi, lo, n, base);
    kex_trace("MapViewOfFile", (DWORD)(ULONG_PTR)h, lo, (DWORD)n, (DWORD)(ULONG_PTR)r);   /* handle, offset, size, view */
    if (!r) {   /* build 119 */
        static LONG nf; void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d); DWORD le = GetLastError();
        if (InterlockedIncrement(&nf) <= 30) {
            void kex_crashlog_callers(const char *what, DWORD ebp, int max);
            kex_crashnote("MapViewOfFile FAILED in Windows (size, offset, error, caller)", (DWORD)n, lo, le, (DWORD)(ULONG_PTR)__builtin_return_address(0));
            if (nf <= 6) kex_crashlog_callers("  MapViewOfFile failure - callers:", (DWORD)(ULONG_PTR)__builtin_frame_address(0), 14);   /* build 121 */
        }
        SetLastError(le);
    }
    /* Chromium (base/memory/shared_memory_mapping.cc) unmaps AlignDown(view, 64 KB) - NT views start on 64 KB
     * boundaries, Windows 98 ones only on 4 KB. A view that is not 64 KB aligned, or a second view of the same
     * section, is therefore handed out as a 64 KB-aligned KEXALIAS alias (build 17). */
    if (r) { InterlockedIncrement((LONG *)&g_n_map); if (!base) sec_mapped(h, r, lo); }
    if (r && !base) {
        LONG c = view_add(r, (DWORD)(ULONG_PTR)h, lo, (DWORD)n, (DWORD)(ULONG_PTR)__builtin_frame_address(0));
        /* the real address can be handed out only once (Win98 gives a second view of a section the same address)
         * and only if no other handed-out view shares its 64 KB window (Chromium unmaps AlignDown(view, 64 KB)) */
        if (c == 1 && try_expose(r)) return r;
        if ((a = alias_view(r, n)) != NULL) return a;           /* 64 KB-aligned alias of its own */
        /* no alias: an address that is not this view's alone would break the program later; fail the map instead,
         * as NT does when it runs out of address space */
        if (kex_view_release(r) == 0 || kex_shm_refcounted()) kex_real_unmap(r);   /* build 37: give the real map back */
        kex_trace("MapViewOfFile: no address of its own for this view (no alias) -> NULL", (DWORD)(ULONG_PTR)h, lo, (DWORD)n, (DWORD)c);
        {   static LONG nf2; void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
            if (InterlockedIncrement(&nf2) <= 30) kex_crashnote("MapViewOfFile FAILED: no alias address for a second view (size, offset, views of it, caller)",
                                                                (DWORD)n, lo, (DWORD)c, (DWORD)(ULONG_PTR)__builtin_return_address(0)); }
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    return r;
}
LPVOID KEXAPI kex_MapViewOfFile(HANDLE h, DWORD access, DWORD hi, DWORD lo, SIZE_T n)
{
    return kex_MapViewOfFileEx(h, access, hi, lo, n, NULL);
}

/* ---------------------------------------------------------------- build 37: report helpers for crashlog_ext.c */
/* v[0] live views, v[1] their bytes, v[2] exposed, v[3] live aliases, v[4] alias bytes, v[5] alias reserved KB,
 * v[6] live section handles kexnt knows, v[7] pagefile sections created, v[8] maps, v[9] unmaps, v[10] failed unmaps,
 * v[11] views not tracked (table full), v[12] failed aliases */
void kex_shm_counts(DWORD v[13])
{
    int i;
    for (i = 0; i < 13; i++) v[i] = 0;
    if (g_sech_init) {
        sech_lock();
        for (i = 0; i < NVIEWS; i++) if (g_views[i].addr) { v[0]++; v[1] += g_views[i].bytes; if (g_views[i].exposed) v[2]++; }
        for (i = 0; i < NALIAS; i++) if (g_alias[i].alias) { v[3]++; v[4] += g_alias[i].bytes; v[5] += ((((g_alias[i].bytes + 0xFFF) >> 12) + 15) & ~15UL) * 4 + 60; }
        for (i = 0; i < 512; i++) if (g_sech[i].h) v[6]++;
        LeaveCriticalSection(&g_sech_cs);
    }
    v[7] = (DWORD)g_n_create; v[8] = (DWORD)g_n_map; v[9] = (DWORD)g_n_unmap; v[10] = (DWORD)g_n_unmap_fail;
    v[11] = (DWORD)g_n_noslot; v[12] = (DWORD)g_n_alias_fail;
}
/* view i (0..NVIEWS-1): FALSE if the slot is empty; else out = addr, count, exposed, bytes, st[0..5] */
BOOL kex_shm_view(int i, DWORD out[10])
{
    int k;
    if (i < 0 || i >= NVIEWS || !g_views[i].addr) return FALSE;
    out[0] = (DWORD)(ULONG_PTR)g_views[i].addr; out[1] = (DWORD)g_views[i].count; out[2] = (DWORD)g_views[i].exposed;
    out[3] = g_views[i].bytes;
    for (k = 0; k < 6; k++) out[4 + k] = g_views[i].st[k];
    return TRUE;
}
int kex_shm_nviews(void) { return NVIEWS; }
/* the alias that starts its reservation at or covers `a` -> its real view, else 0 */
DWORD kex_shm_alias_of(DWORD a)
{
    int i; DWORD r = 0;
    for (i = 0; i < NALIAS; i++)
        if (g_alias[i].alias && a >= ((DWORD)(ULONG_PTR)g_alias[i].alias & ~0xFFFFUL) - 0x10000UL &&
            a < (DWORD)(ULONG_PTR)g_alias[i].alias + g_alias[i].bytes) { r = (DWORD)(ULONG_PTR)g_alias[i].view; break; }
    return r;
}

/* ---------------------------------------------------------------- build 37b: section census
 * Every pagefile-backed section kexnt sees created: its size, the code that created it, the handles of this process
 * that refer to it (CreateFileMapping, DuplicateHandle in this process; CloseHandle removes), and where it lives
 * (from its first view: view - offset). Kept after the last handle closes, so the out-of-memory report can tell
 * "Chromium still holds it" from "closed and unmapped but the memory is still there". */
#define NSEC 4096
#define NSH  4096
typedef struct { DWORD size, base, st[6], t_create, t_close; LONG nh; } KSEC;
typedef struct { HANDLE h; int sec; } KSH;
static KSEC g_sec[NSEC]; static int g_sec_next;
static KSH g_sh[NSH];
static int sh_find(HANDLE h) { int i; for (i = 0; i < NSH; i++) if (g_sh[i].h == h) return i; return -1; }
static void sh_add(HANDLE h, int sec)
{
    int i = sh_find(h);
    if (i < 0) for (i = 0; i < NSH && g_sh[i].h; i++) ;
    if (i >= NSH) return;
    if (g_sh[i].h == h && g_sh[i].sec >= 0) g_sec[g_sh[i].sec].nh--;   /* reused handle value */
    g_sh[i].h = h; g_sh[i].sec = sec; g_sec[sec].nh++;
}
static void sec_created(HANDLE h, DWORD size, DWORD ebp)
{
    int k, n;
    if (!kex_trace_enabled()) return;
    sech_lock();
    for (n = 0; n < NSEC; n++) {                       /* next slot that is closed (or never used) */
        k = (g_sec_next + n) % NSEC;
        if (g_sec[k].nh <= 0) break;
    }
    if (n < NSEC) {
        g_sec_next = (k + 1) % NSEC;
        ZeroMemory(&g_sec[k], sizeof(g_sec[k]));
        g_sec[k].size = size; g_sec[k].t_create = GetTickCount();
        view_stack(ebp, g_sec[k].st);
        sh_add(h, k);
    }
    LeaveCriticalSection(&g_sech_cs);
}
static void sec_dup(HANDLE from, HANDLE to)
{
    int i;
    if (!kex_trace_enabled()) return;
    sech_lock();
    if ((i = sh_find(from)) >= 0) sh_add(to, g_sh[i].sec);
    LeaveCriticalSection(&g_sech_cs);
}
static void sec_mapped(HANDLE h, void *view, DWORD off)
{
    int i;
    if (!kex_trace_enabled()) return;
    sech_lock();
    if ((i = sh_find(h)) >= 0 && !g_sec[g_sh[i].sec].base) g_sec[g_sh[i].sec].base = (DWORD)(ULONG_PTR)view - off;
    LeaveCriticalSection(&g_sech_cs);
}
static void sec_closed_locked(HANDLE h)
{
    int i;
    if (!kex_trace_enabled()) return;
    i = sh_find(h);
    if (i < 0) return;
    if (--g_sec[g_sh[i].sec].nh <= 0) g_sec[g_sh[i].sec].t_close = GetTickCount();
    g_sh[i].h = NULL;
}
/* the section kexnt knows at base `a` (allocation base of a shared-arena region): out = size, nh, t_create, t_close,
 * st[6] (10 DWORDs); FALSE if none */
BOOL kex_shm_section_at(DWORD a, DWORD out[10])
{
    int i, k;
    for (i = 0; i < NSEC; i++)
        if (g_sec[i].base && g_sec[i].base <= a && a < g_sec[i].base + (g_sec[i].size ? g_sec[i].size : 1)) {
            out[0] = g_sec[i].size; out[1] = (DWORD)g_sec[i].nh; out[2] = g_sec[i].t_create; out[3] = g_sec[i].t_close;
            for (k = 0; k < 6; k++) out[4 + k] = g_sec[i].st[k];
            return TRUE;
        }
    return FALSE;
}
/* section i: FALSE if never used; out as above plus out[10] = base */
BOOL kex_shm_section(int i, DWORD out[11])
{
    int k;
    if (i < 0 || i >= NSEC || !g_sec[i].t_create) return FALSE;
    out[0] = g_sec[i].size; out[1] = (DWORD)g_sec[i].nh; out[2] = g_sec[i].t_create; out[3] = g_sec[i].t_close;
    for (k = 0; k < 6; k++) out[4 + k] = g_sec[i].st[k];
    out[10] = g_sec[i].base;
    return TRUE;
}
int kex_shm_nsections(void) { return NSEC; }

/* GDI DIB sections (gdiguard_ext.c kex_CreateDIBSection): on Windows 98 their pixels live in the shared arena */
#define NDIB 1024
static DWORD gdi_type(HGDIOBJ o)
{
    typedef DWORD (WINAPI *T)(HGDIOBJ); static T f;
    if (!f) f = (T)(void *)kex_sysproc("GDI32.DLL", "GetObjectType");
    return f ? f(o) : 0;
}
static struct { HBITMAP b; DWORD bits, bytes, sec; } g_dib[NDIB];
void kex_shm_note_dib(HBITMAP b, const BITMAPINFO *bi, void *bits, HANDLE sec)
{
    int i; DWORD bytes = 0;
    if (!b || !bits || !kex_trace_enabled()) return;
    if (bi) {
        LONG w = bi->bmiHeader.biWidth, hh = bi->bmiHeader.biHeight;
        if (hh < 0) hh = -hh;
        bytes = (DWORD)((((w * bi->bmiHeader.biBitCount) + 31) / 32) * 4) * (DWORD)hh;
    }
    sech_lock();
    for (i = 0; i < NDIB; i++) if (!g_dib[i].b || gdi_type(g_dib[i].b) != OBJ_BITMAP) break;
    if (i < NDIB) { g_dib[i].b = b; g_dib[i].bits = (DWORD)(ULONG_PTR)bits; g_dib[i].bytes = bytes; g_dib[i].sec = (DWORD)(ULONG_PTR)sec; }
    LeaveCriticalSection(&g_sech_cs);
}
/* a live DIB whose pixels are in [a, a+n): its bytes, else 0 */
DWORD kex_shm_dib_at(DWORD a, DWORD n, DWORD *count)
{
    int i; DWORD t = 0, c = 0;
    for (i = 0; i < NDIB; i++)
        if (g_dib[i].b && g_dib[i].bits >= a && g_dib[i].bits < a + n && gdi_type(g_dib[i].b) == OBJ_BITMAP) { t += g_dib[i].bytes; c++; }
    if (count) *count = c;
    return t;
}

/* build 38b: for kextest - Windows' view counting as probed (1/0), and the kexnt counters (see kex_shm_counts) */
LONG KEXAPI kex_KexShmRefcounted(void) { return (LONG)kex_shm_refcounted(); }
LONG KEXAPI kex_KexShmStats(DWORD *v) { if (v) kex_shm_counts(v); return 13; }
