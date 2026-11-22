/*
 * chrome_ext.c - KERNEL32 / NTDLL functions Chromium (and other NT6+/NT10 programs) import that
 * neither Windows 98 SE nor KernelEx 4.5.2 provide: thread/process ids from handles, interlocked
 * singly linked lists, handle-based file information, volume enumeration, geo ids, heap queries,
 * process information and a few Rtl helpers.
 * Rule as everywhere in kexnt: emulate where Win98 has the data, otherwise fail with the error NT
 * itself returns for "not supported here" (never silent garbage).
 */
#include "kexnt_common.h"
#include <tlhelp32.h>
void kex_fpos_lock(HANDLE h);     /* pipe_ext.c, build 85 */
int kex_zero_gap(HANDLE h, DWORD lo, DWORD hi);   /* pipe_ext.c, build 92 */
void kex_fpos_unlock(HANDLE h);
#include <string.h>

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } KUSTR;
PVOID KEXAPI kex_KexGetNtPeb(PDWORD modules, PDWORD sites, PDWORD unhandled);

/* ------------------------------------------------------------------------------------------------
 * Win98 K32 objects. A thread id is (TDB ^ obfuscator) and a process id is (PDB ^ obfuscator); the
 * obfuscators follow from our own TDB/PDB (fs:[18h]-8, fs:[30h]) and ids. Handle -> object goes
 * through KERNEL32's internal GetHandleObject, called by OpenVxDHandle (same pattern KernelEx uses).
 * --------------------------------------------------------------------------------------------- */
typedef PVOID (WINAPI *GHO)(HANDLE h, DWORD handle_type, DWORD flags);
#define K32_HANDLETYPE(t) ((1UL << ((t) - 1)) + 0x80000000UL)
#define K32OBJ_PROCESS 6
#define K32OBJ_THREAD  7

static GHO find_get_handle_object(void)
{
    static GHO cached; static BOOL tried;
    if (!tried) {
        const BYTE *p = (const BYTE *)kex_sysproc("KERNEL32.DLL", "OpenVxDHandle");
        static const BYTE pat[] = { 0x6A, 0x00, 0x68, 0x02, 0x00, 0x00, 0x80, 0xFF, 0x74, 0x24, 0x0C, 0xE8 };
        int i;
        if (p && !IsBadReadPtr(p, 0x80))
            for (i = 0; i + (int)sizeof(pat) + 4 <= 0x80; i++)
                if (!memcmp(p + i, pat, sizeof(pat))) {
                    const BYTE *call = p + i + sizeof(pat) - 1;
                    cached = (GHO)(call + 5 + *(const LONG *)(call + 1));
                    break;
                }
        tried = TRUE;
    }
    return cached;
}

/* GetHandleObject ADDS A REFERENCE to the object it returns (KernelEx pairs every kexGetHandleObject with
 * kexDereferenceObject = cReferences--, K32OBJHEAD {WORD Type; WORD cReferences;}). Without the release, every
 * lookup leaked a reference: pipe ends never died (kextest [named pipes], round 15:43) and thread/process
 * objects looked up by GetThreadId & co. were never freed. The caller's handle keeps the object alive, so the
 * pointer stays valid after the release. */
static BYTE *k32_object(HANDLE h, int type)
{
    GHO gho = kex_is_win9x() ? find_get_handle_object() : NULL;
    BYTE *o = gho ? (BYTE *)gho(h, K32_HANDLETYPE(type), 0) : NULL;
    if (!o) return NULL;
    if (!IsBadWritePtr(o, 4)) __atomic_fetch_sub((volatile WORD *)(o + 2), (WORD)1, __ATOMIC_SEQ_CST);
    return (!IsBadReadPtr(o, 0x40) && o[0] == type) ? o : NULL;
}

/* build 94: is the process behind handle ph still able to take part in a handle operation? Windows 98 frees a
 * process's environment database (PDB+40h) when it terminates while its process object lives on; a
 * DuplicateHandle that closes a handle INSIDE such a process (DUPLICATE_CLOSE_SOURCE from a child), or puts one
 * into it, then reads through the NULL pointer in KERNEL32 and the CALLER crashes (build 93: browser main
 * thread, KERNEL32+dc8a, PDB+40h = 0, right after a tab process exited). 1 = alive, 0 = gone, -1 = unknown. */
int kex_process_alive(HANDLE ph)
{
    BYTE *pdb;
    if (ph == GetCurrentProcess() || ph == (HANDLE)(LONG_PTR)-1) return 1;
    if (WaitForSingleObject(ph, 0) == WAIT_OBJECT_0) return 0;
    pdb = k32_object(ph, K32OBJ_PROCESS);
    if (!pdb) return -1;
    if (IsBadReadPtr(pdb + 0x40, 4)) return -1;
    return *(DWORD *)(pdb + 0x40) ? 1 : 0;
}

/* For pipe_ext.c: K32 object of a handle (type-checked), or NULL. */
BYTE *kex_k32_object(HANDLE h, int type) { return k32_object(h, type); }

static BYTE *cur_tdb(void) { BYTE *t; __asm__ volatile("movl %%fs:0x18, %0" : "=r"(t)); return t - 8; }
static BYTE *cur_pdb(void) { BYTE *p; __asm__ volatile("movl %%fs:0x30, %0" : "=r"(p)); return p; }

DWORD KEXAPI kex_GetThreadId(HANDLE thread)
{
    BYTE *tdb;
    if (thread == GetCurrentThread()) return GetCurrentThreadId();
    if (!(tdb = k32_object(thread, K32OBJ_THREAD))) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
    return (DWORD)(ULONG_PTR)tdb ^ ((DWORD)(ULONG_PTR)cur_tdb() ^ GetCurrentThreadId());
}

DWORD KEXAPI kex_GetProcessIdOfThread(HANDLE thread)
{
    BYTE *tdb, *pdb;
    DWORD kex_pid_nt(DWORD real);                                /* build 131: NT-style id (pid_ext.c) */
    if (thread == GetCurrentThread()) return kex_pid_nt(GetCurrentProcessId());
    if (!(tdb = k32_object(thread, K32OBJ_THREAD))) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
    pdb = *(BYTE **)(tdb + 0x08 + 0x30);                         /* TDB.tib.pProcess */
    if (!pdb) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
    return kex_pid_nt((DWORD)(ULONG_PTR)pdb ^ ((DWORD)(ULONG_PTR)cur_pdb() ^ GetCurrentProcessId()));
}

static DWORD process_id(HANDLE process)
{
    BYTE *pdb;
    if (process == GetCurrentProcess()) return GetCurrentProcessId();
    if (!(pdb = k32_object(process, K32OBJ_PROCESS))) return 0;
    return (DWORD)(ULONG_PTR)pdb ^ ((DWORD)(ULONG_PTR)cur_pdb() ^ GetCurrentProcessId());
}
DWORD kex_process_id(HANDLE process) { return process_id(process); }   /* build 131: mem_ext.c (VirtualAllocEx & co.) */

/* ------------------------------------------------------------------------------------------------
 * Interlocked singly linked lists (x86 SLIST_HEADER: Next, Depth, Sequence in one 8-byte word,
 * updated with cmpxchg8b like NT does).
 * --------------------------------------------------------------------------------------------- */
typedef struct KSLE { struct KSLE *Next; } KSLE;
#define SL_NEXT(v)  ((KSLE *)(ULONG_PTR)(DWORD)(v))
#define SL_DEPTH(v) ((USHORT)((v) >> 32))
#define SL_SEQ(v)   ((USHORT)((v) >> 48))
#define SL_MAKE(n, d, s) ((ULONGLONG)(DWORD)(ULONG_PTR)(n) | ((ULONGLONG)(USHORT)(d) << 32) | ((ULONGLONG)(USHORT)(s) << 48))

static __inline ULONGLONG sl_read(volatile ULONGLONG *h) { return __sync_val_compare_and_swap(h, 0, 0); }

VOID KEXAPI kex_InitializeSListHead(volatile ULONGLONG *h) { *h = 0; }

KSLE *KEXAPI kex_InterlockedPushEntrySList(volatile ULONGLONG *h, KSLE *e)
{
    ULONGLONG o, n;
    do { o = sl_read(h); e->Next = SL_NEXT(o); n = SL_MAKE(e, SL_DEPTH(o) + 1, SL_SEQ(o) + 1); }
    while (!__sync_bool_compare_and_swap(h, o, n));
    return SL_NEXT(o);
}

KSLE *KEXAPI kex_InterlockedPopEntrySList(volatile ULONGLONG *h)
{
    ULONGLONG o, n;
    do {
        o = sl_read(h);
        if (!SL_NEXT(o)) return NULL;
        n = SL_MAKE(SL_NEXT(o)->Next, SL_DEPTH(o) - 1, SL_SEQ(o) + 1);
    } while (!__sync_bool_compare_and_swap(h, o, n));
    return SL_NEXT(o);
}

KSLE *KEXAPI kex_InterlockedFlushSList(volatile ULONGLONG *h)
{
    ULONGLONG o;
    do { o = sl_read(h); if (!SL_NEXT(o)) return NULL; }
    while (!__sync_bool_compare_and_swap(h, o, SL_MAKE(0, 0, SL_SEQ(o) + 1)));
    return SL_NEXT(o);
}

USHORT KEXAPI kex_QueryDepthSList(volatile ULONGLONG *h) { return SL_DEPTH(sl_read(h)); }

/* Vista+: push an already linked list first..last (count entries) in one step. */
KSLE *KEXAPI kex_InterlockedPushListSListEx(volatile ULONGLONG *h, KSLE *first, KSLE *last, ULONG count)
{
    ULONGLONG o, n;
    do { o = sl_read(h); last->Next = SL_NEXT(o); n = SL_MAKE(first, SL_DEPTH(o) + count, SL_SEQ(o) + 1); }
    while (!__sync_bool_compare_and_swap(h, o, n));
    return SL_NEXT(o);
}

/* ------------------------------------------------------------------------------------------------
 * Handle based file information (Vista+). Win98 has GetFileInformationByHandle / SetFileTime /
 * SetEndOfFile; anything that needs the file's path (rename, delete-on-close) is not possible here.
 * --------------------------------------------------------------------------------------------- */
enum { FileBasicInfo_ = 0, FileStandardInfo_ = 1, FileNameInfo_ = 2, FileRenameInfo_ = 3,
       FileDispositionInfo_ = 4, FileAllocationInfo_ = 5, FileEndOfFileInfo_ = 6, FileStreamInfo_ = 7,
       FileAttributeTagInfo_ = 9, FileIoPriorityHintInfo_ = 12, FileIdInfo_ = 18, FileDispositionInfoEx_ = 21 };

static LONGLONG ft64(FILETIME f) { return ((LONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }

BOOL KEXAPI kex_GetFileInformationByHandleEx(HANDLE h, int cls, LPVOID buf, DWORD size)
{
    BY_HANDLE_FILE_INFORMATION fi;
    if (!buf) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    switch (cls) {
    case FileBasicInfo_: case FileStandardInfo_: case FileAttributeTagInfo_: case FileIdInfo_:
        break;
    case FileNameInfo_: {    /* NT: the path inside the volume/device. Known for our pipes (Crashpad) */
        BOOL kex_pipe_name(HANDLE h, char *out, int cb);
        char n[MAX_PATH]; int k, len;
        struct { DWORD len; WCHAR name[1]; } *fn = buf;
        if (!kex_pipe_name(h, n, sizeof(n))) {
            static LONG k; DWORD KEXAPI kex_GetFileType(HANDLE h); void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
            if (InterlockedIncrement(&k) <= 10)   /* build 131: Supermium's crashpad handler stops here (FATAL) */
                kex_crashnote("GetFileInformationByHandleEx(FileNameInfo): no pipe name for this handle (handle, kexnt file type, Windows file type, -)",
                              (DWORD)(ULONG_PTR)h, kex_GetFileType(h), GetFileType(h), 0);
            SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
        len = lstrlenA(n) + 1;                                       /* + the leading backslash */
        if (size < 4 + (DWORD)len * 2) { SetLastError(ERROR_MORE_DATA); return FALSE; }
        fn->name[0] = L'\\';
        for (k = 1; k < len; k++) fn->name[k] = (WCHAR)(BYTE)n[k - 1];
        fn->len = (DWORD)len * 2;
        return TRUE;
    }
    default:
        SetLastError(cls == FileNameInfo_ ? ERROR_NOT_SUPPORTED : ERROR_INVALID_PARAMETER); return FALSE;
    }
    { BOOL KEXAPI kex_GetFileInformationByHandle(HANDLE, BY_HANDLE_FILE_INFORMATION *);
      if (!kex_GetFileInformationByHandle(h, &fi)) return FALSE; }
    if (cls == FileBasicInfo_) {
        struct { LONGLONG c, a, w, ch; DWORD attr; } *b = buf;
        if (size < sizeof(*b)) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
        b->c = ft64(fi.ftCreationTime); b->a = ft64(fi.ftLastAccessTime);
        b->w = b->ch = ft64(fi.ftLastWriteTime); b->attr = fi.dwFileAttributes;
    } else if (cls == FileStandardInfo_) {
        struct { LONGLONG alloc, eof; DWORD links; BOOLEAN del, dir; } *s = buf;
        LONGLONG sz = ((LONGLONG)fi.nFileSizeHigh << 32) | fi.nFileSizeLow;
        if (size < sizeof(*s)) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
        s->eof = sz; s->alloc = (sz + 4095) & ~4095LL; s->links = fi.nNumberOfLinks ? fi.nNumberOfLinks : 1;
        s->del = FALSE; s->dir = (fi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    } else if (cls == FileAttributeTagInfo_) {
        DWORD *t = buf;
        if (size < 8) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
        t[0] = fi.dwFileAttributes; t[1] = 0;
    } else {                                                     /* FileIdInfo */
        struct { ULONGLONG vol; BYTE id[16]; } *i = buf;
        if (size < sizeof(*i)) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
        memset(i, 0, sizeof(*i));
        i->vol = fi.dwVolumeSerialNumber;
        memcpy(i->id, &fi.nFileIndexLow, 4); memcpy(i->id + 4, &fi.nFileIndexHigh, 4);
    }
    return TRUE;
}

BOOL KEXAPI kex_SetFileInformationByHandle(HANDLE h, int cls, LPVOID buf, DWORD size)
{
    if (!buf) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    switch (cls) {
    case FileBasicInfo_: {
        const struct { LONGLONG c, a, w, ch; DWORD attr; } *b = buf;
        FILETIME c, a, w;
        if (size < sizeof(*b)) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
        c.dwLowDateTime = (DWORD)b->c; c.dwHighDateTime = (DWORD)(b->c >> 32);
        a.dwLowDateTime = (DWORD)b->a; a.dwHighDateTime = (DWORD)(b->a >> 32);
        w.dwLowDateTime = (DWORD)b->w; w.dwHighDateTime = (DWORD)(b->w >> 32);
        /* 0 = leave unchanged, -1 = stop updating (NT); attributes need a path on 9x: ignored */
        return SetFileTime(h, (b->c > 0) ? &c : NULL, (b->a > 0) ? &a : NULL, (b->w > 0) ? &w : NULL);
    }
    case FileEndOfFileInfo_: case FileAllocationInfo_: {
        LONGLONG want = *(const LONGLONG *)buf; LONG hi = 0, ohi = 0; DWORD lo, olo; BOOL ok;
        if (size < 8) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
        if (cls == FileAllocationInfo_) return TRUE;             /* allocation hints: nothing to do */
        kex_fpos_lock(h);                                         /* build 85: no read/write may run in between */
        olo = SetFilePointer(h, 0, &ohi, FILE_CURRENT);
        if (olo == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) { kex_fpos_unlock(h); return FALSE; }
        hi = (LONG)(want >> 32);
        lo = SetFilePointer(h, (LONG)(DWORD)want, &hi, FILE_BEGIN);
        if (lo == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) { DWORD le = GetLastError(); kex_fpos_unlock(h); SetLastError(le); return FALSE; }
        kex_zero_gap(h, lo, (DWORD)hi);                           /* build 92: grown part = zeros, as on NT */
        ok = SetEndOfFile(h);
        { DWORD le = GetLastError(); SetFilePointer(h, (LONG)olo, &ohi, FILE_BEGIN); kex_fpos_unlock(h); SetLastError(le); }
        return ok;
    }
    case FileIoPriorityHintInfo_:
        return TRUE;
    case FileDispositionInfo_: case FileDispositionInfoEx_: {
        /* build 50: delete-on-close, done by kexnt's CloseHandle (fpath_ext.c). Ex: flags DWORD, bit 0 = delete. */
        BOOL kex_fpath_set_delete(HANDLE h, BOOL del);
        BOOL del = cls == FileDispositionInfo_ ? (*(const BYTE *)buf != 0) : ((*(const DWORD *)buf & 1) != 0);
        if (size < (cls == FileDispositionInfo_ ? 1u : 4u)) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
        if (kex_fpath_set_delete(h, del)) return TRUE;
    }   /* fall through: a handle kexnt did not open */
    case FileRenameInfo_:
        { void kex_filefail(const char *api, const char *path, DWORD err, DWORD a, DWORD b);
          kex_filefail("SetFileInformationByHandle (class, handle) not supported", NULL, ERROR_NOT_SUPPORTED, (DWORD)cls, (DWORD)(ULONG_PTR)h); }
        SetLastError(ERROR_NOT_SUPPORTED); return FALSE;         /* need the path: not on 9x */
    default:
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
}

DWORD KEXAPI kex_GetFinalPathNameByHandleW(HANDLE h, LPWSTR buf, DWORD cch, DWORD flags)
{
    {   /* build 50: from the path kexnt noted at CreateFile (fpath_ext.c); "\\?\C:\..." as NT returns it */
        BOOL kex_fpath_get(HANDLE h, char *buf, DWORD cb); char p[MAX_PATH + 8]; int n;
        if (kex_fpath_get(h, p + 4, MAX_PATH)) {
            const char *src = (flags & 7) ? p + 4 : p;                    /* VOLUME_NAME_DOS (0) gets the \\?\ prefix */
            p[0] = '\\'; p[1] = '\\'; p[2] = '?'; p[3] = '\\';
            n = MultiByteToWideChar(CP_ACP, 0, src, -1, NULL, 0);      /* includes the terminator */
            if (!buf || cch < (DWORD)n) return (DWORD)n;
            MultiByteToWideChar(CP_ACP, 0, src, -1, buf, (int)cch);
            return (DWORD)(n - 1);
        }
    }
    { void kex_filefail(const char *api, const char *path, DWORD err, DWORD a, DWORD b);
      kex_filefail("GetFinalPathNameByHandleW (handle, flags) not supported", NULL, ERROR_NOT_SUPPORTED, (DWORD)(ULONG_PTR)h, flags); }
    SetLastError(ERROR_NOT_SUPPORTED); return 0;                 /* 9x keeps no path per handle */
}

DWORD KEXAPI kex_GetFinalPathNameByHandleA(HANDLE h, LPSTR buf, DWORD cch, DWORD flags)
{
    SetLastError(ERROR_NOT_SUPPORTED); return 0;
}

/* ------------------------------------------------------------------------------------------------
 * Volumes: 9x has no volume GUID names (\\?\Volume{...}\); enumeration reports "none".
 * --------------------------------------------------------------------------------------------- */
HANDLE KEXAPI kex_FindFirstVolumeW(LPWSTR name, DWORD cch) { SetLastError(ERROR_NO_MORE_FILES); return INVALID_HANDLE_VALUE; }
HANDLE KEXAPI kex_FindFirstVolumeA(LPSTR name, DWORD cch)  { SetLastError(ERROR_NO_MORE_FILES); return INVALID_HANDLE_VALUE; }
BOOL KEXAPI kex_FindNextVolumeW(HANDLE h, LPWSTR name, DWORD cch) { SetLastError(ERROR_NO_MORE_FILES); return FALSE; }
BOOL KEXAPI kex_FindNextVolumeA(HANDLE h, LPSTR name, DWORD cch)  { SetLastError(ERROR_NO_MORE_FILES); return FALSE; }
BOOL KEXAPI kex_FindVolumeClose(HANDLE h) { return TRUE; }
BOOL KEXAPI kex_GetVolumeNameForVolumeMountPointW(LPCWSTR mp, LPWSTR name, DWORD cch) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_GetVolumeNameForVolumeMountPointA(LPCSTR mp, LPSTR name, DWORD cch)   { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_GetVolumePathNamesForVolumeNameW(LPCWSTR vol, LPWSTR names, DWORD cch, PDWORD ret)
{
    if (ret) *ret = 0;
    SetLastError(ERROR_NOT_SUPPORTED); return FALSE;
}

/* build 131: GetVolumeInformationByHandleW (Vista+). Firefox 115+ setup's 7-Zip SFX imports it (its UPX stub ends
 * the process with exit code 0 when an import is missing - "nothing happens" when the setup is started). The path
 * kexnt noted when the file was opened (fpath_ext.c) gives the drive; Windows 98's GetVolumeInformationA does the rest. */
BOOL KEXAPI kex_GetVolumeInformationByHandleW(HANDLE h, LPWSTR vol, DWORD cvol, LPDWORD serial, LPDWORD maxlen,
                                             LPDWORD fsflags, LPWSTR fs, DWORD cfs)
{
    BOOL kex_fpath_get(HANDLE h, char *buf, DWORD cb); char p[MAX_PATH + 8], root[MAX_PATH], v[MAX_PATH + 1], f[MAX_PATH + 1];
    if (!kex_fpath_get(h, p, MAX_PATH)) {
        DWORD n = GetCurrentDirectoryA(MAX_PATH, p);     /* a handle kexnt did not open: its drive is unknown */
        if (!n || n >= MAX_PATH) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    }
    if (p[0] && p[1] == ':') { root[0] = p[0]; root[1] = ':'; root[2] = '\\'; root[3] = 0; }
    else if (p[0] == '\\' && p[1] == '\\') {          /* \\server\share\ */
        const char *q = p + 2; int k = 0;
        while (*q && k < 2) { if (*q == '\\') k++; q++; }
        lstrcpynA(root, p, (int)(q - p) + 1);
        if (k < 2) lstrcatA(root, "\\");
    } else { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (!GetVolumeInformationA(root, v, sizeof(v), serial, maxlen, fsflags, f, sizeof(f))) return FALSE;
    if (vol && cvol && !MultiByteToWideChar(CP_ACP, 0, v, -1, vol, (int)cvol)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (fs && cfs && !MultiByteToWideChar(CP_ACP, 0, f, -1, fs, (int)cfs)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    return TRUE;
}

/* Console: a GUI program on 9x cannot attach to its parent's console. */
BOOL KEXAPI kex_AttachConsole(DWORD pid) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }

/* ------------------------------------------------------------------------------------------------
 * Geographical location. Win98 has no GEOID database; the user's country is derived from the
 * default locale's country code (LOCALE_ICOUNTRY = phone code) for the common cases.
 * --------------------------------------------------------------------------------------------- */
static const struct { WORD phone; LONG geo; char iso2[3]; char iso3[4]; } g_geo[] = {
    { 1, 244, "US", "USA" }, { 2, 39, "CA", "CAN" }, { 7, 203, "RU", "RUS" }, { 30, 98, "GR", "GRC" },
    { 31, 176, "NL", "NLD" }, { 32, 21, "BE", "BEL" }, { 33, 84, "FR", "FRA" }, { 34, 217, "ES", "ESP" },
    { 36, 109, "HU", "HUN" }, { 39, 118, "IT", "ITA" }, { 40, 200, "RO", "ROU" }, { 41, 223, "CH", "CHE" },
    { 43, 14, "AT", "AUT" }, { 44, 242, "GB", "GBR" }, { 45, 61, "DK", "DNK" }, { 46, 221, "SE", "SWE" },
    { 47, 177, "NO", "NOR" }, { 48, 191, "PL", "POL" }, { 49, 94, "DE", "DEU" }, { 52, 166, "MX", "MEX" },
    { 54, 11, "AR", "ARG" }, { 55, 32, "BR", "BRA" }, { 61, 12, "AU", "AUS" }, { 64, 183, "NZ", "NZL" },
    { 81, 122, "JP", "JPN" }, { 82, 134, "KR", "KOR" }, { 86, 45, "CN", "CHN" }, { 90, 235, "TR", "TUR" },
    { 91, 113, "IN", "IND" }, { 351, 193, "PT", "PRT" }, { 353, 68, "IE", "IRL" }, { 358, 77, "FI", "FIN" },
    { 380, 241, "UA", "UKR" }, { 381, 271, "RS", "SRB" }, { 385, 108, "HR", "HRV" }, { 386, 212, "SI", "SVN" },
    { 389, 19618, "MK", "MKD" }, { 420, 75, "CZ", "CZE" }, { 421, 143, "SK", "SVK" }, { 886, 237, "TW", "TWN" },
};
#define GEO_COUNT (sizeof(g_geo) / sizeof(g_geo[0]))

LONG KEXAPI kex_GetUserGeoID(DWORD geoclass)
{
    char b[8]; unsigned i, code;
    if (geoclass != 16 /* GEOCLASS_NATION */) return -1;          /* GEOID_NOT_AVAILABLE */
    if (!GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_ICOUNTRY, b, sizeof(b))) return -1;
    for (code = 0, i = 0; b[i] >= '0' && b[i] <= '9'; i++) code = code * 10 + (b[i] - '0');
    for (i = 0; i < GEO_COUNT; i++) if (g_geo[i].phone == code) return g_geo[i].geo;
    return -1;
}

static int geo_info(LONG geo, DWORD type, char *out, int cch)
{
    unsigned i; char tmp[16]; const char *s = NULL;
    for (i = 0; i < GEO_COUNT && g_geo[i].geo != geo; i++) ;
    if (i == GEO_COUNT) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    switch (type) {
    case 4: s = g_geo[i].iso2; break;                              /* GEO_ISO2 */
    case 5: s = g_geo[i].iso3; break;                              /* GEO_ISO3 */
    case 8: {                                                    /* GEO_ID (no user32 wsprintf here) */
        char r[12]; int k = 0, j = 0; unsigned long v = (unsigned long)geo;
        do { r[k++] = (char)('0' + v % 10); v /= 10; } while (v);
        while (k) tmp[j++] = r[--k];
        tmp[j] = 0; s = tmp; break;
    }
    default: SetLastError(ERROR_INVALID_FLAGS); return 0;         /* names etc.: no database on 9x */
    }
    if (!out || !cch) return lstrlenA(s) + 1;
    if (cch < lstrlenA(s) + 1) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
    lstrcpyA(out, s); return lstrlenA(s) + 1;
}

int KEXAPI kex_GetGeoInfoA(LONG geo, DWORD type, LPSTR data, int cch, LANGID lang)
{
    return geo_info(geo, type, data, cch);
}

int KEXAPI kex_GetGeoInfoW(LONG geo, DWORD type, LPWSTR data, int cch, LANGID lang)
{
    char a[32]; int n = geo_info(geo, type, a, sizeof(a)), i;
    if (!n) return 0;
    if (!data || !cch) return n;
    if (cch < n) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
    for (i = 0; i < n; i++) data[i] = (WCHAR)(BYTE)a[i];
    return n;
}

/* ------------------------------------------------------------------------------------------------
 * Heaps
 * --------------------------------------------------------------------------------------------- */
BOOL KEXAPI kex_HeapQueryInformation(HANDLE heap, int cls, PVOID info, SIZE_T len, PSIZE_T ret)
{
    if (cls == 0) {                                               /* HeapCompatibilityInformation */
        if (ret) *ret = sizeof(ULONG);
        if (len < sizeof(ULONG) || !info) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        *(ULONG *)info = 0;                                       /* standard heap, no LFH */
        return TRUE;
    }
    SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
}

BOOL KEXAPI kex_HeapSetInformation(HANDLE heap, int cls, PVOID info, SIZE_T len)
{
    /* HeapCompatibilityInformation (LFH), HeapEnableTerminationOnCorruption (1), optimize (3): hints */
    if (cls == 0 || cls == 1 || cls == 3) return TRUE;
    SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
}

/* ------------------------------------------------------------------------------------------------
 * NTDLL: process information, files, strings, status codes
 * --------------------------------------------------------------------------------------------- */
#define STATUS_ACCESS_DENIED_K       ((NTSTATUS)0xC0000022L)
#define STATUS_PORT_NOT_SET          ((NTSTATUS)0xC0000353L)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xC000003AL)
#define STATUS_END_OF_FILE           ((NTSTATUS)0xC0000011L)
#define STATUS_DISK_FULL             ((NTSTATUS)0xC000007FL)
#define STATUS_PENDING_K             ((NTSTATUS)0x00000103L)
#define STATUS_UNSUCCESSFUL          ((NTSTATUS)0xC0000001L)
#define STATUS_SHARING_VIOLATION     ((NTSTATUS)0xC0000043L)
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035L)
#define STATUS_BUFFER_OVERFLOW       ((NTSTATUS)0x80000005L)

NTSTATUS kex_status_from_win32(DWORD e)
{
    switch (e) {
    case 0: return STATUS_SUCCESS;
    case ERROR_FILE_NOT_FOUND: return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_PATH_NOT_FOUND: return STATUS_OBJECT_PATH_NOT_FOUND;
    case ERROR_ACCESS_DENIED: return STATUS_ACCESS_DENIED_K;
    case ERROR_INVALID_HANDLE: return STATUS_INVALID_HANDLE_K;
    case ERROR_NOT_ENOUGH_MEMORY: case ERROR_OUTOFMEMORY: return STATUS_NO_MEMORY_K;
    case ERROR_INVALID_PARAMETER: return STATUS_INVALID_PARAMETER;
    case ERROR_HANDLE_EOF: return STATUS_END_OF_FILE;
    case ERROR_DISK_FULL: return STATUS_DISK_FULL;
    case ERROR_SHARING_VIOLATION: return STATUS_SHARING_VIOLATION;
    case ERROR_ALREADY_EXISTS: case ERROR_FILE_EXISTS: return STATUS_OBJECT_NAME_COLLISION;
    case ERROR_INSUFFICIENT_BUFFER: return STATUS_BUFFER_TOO_SMALL;
    case ERROR_MORE_DATA: return STATUS_BUFFER_OVERFLOW;
    case ERROR_NOT_SUPPORTED: case ERROR_CALL_NOT_IMPLEMENTED: return STATUS_NOT_SUPPORTED;
    case ERROR_IO_PENDING: return STATUS_PENDING_K;
    default: return STATUS_UNSUCCESSFUL;
    }
}

/* NT keeps the status of the last failed call in the TEB; 9x only has the Win32 code. */
NTSTATUS KEXAPI kex_RtlGetLastNtStatus(void) { return kex_status_from_win32(GetLastError()); }

ULONG KEXAPI kex_RtlNtStatusToDosError(NTSTATUS s)
{
    switch ((ULONG)s) {
    case 0: return 0;
    case 0xC0000034: return ERROR_FILE_NOT_FOUND;
    case 0xC000003A: return ERROR_PATH_NOT_FOUND;
    case 0xC0000022: return ERROR_ACCESS_DENIED;
    case 0xC0000008: return ERROR_INVALID_HANDLE;
    case 0xC0000017: return ERROR_NOT_ENOUGH_MEMORY;
    case 0xC000000D: return ERROR_INVALID_PARAMETER;
    case 0xC0000011: return ERROR_HANDLE_EOF;
    case 0xC000007F: return ERROR_DISK_FULL;
    case 0xC0000043: return ERROR_SHARING_VIOLATION;
    case 0xC0000035: return ERROR_ALREADY_EXISTS;
    case 0xC0000023: return ERROR_INSUFFICIENT_BUFFER;
    case 0x80000005: return ERROR_MORE_DATA;
    case 0xC00000BB: case 0xC0000002: return ERROR_NOT_SUPPORTED;
    case 0xC0000003: return ERROR_INVALID_PARAMETER;
    case 0xC0000004: return ERROR_BAD_LENGTH;
    case 0x103: return ERROR_IO_PENDING;
    default: return ERROR_MR_MID_NOT_FOUND;
    }
}

VOID KEXAPI kex_RtlInitUnicodeString(KUSTR *u, PCWSTR s)
{
    SIZE_T n = 0;
    if (s) while (s[n]) n++;
    if (n > 0x7FFE) n = 0x7FFE;
    u->Buffer = (PWSTR)s;
    u->Length = (USHORT)(n * 2);
    u->MaximumLength = s ? (USHORT)(n * 2 + 2) : 0;
}

NTSTATUS KEXAPI kex_RtlInitUnicodeStringEx(KUSTR *u, PCWSTR s)
{
    SIZE_T n = 0;
    if (s) while (s[n]) n++;
    if (n > 0x7FFE) return STATUS_INVALID_PARAMETER;   /* NAME_TOO_LONG on NT; same effect */
    kex_RtlInitUnicodeString(u, s);
    return STATUS_SUCCESS;
}

VOID KEXAPI kex_RtlFreeUnicodeString(KUSTR *u)
{
    if (u && u->Buffer) { HeapFree(GetProcessHeap(), 0, u->Buffer); u->Buffer = NULL; u->Length = u->MaximumLength = 0; }
}

typedef struct { USHORT Length, MaximumLength; PCHAR Buffer; } KASTR;
VOID KEXAPI kex_RtlInitAnsiString(KASTR *a, PCSTR s)
{
    SIZE_T n = s ? (SIZE_T)lstrlenA(s) : 0;
    if (n > 0xFFFE) n = 0xFFFE;
    a->Buffer = (PCHAR)s; a->Length = (USHORT)n; a->MaximumLength = s ? (USHORT)(n + 1) : 0;
}

typedef struct { union { NTSTATUS Status; PVOID Pointer; }; ULONG_PTR Information; } KIOSB;

NTSTATUS KEXAPI kex_NtWriteFile(HANDLE h, HANDLE ev, PVOID apc, PVOID apcctx, KIOSB *iosb,
                                PVOID buf, ULONG len, PLARGE_INTEGER offset, PULONG key)
{
    DWORD done = 0; BOOL ok;
    kex_fpos_lock(h);                                             /* build 85: seek + write as one step */
    if (offset && !(offset->HighPart == -1 && (offset->LowPart == 0xFFFFFFFF || offset->LowPart == 0xFFFFFFFE))) {
        LONG hi = offset->HighPart;
        kex_zero_gap(h, offset->LowPart, (DWORD)offset->HighPart);   /* build 92 */
        if (SetFilePointer(h, (LONG)offset->LowPart, &hi, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
            GetLastError() != NO_ERROR) { DWORD le = GetLastError(); kex_fpos_unlock(h); return kex_status_from_win32(le); }
    } else if (offset && offset->LowPart == 0xFFFFFFFF) {       /* FILE_WRITE_TO_END_OF_FILE */
        SetFilePointer(h, 0, NULL, FILE_END);
    }
    ok = WriteFile(h, buf, len, &done, NULL);
    if (ok && offset && offset->HighPart >= 0) { void kex_fpos_check(HANDLE, DWORD, DWORD, DWORD, int); kex_fpos_check(h, offset->LowPart, (DWORD)offset->HighPart, done, 1); }
    { DWORD le = GetLastError(); kex_fpos_unlock(h); SetLastError(le); }
    if (!ok) {
        NTSTATUS s = kex_status_from_win32(GetLastError());
        if (iosb) { iosb->Status = s; iosb->Information = 0; }
        return s;
    }
    if (iosb) { iosb->Status = STATUS_SUCCESS; iosb->Information = done; }
    if (ev) SetEvent(ev);
    return STATUS_SUCCESS;
}

NTSTATUS KEXAPI kex_NtReadFile(HANDLE h, HANDLE ev, PVOID apc, PVOID apcctx, KIOSB *iosb,
                               PVOID buf, ULONG len, PLARGE_INTEGER offset, PULONG key)
{
    DWORD done = 0; BOOL ok;
    kex_fpos_lock(h);                                             /* build 85: seek + read as one step */
    if (offset && !(offset->HighPart == -1 && offset->LowPart == 0xFFFFFFFE)) {
        LONG hi = offset->HighPart;
        if (SetFilePointer(h, (LONG)offset->LowPart, &hi, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
            GetLastError() != NO_ERROR) { DWORD le = GetLastError(); kex_fpos_unlock(h); return kex_status_from_win32(le); }
    }
    ok = ReadFile(h, buf, len, &done, NULL);
    if (ok && offset && offset->HighPart >= 0) { void kex_fpos_check(HANDLE, DWORD, DWORD, DWORD, int); kex_fpos_check(h, offset->LowPart, (DWORD)offset->HighPart, done, 0); }
    { DWORD le = GetLastError(); kex_fpos_unlock(h); SetLastError(le); }
    if (!ok) {
        NTSTATUS s = kex_status_from_win32(GetLastError());
        if (iosb) { iosb->Status = s; iosb->Information = 0; }
        return s;
    }
    if (iosb) { iosb->Status = (done || !len) ? STATUS_SUCCESS : STATUS_END_OF_FILE; iosb->Information = done; }
    if (ev) SetEvent(ev);
    return (done || !len) ? STATUS_SUCCESS : STATUS_END_OF_FILE;
}

NTSTATUS KEXAPI kex_NtQueryVolumeInformationFile(HANDLE h, KIOSB *iosb, PVOID buf, ULONG len, ULONG cls)
{
    if (cls == 4) {                                               /* FileFsDeviceInformation */
        DWORD *d = buf;
        if (len < 8) return STATUS_INFO_LENGTH_MISMATCH;
        d[0] = (GetFileType(h) == FILE_TYPE_DISK) ? 7 /* FILE_DEVICE_DISK */ : 0x11 /* NAMED_PIPE */;
        d[1] = 0;
        if (iosb) { iosb->Status = STATUS_SUCCESS; iosb->Information = 8; }
        return STATUS_SUCCESS;
    }
    return STATUS_INVALID_INFO_CLASS;
}

/* Build 131: the PEB of ANOTHER process. kexnt's PEB of a process lives in that process's kexnt.dll and exists only
 * after kexnt has started there; Chromium's sandbox broker (Firefox 115 content processes) reads the PEB of a child it
 * has just created SUSPENDED (GetProcessBaseAddress: ProcessBasicInformation -> ReadProcessMemory(PEB) ->
 * ImageBaseAddress -> "MZ"). Windows 98 maps a suspended child's EXE before it runs (kextest [suspended child]), and
 * its shared arena is visible at the same address in every process - so every process kexnt starts (or is asked
 * about) gets a PEB-shaped record in a system-wide table: ImageBaseAddress, OS version as in this process's PEB, the
 * rest zero. */
#define FPEB_N  64
#define FPEB_SZ 0x480
typedef struct { DWORD pid, base, tick, pad; BYTE peb[FPEB_SZ]; } FPEB;
typedef struct { DWORD magic, version, pad[2]; FPEB e[FPEB_N]; } FPEBTAB;
static FPEBTAB *g_fpeb; static HANDLE g_fpeb_mx; static volatile LONG g_fpeb_init;
static FPEBTAB *fpeb_table(void)
{
    if (g_fpeb) return g_fpeb;
    kex_spin_acquire(&g_fpeb_init);
    if (!g_fpeb) {
        HANDLE m = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(FPEBTAB), "KXNT_FOREIGN_PEB");
        HANDLE x = CreateMutexA(NULL, FALSE, "KXNT_FOREIGN_PEB_LOCK");
        FPEBTAB *t = m ? (FPEBTAB *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0) : NULL;
        if (t && x) {
            WaitForSingleObject(x, INFINITE);
            if (t->magic != 0x4250464BUL || t->version != 1) { memset(t, 0, sizeof(*t)); t->magic = 0x4250464BUL; t->version = 1; }
            ReleaseMutex(x);
            g_fpeb_mx = x; g_fpeb = t;                   /* the mapping stays for the life of the process */
        }
    }
    InterlockedExchange(&g_fpeb_init, 0);
    return g_fpeb;
}
static PVOID fpeb_put(DWORD pid, DWORD base)
{
    FPEBTAB *t = fpeb_table(); FPEB *e = NULL; BYTE *own; int i;
    if (!t || !pid || !base) return NULL;
    WaitForSingleObject(g_fpeb_mx, INFINITE);
    for (i = 0; i < FPEB_N && !e; i++) if (t->e[i].pid == pid) e = &t->e[i];
    for (i = 0; i < FPEB_N && !e; i++) if (!t->e[i].pid) e = &t->e[i];
    if (!e) { e = &t->e[0]; for (i = 1; i < FPEB_N; i++) if (t->e[i].tick < e->tick) e = &t->e[i]; }   /* oldest */
    memset(e->peb, 0, sizeof(e->peb));
    own = (BYTE *)kex_KexGetNtPeb(NULL, NULL, NULL);
    if (own) { memcpy(e->peb + 0x64, own + 0x64, 8); memcpy(e->peb + 0xA4, own + 0xA4, 0x10); }   /* CPUs, flags, OS version */
    *(DWORD *)(e->peb + 0x08) = base;                    /* ImageBaseAddress */
    e->pid = pid; e->base = base; e->tick = GetTickCount();
    ReleaseMutex(g_fpeb_mx);
    return e->peb;
}
static PVOID fpeb_get(DWORD pid)
{
    FPEBTAB *t = fpeb_table(); int i; PVOID r = NULL;
    if (!t) return NULL;
    WaitForSingleObject(g_fpeb_mx, INFINITE);
    for (i = 0; i < FPEB_N; i++) if (t->e[i].pid == pid) { r = t->e[i].peb; break; }
    ReleaseMutex(g_fpeb_mx);
    if (!r) {   /* not started through kexnt: its EXE from Toolhelp (first module whose path is the process's EXE) */
        HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); PROCESSENTRY32 pe; char exe[MAX_PATH] = "";
        if (s != INVALID_HANDLE_VALUE) {
            pe.dwSize = sizeof(pe);
            if (Process32First(s, &pe)) do if (pe.th32ProcessID == pid) { lstrcpynA(exe, pe.szExeFile, MAX_PATH); break; } while (Process32Next(s, &pe));
            CloseHandle(s);
        }
        if (exe[0] && (s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)) != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me; me.dwSize = sizeof(me);
            if (Module32First(s, &me)) do if (!lstrcmpiA(me.szExePath, exe)) { r = fpeb_put(pid, (DWORD)(ULONG_PTR)me.modBaseAddr); break; } while (Module32Next(s, &me));
            CloseHandle(s);
        }
    }
    return r;
}
/* procspawn_ext.c: a child kexnt just created - its EXE base from the EXE's own header (Windows 98 never moves an EXE) */
void kex_fpeb_note_child(DWORD pid, HANDLE ph, const char *exe)
{
    char full[MAX_PATH], *fp; HANDLE f; BYTE h[0x200]; DWORD n = 0, base = 0; BYTE mz[2];
    if (!pid || !exe || !exe[0]) return;
    if (!SearchPathA(NULL, exe, ".exe", MAX_PATH, full, &fp)) lstrcpynA(full, exe, MAX_PATH);
    f = CreateFileA(full, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    if (ReadFile(f, h, sizeof(h), &n, NULL) && n >= 0x40 && h[0] == 'M' && h[1] == 'Z') {
        LONG o = *(LONG *)(h + 0x3C);
        if (o > 0 && o + 0x38 < (LONG)n && *(DWORD *)(h + o) == IMAGE_NT_SIGNATURE) base = *(DWORD *)(h + o + 0x34);
    }
    CloseHandle(f);
    if (base && ph && ReadProcessMemory(ph, (LPCVOID)(ULONG_PTR)base, mz, 2, &n) && mz[0] == 'M' && mz[1] == 'Z')
        fpeb_put(pid, base);
}

NTSTATUS KEXAPI kex_NtQueryInformationProcess(HANDLE process, ULONG cls, PVOID buf, ULONG len, PULONG retlen)
{
    DWORD pid = process_id(process);
    BOOL self = (process == GetCurrentProcess() || pid == GetCurrentProcessId());
    if (!pid) return STATUS_INVALID_HANDLE_K;
    switch (cls) {
    case 0: {                                                     /* ProcessBasicInformation */
        struct { NTSTATUS exit; PVOID peb; ULONG_PTR affinity; LONG prio; ULONG_PTR pid, ppid; } *b = buf;
        if (retlen) *retlen = sizeof(*b);
        if (len != sizeof(*b)) return STATUS_INFO_LENGTH_MISMATCH;
        memset(b, 0, sizeof(*b));
        { DWORD kex_pid_nt(DWORD real); b->exit = STILL_ACTIVE; b->affinity = 1; b->prio = 8; b->pid = kex_pid_nt(pid); }   /* build 131: NT-style id */
        if (self) b->peb = kex_KexGetNtPeb(NULL, NULL, NULL);
        else b->peb = fpeb_get(pid);                              /* build 131: other processes (see fpeb_table) */
        return STATUS_SUCCESS;
    }
    case 7:                                                       /* ProcessDebugPort */
        if (retlen) *retlen = sizeof(ULONG_PTR);
        if (len != sizeof(ULONG_PTR)) return STATUS_INFO_LENGTH_MISMATCH;
        *(ULONG_PTR *)buf = 0; return STATUS_SUCCESS;
    case 26:                                                      /* ProcessWow64Information */
        if (retlen) *retlen = sizeof(ULONG_PTR);
        if (len != sizeof(ULONG_PTR)) return STATUS_INFO_LENGTH_MISMATCH;
        *(ULONG_PTR *)buf = 0; return STATUS_SUCCESS;
    case 30:                                                      /* ProcessDebugObjectHandle */
        if (retlen) *retlen = sizeof(HANDLE);
        if (len != sizeof(HANDLE)) return STATUS_INFO_LENGTH_MISMATCH;
        *(HANDLE *)buf = NULL; return STATUS_PORT_NOT_SET;
    case 31:                                                      /* ProcessDebugFlags */
        if (retlen) *retlen = sizeof(ULONG);
        if (len != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
        *(ULONG *)buf = 1; return STATUS_SUCCESS;
    case 27: case 43: {                                           /* ProcessImageFileName(Win32) */
        char path[MAX_PATH]; int n; KUSTR *u = buf; WCHAR *w;
        if (!self) return STATUS_ACCESS_DENIED_K;
        n = (int)GetModuleFileNameA(NULL, path, MAX_PATH);
        if (cls == 27) {                                          /* NT path: \??\C:\... */
            memmove(path + 4, path, (n + 1 < MAX_PATH - 4) ? n + 1 : MAX_PATH - 4); memcpy(path, "\\??\\", 4);
            n += 4;
        }
        if (retlen) *retlen = sizeof(KUSTR) + (n + 1) * 2;
        if (len < sizeof(KUSTR) + (ULONG)(n + 1) * 2) return STATUS_INFO_LENGTH_MISMATCH;
        w = (WCHAR *)(u + 1);
        n = MultiByteToWideChar(CP_ACP, 0, path, n, w, n + 1);
        w[n] = 0; u->Buffer = w; u->Length = (USHORT)(n * 2); u->MaximumLength = (USHORT)(n * 2 + 2);
        return STATUS_SUCCESS;
    }
    case 36:                                                      /* ProcessCookie */
        if (retlen) *retlen = sizeof(ULONG);
        if (len != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
        *(ULONG *)buf = GetCurrentProcessId() * 2654435761UL ^ 0x5A17C0DEUL; return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_INFO_CLASS;
    }
}

/* NtQueryObject (2026-11-10 build 14). Chromium checks the TYPE of every handle it receives on a child's command
 * line (base/win/scoped_handle.cc TakeHandleOfType -> GetObjectTypeName: "Section" for shared memory) and fails
 * the region otherwise (histogram_shared_memory.cc:146 "Invald memory region passed on command line" in every
 * helper process). Windows 98 keeps a type byte in each kernel object and the access mask in the handle table;
 * from those this answers ObjectBasicInformation (0), ObjectNameInformation (1, empty name) and
 * ObjectTypeInformation (2) with the NT type names. kexnt's own pipe ends (named events) and directory handles
 * report "File", as on NT. Layouts from the public winternl.h / ntdef structures. */
BOOL kex_handle_facts(HANDLE h, BYTE *type, DWORD *access, BOOL *inherit);   /* procspawn_ext.c */
BOOL kex_pipe_name(HANDLE h, char *out, int cb);                             /* pipe_ext.c */
BOOL kex_dir_is(HANDLE h);                                                   /* dirhandle_ext.c */
DWORD kex_section_access(HANDLE h, DWORD dflt);                              /* shm_ext.c */
static const char *nt_type_name(HANDLE h, BYTE t)
{
    char tmp[8];
    if (h == (HANDLE)(LONG_PTR)-1 || h == GetCurrentProcess()) return "Process";   /* 9x pseudo handles: 0x7FFFFFFF / 0xFFFFFFFE */
    if (h == (HANDLE)(LONG_PTR)-2 || h == GetCurrentThread()) return "Thread";
    if (kex_dir_is(h)) return "File";
    switch (t) {
    case 1: return "Semaphore";
    case 2: return kex_pipe_name(h, tmp, sizeof(tmp)) ? "File" : "Event";
    case 3: return "Mutant";
    case 5: return "File";                     /* change notification: NT has a File/Directory handle */
    case 6: return "Process";
    case 7: return "Thread";
    case 0xD: return "Section";
    case 0x10: return "Section";
    case 8: case 9: case 0xA: case 0xB: case 0xC: case 0xE: case 0xF: case 0x11: return "File";
    default: return NULL;
    }
}
NTSTATUS KEXAPI kex_NtQueryObject(HANDLE h, ULONG cls, PVOID buf, ULONG len, PULONG retlen)
{
    BYTE t = 0; DWORD acc = 0; BOOL inh = FALSE, ok;
    const char *name;
    if (retlen) *retlen = 0;
    if (h == (HANDLE)(LONG_PTR)-1 || h == GetCurrentProcess()) { ok = TRUE; t = 6; acc = 0x1FFFFF; }
    else if (h == (HANDLE)(LONG_PTR)-2 || h == GetCurrentThread()) { ok = TRUE; t = 7; acc = 0x1FFFFF; }
    else ok = kex_handle_facts(h, &t, &acc, &inh);
    if (!ok) return STATUS_INVALID_HANDLE_K;
    switch (cls) {
    case 0: {                                   /* PUBLIC_OBJECT_BASIC_INFORMATION, 56 bytes */
        ULONG *b = (ULONG *)buf;
        if (retlen) *retlen = 56;
        if (len < 56 || !buf) return STATUS_INFO_LENGTH_MISMATCH;
        memset(b, 0, 56);
        if (t == 0xD) acc = kex_section_access(h, acc);
        /* build 66: Chromium's IsReadOnlyFile (mojo read_only_file_mojom_traits.cc:68, the unzip service at
         * startup) wants GrantedAccess without any write right for a file opened read-only. Windows 98's handle
         * table has no NT rights; kexnt knows how the file was opened (CreateFile / DuplicateHandle). */
        else if (t == 8 || t == 9 || t == 0xA || t == 0xB || t == 0xC || t == 0xE || t == 0xF || t == 0x11 || t == 5) {
            int kex_fview_access(HANDLE h);
            int k = kex_fview_access(h);
            if (k == 2) acc = 0x00120089;                  /* FILE_GENERIC_READ */
            else if (k == 1) acc = 0x0012019F;             /* FILE_GENERIC_READ | FILE_GENERIC_WRITE */
            else {
                DWORD m = 0;                               /* Windows 98's own field, if it holds GENERIC_* bits */
                if (acc & GENERIC_READ) m |= 0x00120089;
                if (acc & GENERIC_WRITE) m |= 0x00120116;
                if (acc & GENERIC_EXECUTE) m |= 0x001200A0;
                if (acc & GENERIC_ALL) m |= 0x001F01FF;
                {   static LONG nn; void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
                    if (InterlockedIncrement(&nn) <= 10) kex_crashnote("NtQueryObject: file handle kexnt did not see opened (handle, Win98 access, reported, type)", (DWORD)(ULONG_PTR)h, acc, m ? m : 0x0012019F, t); }
                acc = m ? m : 0x0012019F;
            }
        }
        b[0] = inh ? 2 : 0;                     /* OBJ_INHERIT */
        b[1] = acc ? acc : 0x1F0000;            /* GrantedAccess */
        b[2] = 1; b[3] = 2;                     /* HandleCount, PointerCount */
        return STATUS_SUCCESS;
    }
    case 1: {                                   /* OBJECT_NAME_INFORMATION: no name */
        WORD *u = (WORD *)buf;
        if (retlen) *retlen = 8;
        if (len < 8 || !buf) return STATUS_INFO_LENGTH_MISMATCH;
        u[0] = 0; u[1] = 0; *(void **)(u + 2) = NULL;
        return STATUS_SUCCESS;
    }
    case 2: {                                   /* OBJECT_TYPE_INFORMATION: UNICODE_STRING + 22 ULONGs, then the name */
        ULONG need, n, i; BYTE *b = (BYTE *)buf; WCHAR *w;
        if (!(name = nt_type_name(h, t))) return STATUS_INVALID_HANDLE_K;
        n = (ULONG)lstrlenA(name);
        need = 96 + (n + 1) * 2;
        if (retlen) *retlen = need;
        if (len < need || !buf) return STATUS_INFO_LENGTH_MISMATCH;
        memset(b, 0, 96);
        w = (WCHAR *)(b + 96);
        for (i = 0; i < n; i++) w[i] = (WCHAR)name[i];
        w[n] = 0;
        *(WORD *)b = (WORD)(n * 2); *(WORD *)(b + 2) = (WORD)(n * 2 + 2); *(WCHAR **)(b + 4) = w;
        *(ULONG *)(b + 8) = 1; *(ULONG *)(b + 12) = 1;    /* TotalNumberOfObjects / Handles */
        *(ULONG *)(b + 40) = acc ? acc : 0x1F0000;          /* ValidAccessMask (approximate) */
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_INVALID_INFO_CLASS;
    }
}
