/* msicompat_ext.c - Windows Installer packages made for Windows Installer 3+ on Windows Installer 2.0 (build 125).
 *
 * Measured in the test VM (build 124): the Visual C++ 2013 runtime packages (vc_runtimeMinimum_x86.msi,
 * vc_runtimeAdditional_x86.msi, WiX 3.7) fail in Windows 98's MSI 2.0 before anything is read:
 *   msiexec /i: "Note: 1: 2203 2: <package> 3: -2147286779" = STG_E_OLDDLL, MainEngineThread returns 1620.
 * Cause 1: they are compound files of version 4 (4096-byte sectors, header major version 4) - Windows 98's OLE32
 *          only opens version 3 (512-byte sectors).
 * Cause 2: their summary information asks for Windows Installer 3.01 (PID_PAGECOUNT 301; MSI 2.0 refuses > 200).
 * Their tables use nothing MSI 2.0 lacks (File/Component/Registry/standard actions; checked with msidb.py).
 *
 * What kexnt does: the program's Windows Installer calls (below) get, for a READ-ONLY use of a Windows Installer
 * package/patch/transform that is a version-4 compound file, or a
 * package or patch whose summary asks for a Windows Installer newer than 2.0, is served from a converted copy in %TEMP%
 * (KXMxxxx.TMP): every storage and stream copied unchanged into a version-3 compound file made by Windows 98's
 * own OLE32 (StgCreateDocfile), the root CLSID and state bits kept, and only the summary's "minimum installer
 * version" lowered to Windows Installer 2.0 (database: page count 200; patch: word count 3). The original file is never written. Anything else - other files, write access, other
 * CLSIDs - goes to OLE32 unchanged. Each conversion is noted in KEXCRASH and in %WINDIR%\KEXMSI.LOG.
 * The compound file format: [MS-CFB] (public specification). */
#include "kexnt_common.h"
#include <objbase.h>

void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

static const GUID CLSID_MsiDb    = {0x000C1084,0,0,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID CLSID_MsiPatch = {0x000C1086,0,0,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID CLSID_MsiXform = {0x000C1082,0,0,{0xC0,0,0,0,0,0,0,0x46}};

/* ---------------- compound file reader (version 3 and 4) ---------------- */
typedef struct {
    HANDLE f; DWORD fsize; DWORD ss, mss, cutoff;          /* sector size, mini sector size, mini stream cutoff */
    DWORD *fat; DWORD nfat; DWORD *minifat; DWORD nminifat;
    BYTE *dir; DWORD ndir;                                 /* directory entries, 128 bytes each */
    BYTE *ministream; DWORD ministream_len;
} CFB;
#define ENDOFCHAIN 0xFFFFFFFEUL
#define FREESECT   0xFFFFFFFFUL
static void *xalloc(DWORD n) { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n ? n : 1); }
static void xfree(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }
static BOOL rd_at(CFB *c, DWORD off, void *b, DWORD n)
{
    DWORD got = 0;
    if (off > c->fsize || n > c->fsize - off) return FALSE;
    if (SetFilePointer(c->f, (LONG)off, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) return FALSE;
    return ReadFile(c->f, b, n, &got, NULL) && got == n;
}
static BOOL rd_sec(CFB *c, DWORD s, void *b) { return rd_at(c, (s + 1) * c->ss, b, c->ss); }
/* whole chain from a FAT start sector into a new buffer (len = bytes wanted; 0 = whole chain) */
static BYTE *rd_chain(CFB *c, DWORD start, DWORD len, DWORD *outlen)
{
    DWORD n = 0, s = start, cap; BYTE *b;
    for (s = start; s < c->nfat && n < c->nfat; s = c->fat[s]) n++;      /* chain length (bounded) */
    if (s != ENDOFCHAIN && n) { /* tolerate */ }
    cap = n * c->ss; if (len && len < cap) cap = len;
    b = (BYTE *)xalloc(cap + c->ss);
    if (!b) return NULL;
    { DWORD pos = 0, k = 0; BYTE *tmp = (BYTE *)xalloc(c->ss);
      for (s = start; s < c->nfat && k < n && pos < cap; s = c->fat[s], k++) {
          if (!rd_sec(c, s, tmp)) { xfree(tmp); xfree(b); return NULL; }
          { DWORD m = cap - pos < c->ss ? cap - pos : c->ss; CopyMemory(b + pos, tmp, m); pos += m; }
      }
      xfree(tmp);
      if (outlen) *outlen = pos; }
    return b;
}
static void cfb_close(CFB *c)
{
    xfree(c->fat); xfree(c->minifat); xfree(c->dir); xfree(c->ministream);
    if (c->f != INVALID_HANDLE_VALUE) CloseHandle(c->f);
    ZeroMemory(c, sizeof(*c)); c->f = INVALID_HANDLE_VALUE;
}
static BOOL cfb_open(CFB *c, const char *path)
{
    BYTE h[512]; DWORD nfatsec, dirstart, ministart, nmini, difstart, ndif, i, k, *difat = NULL, ndifat;
    ZeroMemory(c, sizeof(*c));
    c->f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (c->f == INVALID_HANDLE_VALUE) return FALSE;
    c->fsize = GetFileSize(c->f, NULL);
    if (!rd_at(c, 0, h, 512) || *(DWORD *)h != 0xE011CFD0UL || *(DWORD *)(h + 4) != 0xE11AB1A1UL) goto bad;
    c->ss = 1u << *(WORD *)(h + 30); c->mss = 1u << *(WORD *)(h + 32);
    if (c->ss != 512 && c->ss != 4096) goto bad;
    nfatsec = *(DWORD *)(h + 44); dirstart = *(DWORD *)(h + 48); c->cutoff = *(DWORD *)(h + 56);
    ministart = *(DWORD *)(h + 60); nmini = *(DWORD *)(h + 64); difstart = *(DWORD *)(h + 68); ndif = *(DWORD *)(h + 72);
    if (nfatsec > (c->fsize / c->ss) + 1 || ndif > 4096) goto bad;
    ndifat = 109 + ndif * (c->ss / 4 - 1);
    if (!(difat = (DWORD *)xalloc(ndifat * 4))) goto bad;
    CopyMemory(difat, h + 76, 109 * 4);
    { DWORD s = difstart, pos = 109, *sec = (DWORD *)xalloc(c->ss);
      for (k = 0; k < ndif && s < 0xFFFFFFFAUL && sec; k++) {
          if (!rd_sec(c, s, sec)) break;
          CopyMemory(difat + pos, sec, c->ss - 4); pos += c->ss / 4 - 1; s = sec[c->ss / 4 - 1];
      }
      xfree(sec); }
    c->nfat = nfatsec * (c->ss / 4);
    if (!(c->fat = (DWORD *)xalloc(c->nfat * 4))) goto bad;
    for (i = 0; i < nfatsec; i++) if (!rd_sec(c, difat[i], (BYTE *)c->fat + i * c->ss)) goto bad;
    { DWORD dl; c->dir = rd_chain(c, dirstart, 0, &dl); if (!c->dir) goto bad; c->ndir = dl / 128; }
    if (nmini && ministart < c->nfat) {
        DWORD ml; BYTE *m = rd_chain(c, ministart, 0, &ml);
        if (!m) goto bad;
        c->minifat = (DWORD *)m; c->nminifat = ml / 4;
    }
    {   /* root entry (0): the mini stream */
        DWORD rs = *(DWORD *)(c->dir + 116), rl = *(DWORD *)(c->dir + 120);
        if (rl && rs < c->nfat) c->ministream = rd_chain(c, rs, rl, &c->ministream_len);
    }
    xfree(difat);
    return TRUE;
bad:
    xfree(difat); cfb_close(c);
    return FALSE;
}
static BYTE *cfb_stream(CFB *c, DWORD e, DWORD *len)
{
    BYTE *d = c->dir + e * 128; DWORD start = *(DWORD *)(d + 116), size = *(DWORD *)(d + 120);
    if (c->ss == 512) size &= 0xFFFFFFFFUL;                /* v3: high DWORD of the size is ignored */
    *len = 0;
    if (size < c->cutoff) {                                /* in the mini stream */
        BYTE *b = (BYTE *)xalloc(size + 1); DWORD pos = 0, s = start, k = 0;
        if (!b) return NULL;
        while (pos < size && s < c->nminifat && k++ < c->nminifat) {
            DWORD off = s * c->mss, m = size - pos < c->mss ? size - pos : c->mss;
            if (!c->ministream || off + m > c->ministream_len) break;
            CopyMemory(b + pos, c->ministream + off, m); pos += m; s = c->minifat[s];
        }
        *len = pos; return b;
    }
    return rd_chain(c, start, size, len);
}

/* ---------------- copy into a new version-3 file through OLE32 ---------------- */
typedef HRESULT (WINAPI *T_SCD)(const WCHAR *, DWORD, DWORD, IStorage **);
typedef HRESULT (WINAPI *T_SOS)(const WCHAR *, IStorage *, DWORD, SNB, DWORD, IStorage **);
static int g_fixed;                                        /* summary changes made in the current conversion */
/* Windows 98's lstrcmpW is a stub (always 0) - own comparison */
static int wsame(const WCHAR *a, const WCHAR *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }
/* MSI summary information - the "minimum installer" fields:
 *   database: PID_PAGECOUNT (14), 200 = Windows Installer 2.0 (lowered from 300/301/500)
 *   patch:    PID_WORDCOUNT (15), 3 = Windows Installer 2.0, 4 = 3.0, 5 = 3.1 (documented "Word Count Summary")
 * kind: 1 database, 2 patch, 0 other (nothing changed) */
static void fix_summary(BYTE *s, DWORD n, int kind)
{
    DWORD so, cnt, i, want_pid = kind == 1 ? 14 : 15; LONG limit = kind == 1 ? 200 : 3;
    if (!kind || n < 48) return;
    so = *(DWORD *)(s + 44);
    if (so + 8 > n) return;
    cnt = *(DWORD *)(s + so + 4);
    for (i = 0; i < cnt && so + 8 + 8 * i + 8 <= n; i++) {
        DWORD pid = *(DWORD *)(s + so + 8 + 8 * i), po = *(DWORD *)(s + so + 12 + 8 * i);
        if (pid == want_pid && so + po + 8 <= n && *(DWORD *)(s + so + po) == 3 /* VT_I4 */) {
            LONG *v = (LONG *)(s + so + po + 4);
            if (*v > limit) { *v = limit; g_fixed++; }
        }
    }
}
static int copy_tree(CFB *c, DWORD e, IStorage *dst, int is_db, int depth)
{
    /* entries of one storage form a red-black tree: walk left, self, right */
    BYTE *d; DWORD left, right, child, type, nl; WCHAR name[33]; int err = 0;
    if (e >= c->ndir || depth > 64) return 0;
    d = c->dir + e * 128;
    left = *(DWORD *)(d + 68); right = *(DWORD *)(d + 72); child = *(DWORD *)(d + 76); type = d[66];
    nl = *(WORD *)(d + 64);
    if (left != FREESECT) err |= copy_tree(c, left, dst, is_db, depth + 1);
    if (nl >= 2 && nl <= 64) {
        CopyMemory(name, d, nl); name[nl / 2 - 1] = 0;
        if (type == 2) {                                   /* stream */
            DWORD len; BYTE *data = cfb_stream(c, e, &len); IStream *st = NULL; ULONG w;
            if (!data) err = 1;
            else {
                if (wsame(name, L"\x05SummaryInformation")) fix_summary(data, len, is_db);
                if (FAILED(dst->lpVtbl->CreateStream(dst, name, STGM_CREATE | STGM_WRITE | STGM_SHARE_EXCLUSIVE, 0, 0, &st))) err = 1;
                else { if (len && (FAILED(st->lpVtbl->Write(st, data, len, &w)) || w != len)) err = 1; st->lpVtbl->Release(st); }
                xfree(data);
            }
        } else if (type == 1) {                            /* storage */
            IStorage *sub = NULL;
            if (FAILED(dst->lpVtbl->CreateStorage(dst, name, STGM_CREATE | STGM_WRITE | STGM_SHARE_EXCLUSIVE, 0, 0, &sub))) err = 1;
            else {
                sub->lpVtbl->SetClass(sub, (REFCLSID)(d + 80));
                if (*(DWORD *)(d + 96)) sub->lpVtbl->SetStateBits(sub, *(DWORD *)(d + 96), 0xFFFFFFFFUL);
                if (child != FREESECT) err |= copy_tree(c, child, sub, 0, depth + 1);
                sub->lpVtbl->Commit(sub, STGC_DEFAULT); sub->lpVtbl->Release(sub);
            }
        }
    }
    if (right != FREESECT) err |= copy_tree(c, right, dst, is_db, depth + 1);
    return err;
}

static void hex8(char *o, DWORD v) { int i; for (i = 0; i < 8; i++) o[i] = "0123456789abcdef"[(v >> (28 - 4 * i)) & 15]; o[8] = 0; }
static void msilog(const char *a, const char *b, DWORD v)
{
    char p[MAX_PATH], h[12]; HANDLE f; DWORD w; SYSTEMTIME t; char ts[24]; int k = 0;
    if (!GetWindowsDirectoryA(p, MAX_PATH - 16)) return;
    lstrcatA(p, "\\KEXMSI.LOG");
    GetLocalTime(&t);
    { WORD v4[6] = { t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond }; int i;
      for (i = 0; i < 6; i++) { WORD x = v4[i]; if (i == 0) { ts[k++] = (char)('0' + x / 1000); ts[k++] = (char)('0' + x / 100 % 10); }
                                ts[k++] = (char)('0' + x / 10 % 10); ts[k++] = (char)('0' + x % 10); ts[k++] = i < 2 ? '-' : i == 2 ? ' ' : i < 5 ? ':' : ' '; }
      ts[k] = 0; }
    hex8(h, v);
    f = CreateFileA(p, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    SetFilePointer(f, 0, NULL, FILE_END);
    WriteFile(f, ts, (DWORD)lstrlenA(ts), &w, NULL); WriteFile(f, a, (DWORD)lstrlenA(a), &w, NULL); WriteFile(f, " ", 1, &w, NULL);
    WriteFile(f, b, (DWORD)lstrlenA(b), &w, NULL); WriteFile(f, " ", 1, &w, NULL); WriteFile(f, h, 8, &w, NULL); WriteFile(f, "\r\n", 2, &w, NULL);
    CloseHandle(f);
}

/* does this file need converting? 1 = version-4 compound file of an MSI class, 2 = MSI database asking > 2.0
 * (3, decided in convert(): "system32" folders of downlevel merge modules) */
static int needs_conversion(CFB *c, int *kind)
{
    const BYTE *root = c->dir;
    const GUID *cl = (const GUID *)(root + 80);
    *kind = IsEqualGUID(cl, &CLSID_MsiDb) ? 1 : IsEqualGUID(cl, &CLSID_MsiPatch) ? 2 : 0;
    if (!*kind && !IsEqualGUID(cl, &CLSID_MsiXform)) return 0;
    if (c->ss != 512) return 1;
    if (*kind) {    /* version-3 file: only if its summary asks for more than Windows Installer 2.0 */
        DWORD e, len; BYTE *d;
        for (e = 1; e < c->ndir; e++) {
            WCHAR nm[33]; DWORD nl = *(WORD *)(c->dir + e * 128 + 64);
            if (c->dir[e * 128 + 66] != 2 || nl < 2 || nl > 64) continue;
            CopyMemory(nm, c->dir + e * 128, nl); nm[nl / 2 - 1] = 0;
            if (!wsame(nm, L"\x05SummaryInformation")) continue;
            if (!(d = cfb_stream(c, e, &len))) return 0;
            g_fixed = 0; fix_summary(d, len, *kind); xfree(d);
            return g_fixed ? 2 : 0;
        }
    }
    return 0;
}


/* ---- LaunchCondition as on Windows XP SP2 (build 125) ----
 * Measured (VC++ 2013 minimum runtime, MSIQ.EXE + verbose log): LaunchCondition "VersionNT >= 501" -> "can only be
 * installed on Windows XP SP2 and newer platforms", 1603. Windows Installer 2.0 on Windows 98 leaves VersionNT empty
 * and ignores a VersionNT=501 command-line value (tested). kexnt presents Windows XP SP2 (5.1.2600) to these programs,
 * so in the converted copy only (never the original), LaunchCondition rows are rewritten with the values Windows
 * Installer sets on XP SP2: VersionNT 501, ServicePackLevel 2, WindowsBuild 2600, Version9X empty. Component and
 * sequence conditions are left alone (they choose what Windows 98 itself can use, e.g. "VersionNT >= 601" files,
 * service actions). */
typedef UINT (WINAPI *T_MODA)(LPCSTR, LPCSTR, DWORD *);
typedef UINT (WINAPI *T_MOVA)(DWORD, LPCSTR, DWORD *);
typedef UINT (WINAPI *T_MVE)(DWORD, DWORD);
typedef UINT (WINAPI *T_MVF)(DWORD, DWORD *);
typedef UINT (WINAPI *T_MRGS)(DWORD, UINT, LPSTR, DWORD *);
typedef DWORD (WINAPI *T_MCR)(UINT);
typedef UINT (WINAPI *T_MRSS)(DWORD, UINT, LPCSTR);
typedef UINT (WINAPI *T_MCH)(DWORD);
typedef UINT (WINAPI *T_MDC)(DWORD);
static int pfx(const char *p, const char *w) { while (*w && *p == *w) { p++; w++; } return !*w; }
static int idch(char ch) { return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '.'; }
static int cond_subst(const char *in, char *out, int cap, const char *const *val);
static int xp_cond(const char *in, char *out, int cap)
{
    static const char *const val[] = { "501", "2", "2600", "\"\"" };
    return cond_subst(in, out, cap, val);
}
static int cond_subst(const char *in, char *out, int cap, const char *const *val)
{
    static const char *nm[] = { "VersionNT", "ServicePackLevel", "WindowsBuild", "Version9X" };
    int n = 0, changed = 0; const char *p = in;
    while (*p && n < cap - 8) {
        int k, hit = -1;
        if (*p == '"') { do out[n++] = *p++; while (*p && *p != '"' && n < cap - 8); if (*p) out[n++] = *p++; continue; }
        if (idch(*p) && (p == in || !idch(p[-1])))
            for (k = 0; k < 4; k++) { int l = lstrlenA(nm[k]); if (pfx(p, nm[k]) && !idch(p[l])) { hit = k; break; } }
        if (hit >= 0 && n + lstrlenA(val[hit]) < cap - 8) { lstrcpyA(out + n, val[hit]); n += lstrlenA(val[hit]); p += lstrlenA(nm[hit]); changed = 1; }
        else out[n++] = *p++;
    }
    out[n] = 0;
    return changed && !*p;
}
static void xp_launch_conditions(const char *path)
{
#define MP(t, n) t n = (t)(void *)kex_sysproc("MSI.DLL", #n)
    MP(T_MODA, MsiOpenDatabaseA); MP(T_MOVA, MsiDatabaseOpenViewA); MP(T_MVE, MsiViewExecute); MP(T_MVF, MsiViewFetch);
    MP(T_MRGS, MsiRecordGetStringA); MP(T_MCR, MsiCreateRecord); MP(T_MRSS, MsiRecordSetStringA); MP(T_MCH, MsiCloseHandle);
    MP(T_MDC, MsiDatabaseCommit);
#undef MP
    DWORD db = 0, v = 0, rec = 0; int nrow = 0, i, done = 0;
    static char cond[8][1024], desc[8][1024];
    if (!MsiOpenDatabaseA || !MsiDatabaseOpenViewA || !MsiViewExecute || !MsiViewFetch || !MsiRecordGetStringA || !MsiCreateRecord ||
        !MsiRecordSetStringA || !MsiCloseHandle || !MsiDatabaseCommit) return;
    if (MsiOpenDatabaseA(path, (LPCSTR)(ULONG_PTR)1 /* MSIDBOPEN_TRANSACT */, &db)) return;
    if (!MsiDatabaseOpenViewA(db, "SELECT `Condition`, `Description` FROM `LaunchCondition`", &v) && !MsiViewExecute(v, 0)) {
        while (nrow < 8 && !MsiViewFetch(v, &rec)) {
            DWORD a = sizeof(cond[0]), b = sizeof(desc[0]);
            if (!MsiRecordGetStringA(rec, 1, cond[nrow], &a) && !MsiRecordGetStringA(rec, 2, desc[nrow], &b)) nrow++;
            MsiCloseHandle(rec);
        }
    }
    if (v) MsiCloseHandle(v);
    for (i = 0; i < nrow; i++) {
        char nc[1024]; DWORD r, dv = 0, iv = 0;
        if (!xp_cond(cond[i], nc, sizeof(nc))) continue;
        if (!(r = MsiCreateRecord(2))) break;
        MsiRecordSetStringA(r, 1, cond[i]);
        if (!MsiDatabaseOpenViewA(db, "DELETE FROM `LaunchCondition` WHERE `Condition` = ?", &dv)) { MsiViewExecute(dv, r); MsiCloseHandle(dv); }
        MsiRecordSetStringA(r, 1, nc); MsiRecordSetStringA(r, 2, desc[i]);
        if (!MsiDatabaseOpenViewA(db, "INSERT INTO `LaunchCondition` (`Condition`, `Description`) VALUES (?, ?)", &iv)) {
            if (!MsiViewExecute(iv, r)) { done++; msilog("  launch condition", cond[i], 0); msilog("    as on XP SP2:", nc, 0); }
            MsiCloseHandle(iv);
        }
        MsiCloseHandle(r);
    }
    if (done) MsiDatabaseCommit(db);
    MsiCloseHandle(db);
}


static int has(const char *s, const char *w);
/* build 132: does the package have a LaunchCondition that tests VersionNT/ServicePackLevel/WindowsBuild? Measured
 * (.NET Framework 3.5 SP1 setup -> netfx20a_x86.msi, a package for Windows Installer 2.0 that needed no other
 * conversion): LaunchCondition "Microsoft .NET Framework 2.0 Service Pack 2 requires Windows 2000 SP3 or later" -> 1603,
 * because Windows Installer 2.0 on Windows 98 leaves VersionNT empty. Such a package now also gets the converted copy,
 * whose LaunchCondition rows carry the values Windows XP's installer sets (xp_launch_conditions). */
static int nt_launch_conditions(const char *path)
{
#define MP(t, n) t n = (t)(void *)kex_sysproc("MSI.DLL", #n)
    MP(T_MODA, MsiOpenDatabaseA); MP(T_MOVA, MsiDatabaseOpenViewA); MP(T_MVE, MsiViewExecute); MP(T_MVF, MsiViewFetch);
    MP(T_MRGS, MsiRecordGetStringA); MP(T_MCH, MsiCloseHandle);
#undef MP
    DWORD db = 0, v = 0, rec = 0; int found = 0; char cond[1024], nc[1024];
    if (!MsiOpenDatabaseA || !MsiDatabaseOpenViewA || !MsiViewExecute || !MsiViewFetch || !MsiRecordGetStringA || !MsiCloseHandle) return 0;
    if (MsiOpenDatabaseA(path, (LPCSTR)(ULONG_PTR)0 /* MSIDBOPEN_READONLY */, &db)) return 0;
    if (!MsiDatabaseOpenViewA(db, "SELECT `Condition` FROM `LaunchCondition`", &v) && !MsiViewExecute(v, 0)) {
        while (!found && !MsiViewFetch(v, &rec)) {
            DWORD a = sizeof(cond);
            if (!MsiRecordGetStringA(rec, 1, cond, &a) && has(cond, "VersionNT") && xp_cond(cond, nc, sizeof(nc))) found = 1;
            MsiCloseHandle(rec);
        }
    }
    if (v) MsiCloseHandle(v);
    MsiCloseHandle(db);
    return found;
}

/* ---- Component conditions of NT-only packages (build 132) ----
 * Measured (.NET Framework 4.0, netfx_Core_x86.msi, verbose log): the loader shim mscoree.dll (and its MUI resources)
 * have the component condition "VersionNT < 600" - XP/2003 get the shim from the package, Vista+ have it in Windows.
 * Windows Installer 2.0 on Windows 98 leaves VersionNT empty, so the component was skipped ("Action: Null"); without
 * SYSTEM\mscoree.dll no .NET program can start (csc.exe: delay-load of mscoree.dll -> 0xC06D007E).
 * A package whose component conditions mention VersionNT and never Version9X was written for NT only; in the
 * converted copy those conditions get the values Windows Installer sets on Windows XP - the same values as the
 * LaunchCondition rows above (kexnt presents these setups as XP; kexnt's own GetVersionEx would only see Windows 98).
 * Vista+-only components ("VersionNT >= 600") stay excluded, as before. Rows that mention Version9X are never changed
 * ("NOT Version9X": .NET's perfcounter.dll stays out); a package with a row that SELECTS Version9X keeps all its
 * conditions (it chooses Windows 98 variants itself). */
static int has(const char *s, const char *w) { int l = lstrlenA(w); for (; *s; s++) if (pfx(s, w)) return 1; (void)l; return 0; }
static void nt_component_conditions(const char *path)
{
#define MP(t, n) t n = (t)(void *)kex_sysproc("MSI.DLL", #n)
    MP(T_MODA, MsiOpenDatabaseA); MP(T_MOVA, MsiDatabaseOpenViewA); MP(T_MVE, MsiViewExecute); MP(T_MVF, MsiViewFetch);
    MP(T_MRGS, MsiRecordGetStringA); MP(T_MCR, MsiCreateRecord); MP(T_MRSS, MsiRecordSetStringA); MP(T_MCH, MsiCloseHandle);
    MP(T_MDC, MsiDatabaseCommit);
#undef MP
    static char comp[256][80], cond[256][256]; DWORD db = 0, v = 0, rec = 0; int nrow = 0, i, done = 0, any9x = 0;
    if (!MsiOpenDatabaseA || !MsiDatabaseOpenViewA || !MsiViewExecute || !MsiViewFetch || !MsiRecordGetStringA || !MsiCreateRecord ||
        !MsiRecordSetStringA || !MsiCloseHandle || !MsiDatabaseCommit) return;
    if (MsiOpenDatabaseA(path, (LPCSTR)(ULONG_PTR)1 /* MSIDBOPEN_TRANSACT */, &db)) return;
    if (!MsiDatabaseOpenViewA(db, "SELECT `Component`, `Condition` FROM `Component`", &v) && !MsiViewExecute(v, 0)) {
        while (!MsiViewFetch(v, &rec)) {
            char c1[80], c2[256]; DWORD a = sizeof(c1), b = sizeof(c2);
            if (!MsiRecordGetStringA(rec, 1, c1, &a) && !MsiRecordGetStringA(rec, 2, c2, &b) && c2[0]) {
                if (has(c2, "Version9X")) { if (!has(c2, "NOT Version9X") && !has(c2, "not Version9X")) any9x = 1; }   /* rows that exclude 9x stay */
                else if (has(c2, "VersionNT") && nrow < 256) { lstrcpyA(comp[nrow], c1); lstrcpyA(cond[nrow], c2); nrow++; }
            }
            MsiCloseHandle(rec);
        }
    }
    if (v) MsiCloseHandle(v);
    for (i = 0; !any9x && i < nrow; i++) {
        char nc[512]; DWORD r, uv = 0;
        if (!xp_cond(cond[i], nc, sizeof(nc))) continue;
        if (!(r = MsiCreateRecord(2))) break;
        MsiRecordSetStringA(r, 1, nc); MsiRecordSetStringA(r, 2, comp[i]);
        if (!MsiDatabaseOpenViewA(db, "UPDATE `Component` SET `Condition` = ? WHERE `Component` = ?", &uv)) {
            if (!MsiViewExecute(uv, r)) { done++; if (done <= 12) { msilog("  component condition", cond[i], 0); msilog("    as on NT:", nc, 0); } }
            MsiCloseHandle(uv);
        }
        MsiCloseHandle(r);
    }
    if (done) { MsiDatabaseCommit(db); kex_crashnote("MSI: component conditions of an NT-only package evaluated as on Windows XP (rows, -, -, -)", (DWORD)done, 0, 0, 0); }
    MsiCloseHandle(db);
}

/* ---- "system32" folders of downlevel merge modules (build 126) ----
 * Measured (Visual C++ 2008 SP1 redistributable, MSI log + MSIQ.EXE): its merge modules carry "nosxs" components
 * for systems without side-by-side assemblies, condition "(VersionNT < 501) or Version9X", installed to a folder
 * SystemFolder.<...> = [WindowsFolder] + "system32" - the Windows 2000 name. On Windows 98 that made a new folder
 * C:\WINDOWS\system32 that no program searches (Geometry Dash: MSVCR90.DLL not found; with msvcr90.dll in SYSTEM it
 * starts). In the converted copy those rows name the real system folder (SYSTEM). Only Directory rows whose key
 * starts with "SystemFolder." and whose name is exactly "system32" are changed. */
static void sysdir_name(char *out, int cap)
{
    char s[MAX_PATH]; const char *b; int i;
    out[0] = 0;
    if (!GetSystemDirectoryA(s, MAX_PATH)) return;
    b = strrchr(s, '\\'); b = b ? b + 1 : s;
    for (i = 0; b[i] && i < cap - 1; i++) out[i] = b[i];
    out[i] = 0;
}
static int sys32_rows(const char *path, int fix)
{
#define MP(t, n) t n = (t)(void *)kex_sysproc("MSI.DLL", #n)
    MP(T_MODA, MsiOpenDatabaseA); MP(T_MOVA, MsiDatabaseOpenViewA); MP(T_MVE, MsiViewExecute); MP(T_MVF, MsiViewFetch);
    MP(T_MRGS, MsiRecordGetStringA); MP(T_MCR, MsiCreateRecord); MP(T_MRSS, MsiRecordSetStringA); MP(T_MCH, MsiCloseHandle);
    MP(T_MDC, MsiDatabaseCommit);
#undef MP
    DWORD db = 0, v = 0, rec = 0; int n = 0, i; static char key[16][80]; char sys[64];
    if (!MsiOpenDatabaseA || !MsiDatabaseOpenViewA || !MsiViewExecute || !MsiViewFetch || !MsiRecordGetStringA || !MsiCreateRecord ||
        !MsiRecordSetStringA || !MsiCloseHandle || !MsiDatabaseCommit) return 0;
    sysdir_name(sys, sizeof(sys));
    if (!sys[0] || !lstrcmpiA(sys, "system32")) return 0;
    if (MsiOpenDatabaseA(path, (LPCSTR)(ULONG_PTR)(fix ? 1 : 0), &db)) return 0;
    if (!MsiDatabaseOpenViewA(db, "SELECT `Directory`, `DefaultDir` FROM `Directory`", &v) && !MsiViewExecute(v, 0)) {
        while (n < 16 && !MsiViewFetch(v, &rec)) {
            char d[80], dd[80]; DWORD a = sizeof(d), b = sizeof(dd);
            if (!MsiRecordGetStringA(rec, 1, d, &a) && !MsiRecordGetStringA(rec, 2, dd, &b) && pfx(d, "SystemFolder.") && !lstrcmpiA(dd, "system32"))
                lstrcpyA(key[n++], d);
            MsiCloseHandle(rec);
        }
    }
    if (v) MsiCloseHandle(v);
    if (fix && n) {
        int done = 0;
        for (i = 0; i < n; i++) {
            DWORD r = MsiCreateRecord(2), uv = 0;
            if (!r) break;
            MsiRecordSetStringA(r, 1, sys); MsiRecordSetStringA(r, 2, key[i]);
            if (!MsiDatabaseOpenViewA(db, "UPDATE `Directory` SET `DefaultDir` = ? WHERE `Directory` = ?", &uv)) {
                if (!MsiViewExecute(uv, r)) { done++; msilog("  folder system32 ->", sys, 0); msilog("    for", key[i], 0); }
                MsiCloseHandle(uv);
            }
            MsiCloseHandle(r);
        }
        if (done) MsiDatabaseCommit(db);
    }
    MsiCloseHandle(db);
    return n;
}

/* converted copies made in this process: original path -> temp path (deleted at process exit when possible) */
typedef struct { char src[MAX_PATH]; FILETIME wt; DWORD size; char tmp[MAX_PATH]; int in_temp, exact; } CONV;
static CONV g_conv[16]; static int g_nconv; static volatile LONG g_lock;

/* exact = 1: content-identical copy for signature checking - only version-4 files, summary untouched, always in %TEMP% */
static BOOL convert(const char *src, char *tmp_out, int exact)
{
    CFB c; int is_db = 0, in_temp = 0; BOOL ok = FALSE; int why; char dir[MAX_PATH]; WCHAR wtmp[MAX_PATH]; IStorage *dst = NULL;
    T_SCD scd = (T_SCD)(void *)kex_sysproc("OLE32.DLL", "StgCreateDocfile");
    HANDLE h; FILETIME wt; DWORD size; int i;
    h = CreateFileA(src, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    GetFileTime(h, NULL, NULL, &wt); size = GetFileSize(h, NULL); CloseHandle(h);
    kex_spin_acquire(&g_lock);
    for (i = 0; i < g_nconv; i++)
        if (!lstrcmpiA(g_conv[i].src, src) && g_conv[i].exact == exact && g_conv[i].size == size && !CompareFileTime(&g_conv[i].wt, &wt) &&
            GetFileAttributesA(g_conv[i].tmp) != INVALID_FILE_ATTRIBUTES) {
            lstrcpyA(tmp_out, g_conv[i].tmp); InterlockedExchange(&g_lock, 0); return TRUE;
        }
    InterlockedExchange(&g_lock, 0);
    if (!scd || !cfb_open(&c, src)) { if (!exact) msilog("not a compound file", src, scd ? 1 : 0); return FALSE; }
    why = needs_conversion(&c, &is_db);
    if (exact) { if (why != 1) why = 0; is_db = 0; }
    if (!why && !exact && is_db == 1 && sys32_rows(src, 0)) why = 3;   /* downlevel "system32" folders (build 126) */
    if (!why && !exact && is_db == 1 && nt_launch_conditions(src)) why = 4;   /* NT-only launch conditions (build 132) */
    if (!why && !exact) msilog("no conversion needed", src, (DWORD)is_db | (c.ss << 8));
    if (!why) { cfb_close(&c); return FALSE; }
    /* beside the original, so external cabinets (Media table) are found and Windows Installer's cached source
     * stays valid: <name>_kx98<ext>; if that folder is not writable, %TEMP% */
    {   const char *bs = strrchr(src, '\\'), *dot = strrchr(src, '.'); int bl;
        HANDLE t;
        in_temp = 0;
        if (!dot || (bs && dot < bs)) dot = src + lstrlenA(src);
        bl = (int)(dot - src);
        if (!exact && bl + 6 + lstrlenA(dot) < MAX_PATH) {
            CopyMemory(tmp_out, src, bl); tmp_out[bl] = 0; lstrcatA(tmp_out, "_kx98"); lstrcatA(tmp_out, dot);
            t = CreateFileA(tmp_out, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
            if (t != INVALID_HANDLE_VALUE) CloseHandle(t); else tmp_out[0] = 0;
        } else tmp_out[0] = 0;
        if (!tmp_out[0]) {
            if (!GetTempPathA(MAX_PATH, dir) || !GetTempFileNameA(dir, "KXM", 0, tmp_out)) { cfb_close(&c); return FALSE; }
            in_temp = 1;
        }
    }
    MultiByteToWideChar(CP_ACP, 0, tmp_out, -1, wtmp, MAX_PATH);
    if (SUCCEEDED(scd(wtmp, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, &dst))) {
        DWORD rootchild = *(DWORD *)(c.dir + 76);
        g_fixed = 0;
        dst->lpVtbl->SetClass(dst, (REFCLSID)(c.dir + 80));
        ok = !copy_tree(&c, rootchild, dst, is_db, 0);
        if (ok && FAILED(dst->lpVtbl->Commit(dst, STGC_DEFAULT))) ok = FALSE;
        dst->lpVtbl->Release(dst);
    }
    msilog(ok ? (exact ? "converted (exact copy for the signature check)" : "converted") : "conversion FAILED", src, (DWORD)why | (c.ss << 8) | ((DWORD)g_fixed << 24));
    msilog("  ->", tmp_out, size);
    kex_crashnote(ok ? "MSI: package for Windows Installer 3+ opened through a converted copy (reason 1 = 4 KB-sector file, 2 = asks > 2.0, 3 = system32 rows, 4 = NT launch conditions; sector size; summary fixes)"
                     : "MSI: converting a package for Windows Installer 3+ FAILED (reason, sector size)",
                  (DWORD)why, c.ss, (DWORD)g_fixed, 0);
    cfb_close(&c);
    if (!ok) { DeleteFileA(tmp_out); return FALSE; }
    if (!exact && is_db == 1) { xp_launch_conditions(tmp_out); nt_component_conditions(tmp_out); sys32_rows(tmp_out, 1); }
    kex_spin_acquire(&g_lock);
    if (g_nconv < 16) { lstrcpynA(g_conv[g_nconv].src, src, MAX_PATH); g_conv[g_nconv].wt = wt; g_conv[g_nconv].size = size;
                        lstrcpynA(g_conv[g_nconv].tmp, tmp_out, MAX_PATH); g_conv[g_nconv].in_temp = in_temp; g_conv[g_nconv].exact = exact; g_nconv++; }
    InterlockedExchange(&g_lock, 0);
    return TRUE;
}

/* ---- the Windows Installer API, as programs call it ----
 * Measured (build 125 first try): msi.dll itself reaches OLE32 directly - KernelEx does not route the imports or
 * GetProcAddress of DLLs in the SYSTEM folder - so a StgOpenStorage wrapper never saw the packages. The program's
 * own calls into MSI.DLL ARE routed (by name and by ordinal), so the package and patch paths are swapped there:
 *   MsiInstallProduct, MsiApplyPatch, MsiOpenPackage(Ex), MsiOpenDatabase (read-only / patch file),
 *   MsiGetSummaryInformation (by path, read-only), MsiVerifyPackage: the path argument;
 *   MsiInstallProduct / MsiConfigureProductEx / MsiApplyPatch / MsiReinstall: "PATCH=a;b" in the command line.
 * Windows Installer 2.0 then caches and registers the converted copy, so repair and removal (Add/Remove Programs,
 * msiexec) later work on a package it can read. Files that need nothing are passed through untouched. */
static BOOL conv_a(LPCSTR path, char *out)
{
    char full[MAX_PATH], *fp;
    if (!path || IsBadStringPtrA(path, MAX_PATH) || !GetFullPathNameA(path, MAX_PATH, full, &fp)) return FALSE;
    if (GetFileAttributesA(full) == INVALID_FILE_ATTRIBUTES) return FALSE;
    return convert(full, out, 0);
}
static BOOL conv_w(LPCWSTR path, WCHAR *out)
{
    char a[MAX_PATH], t[MAX_PATH];
    if (!path || IsBadStringPtrW(path, MAX_PATH) || !WideCharToMultiByte(CP_ACP, 0, path, -1, a, MAX_PATH, NULL, NULL)) return FALSE;
    if (!conv_a(a, t)) return FALSE;
    return MultiByteToWideChar(CP_ACP, 0, t, -1, out, MAX_PATH) > 0;
}
/* command line: PATCH=<list> with converted patch paths; returns a new heap string or NULL (unchanged) */
static WCHAR *cmd_patch_w(LPCWSTR cmd)
{
    const WCHAR *p; WCHAR *out = NULL; int changed = 0, n, cap;
    if (!cmd || IsBadStringPtrW(cmd, 32767)) return NULL;
    for (p = cmd; *p; p++) {
        if ((p == cmd || p[-1] == L' ') && (p[0] | 32) == 'p' && (p[1] | 32) == 'a' && (p[2] | 32) == 't' && (p[3] | 32) == 'c' &&
            (p[4] | 32) == 'h' && p[5] == L'=') break;
    }
    if (!*p) return NULL;
    cap = lstrlenW(cmd) + 16 * MAX_PATH + 16;
    if (!(out = (WCHAR *)xalloc(cap * sizeof(WCHAR)))) return NULL;
    n = (int)(p - cmd + 6); CopyMemory(out, cmd, n * sizeof(WCHAR));
    p += 6;
    {   int q = *p == L'"'; WCHAR one[MAX_PATH], conv[MAX_PATH]; int k, items = 0;
        if (q) out[n++] = *p++;
        while (*p && (q ? *p != L'"' : *p != L' ') && items < 16) {
            for (k = 0; *p && *p != L';' && (q ? *p != L'"' : *p != L' ') && k < MAX_PATH - 1; ) one[k++] = *p++;
            one[k] = 0; items++;
            if (conv_w(one, conv)) { lstrcpyW(out + n, conv); n += lstrlenW(conv); changed = 1; }
            else { lstrcpyW(out + n, one); n += k; }
            if (*p == L';') out[n++] = *p++;
        }
        lstrcpyW(out + n, p);
    }
    if (!changed) { xfree(out); return NULL; }
    return out;
}
static char *cmd_patch_a(LPCSTR cmd)
{
    WCHAR *w, *r; int n; char *a;
    if (!cmd || IsBadStringPtrA(cmd, 32767)) return NULL;
    n = MultiByteToWideChar(CP_ACP, 0, cmd, -1, NULL, 0);
    if (n <= 0 || !(w = (WCHAR *)xalloc(n * sizeof(WCHAR)))) return NULL;
    MultiByteToWideChar(CP_ACP, 0, cmd, -1, w, n);
    r = cmd_patch_w(w); xfree(w);
    if (!r) return NULL;
    n = WideCharToMultiByte(CP_ACP, 0, r, -1, NULL, 0, NULL, NULL);
    a = n > 0 ? (char *)xalloc(n) : NULL;
    if (a) WideCharToMultiByte(CP_ACP, 0, r, -1, a, n, NULL, NULL);
    xfree(r);
    return a;
}
#define MSIFN(name) static FARPROC p_##name; if (!p_##name) p_##name = kex_sysproc("MSI.DLL", #name); if (!p_##name) return ERROR_CALL_NOT_IMPLEMENTED
typedef UINT (WINAPI *T_IPW)(LPCWSTR, LPCWSTR); typedef UINT (WINAPI *T_IPA)(LPCSTR, LPCSTR);
/* build 132: HKLM\Software\KernelEx\KexNG "MsiLog" = DWORD 1: every install a program starts through these wrappers
 * gets Windows Installer 2.0's verbose log in %WINDIR%\TEMP\KXMSI.LOG (appended). Setups that point MSI's log at a
 * place that never appears (the .NET 4.0 setup engine) can then be diagnosed. MsiEnableLog right before the install
 * call is the last one made, so it is the one Windows Installer uses. */
static void msi_force_log(void)
{
    typedef UINT (WINAPI *T_EL)(DWORD, LPCSTR, DWORD);
    HKEY k; DWORD v = 0, t, n = sizeof(v); char path[MAX_PATH]; T_EL el; UINT r;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExA(k, "MsiLog", NULL, &t, (BYTE *)&v, &n) != ERROR_SUCCESS || t != REG_DWORD) v = 0;
        RegCloseKey(k);
    }
    if (v != 1 || !(el = (T_EL)(void *)kex_sysproc("MSI.DLL", "MsiEnableLogA"))) return;
    n = GetWindowsDirectoryA(path, MAX_PATH - 20);
    if (!n || n >= MAX_PATH - 20) return;
    lstrcatA(path, "\\TEMP\\KXMSI.LOG");
    r = el(0x1FFF /* everything incl. VERBOSE */, path, 1 /* INSTALLLOGATTRIBUTES_APPEND */);
    kex_crashnote("MSI: verbose log forced (KexNG\\MsiLog=1) to %WINDIR%\\TEMP\\KXMSI.LOG (MsiEnableLog result)", r, 0, 0, 0);
}
BOOL kex_slip_install(LPCWSTR pkg, LPCWSTR cmd, WCHAR *newpkg, WCHAR **newcmd);   /* slip_ext.c (build 132) */
UINT KEXAPI kex_MsiInstallProductW(LPCWSTR pkg, LPCWSTR cmd)
{
    WCHAR c[MAX_PATH], *nc, sp[MAX_PATH], *sc = NULL; UINT r; MSIFN(MsiInstallProductW);
    msi_force_log();
    if (kex_slip_install(pkg, cmd, sp, &sc)) { pkg = sp; cmd = sc; }   /* Windows Installer 3 patches merged into the package */
    nc = cmd_patch_w(cmd);
    r = ((T_IPW)p_MsiInstallProductW)(conv_w(pkg, c) ? c : pkg, nc ? nc : cmd);
    xfree(nc); if (sc) HeapFree(GetProcessHeap(), 0, sc); return r;
}
UINT KEXAPI kex_MsiInstallProductA(LPCSTR pkg, LPCSTR cmd)
{
    char c[MAX_PATH], *nc; UINT r; MSIFN(MsiInstallProductA);
    msi_force_log();
    nc = cmd_patch_a(cmd);
    r = ((T_IPA)p_MsiInstallProductA)(conv_a(pkg, c) ? c : pkg, nc ? nc : cmd);
    xfree(nc); return r;
}
typedef UINT (WINAPI *T_CPXW)(LPCWSTR, int, int, LPCWSTR); typedef UINT (WINAPI *T_CPXA)(LPCSTR, int, int, LPCSTR);
UINT KEXAPI kex_MsiConfigureProductExW(LPCWSTR prod, int level, int state, LPCWSTR cmd)
{
    WCHAR *nc; UINT r; MSIFN(MsiConfigureProductExW);
    nc = cmd_patch_w(cmd); r = ((T_CPXW)p_MsiConfigureProductExW)(prod, level, state, nc ? nc : cmd); xfree(nc); return r;
}
UINT KEXAPI kex_MsiConfigureProductExA(LPCSTR prod, int level, int state, LPCSTR cmd)
{
    char *nc; UINT r; MSIFN(MsiConfigureProductExA);
    nc = cmd_patch_a(cmd); r = ((T_CPXA)p_MsiConfigureProductExA)(prod, level, state, nc ? nc : cmd); xfree(nc); return r;
}
typedef UINT (WINAPI *T_APW)(LPCWSTR, LPCWSTR, int, LPCWSTR); typedef UINT (WINAPI *T_APA)(LPCSTR, LPCSTR, int, LPCSTR);
UINT KEXAPI kex_MsiApplyPatchW(LPCWSTR patch, LPCWSTR pkg, int type, LPCWSTR cmd)
{
    WCHAR c1[MAX_PATH], c2[MAX_PATH], *nc; UINT r; MSIFN(MsiApplyPatchW);
    nc = cmd_patch_w(cmd);
    r = ((T_APW)p_MsiApplyPatchW)(conv_w(patch, c1) ? c1 : patch, (pkg && conv_w(pkg, c2)) ? c2 : pkg, type, nc ? nc : cmd);
    xfree(nc); return r;
}
UINT KEXAPI kex_MsiApplyPatchA(LPCSTR patch, LPCSTR pkg, int type, LPCSTR cmd)
{
    char c1[MAX_PATH], c2[MAX_PATH], *nc; UINT r; MSIFN(MsiApplyPatchA);
    nc = cmd_patch_a(cmd);
    r = ((T_APA)p_MsiApplyPatchA)(conv_a(patch, c1) ? c1 : patch, (pkg && conv_a(pkg, c2)) ? c2 : pkg, type, nc ? nc : cmd);
    xfree(nc); return r;
}
typedef UINT (WINAPI *T_OPW)(LPCWSTR, DWORD *); typedef UINT (WINAPI *T_OPA)(LPCSTR, DWORD *);
typedef UINT (WINAPI *T_OPXW)(LPCWSTR, DWORD, DWORD *); typedef UINT (WINAPI *T_OPXA)(LPCSTR, DWORD, DWORD *);
UINT KEXAPI kex_MsiOpenPackageW(LPCWSTR pkg, DWORD *h)
{ WCHAR c[MAX_PATH]; MSIFN(MsiOpenPackageW); return ((T_OPW)p_MsiOpenPackageW)((pkg && pkg[0] != L'#' && conv_w(pkg, c)) ? c : pkg, h); }
UINT KEXAPI kex_MsiOpenPackageA(LPCSTR pkg, DWORD *h)
{ char c[MAX_PATH]; MSIFN(MsiOpenPackageA); return ((T_OPA)p_MsiOpenPackageA)((pkg && pkg[0] != '#' && conv_a(pkg, c)) ? c : pkg, h); }
UINT KEXAPI kex_MsiOpenPackageExW(LPCWSTR pkg, DWORD opt, DWORD *h)
{ WCHAR c[MAX_PATH]; MSIFN(MsiOpenPackageExW); return ((T_OPXW)p_MsiOpenPackageExW)((pkg && pkg[0] != L'#' && conv_w(pkg, c)) ? c : pkg, opt, h); }
UINT KEXAPI kex_MsiOpenPackageExA(LPCSTR pkg, DWORD opt, DWORD *h)
{ char c[MAX_PATH]; MSIFN(MsiOpenPackageExA); return ((T_OPXA)p_MsiOpenPackageExA)((pkg && pkg[0] != '#' && conv_a(pkg, c)) ? c : pkg, opt, h); }
/* MsiOpenDatabase: persist 0 (read-only) or 32 (MSIDBOPEN_PATCHFILE) only - writes must reach the real file */
#define RO_PERSIST(p) ((ULONG_PTR)(p) == 0 || (ULONG_PTR)(p) == 32)
typedef UINT (WINAPI *T_ODW)(LPCWSTR, LPCWSTR, DWORD *); typedef UINT (WINAPI *T_ODA)(LPCSTR, LPCSTR, DWORD *);
UINT KEXAPI kex_MsiOpenDatabaseW(LPCWSTR path, LPCWSTR persist, DWORD *h)
{ WCHAR c[MAX_PATH]; MSIFN(MsiOpenDatabaseW); return ((T_ODW)p_MsiOpenDatabaseW)((RO_PERSIST(persist) && conv_w(path, c)) ? c : path, persist, h); }
UINT KEXAPI kex_MsiOpenDatabaseA(LPCSTR path, LPCSTR persist, DWORD *h)
{ char c[MAX_PATH]; MSIFN(MsiOpenDatabaseA); return ((T_ODA)p_MsiOpenDatabaseA)((RO_PERSIST(persist) && conv_a(path, c)) ? c : path, persist, h); }
typedef UINT (WINAPI *T_GSW)(DWORD, LPCWSTR, UINT, DWORD *); typedef UINT (WINAPI *T_GSA)(DWORD, LPCSTR, UINT, DWORD *);
UINT KEXAPI kex_MsiGetSummaryInformationW(DWORD db, LPCWSTR path, UINT upd, DWORD *h)
{ WCHAR c[MAX_PATH]; MSIFN(MsiGetSummaryInformationW); return ((T_GSW)p_MsiGetSummaryInformationW)(db, (!db && !upd && conv_w(path, c)) ? c : path, upd, h); }
UINT KEXAPI kex_MsiGetSummaryInformationA(DWORD db, LPCSTR path, UINT upd, DWORD *h)
{ char c[MAX_PATH]; MSIFN(MsiGetSummaryInformationA); return ((T_GSA)p_MsiGetSummaryInformationA)(db, (!db && !upd && conv_a(path, c)) ? c : path, upd, h); }
typedef UINT (WINAPI *T_VPW)(LPCWSTR); typedef UINT (WINAPI *T_VPA)(LPCSTR);
UINT KEXAPI kex_MsiVerifyPackageW(LPCWSTR path) { WCHAR c[MAX_PATH]; MSIFN(MsiVerifyPackageW); return ((T_VPW)p_MsiVerifyPackageW)(conv_w(path, c) ? c : path); }
UINT KEXAPI kex_MsiVerifyPackageA(LPCSTR path) { char c[MAX_PATH]; MSIFN(MsiVerifyPackageA); return ((T_VPA)p_MsiVerifyPackageA)(conv_a(path, c) ? c : path); }

/* ---- WinVerifyTrust (WINTRUST.DLL) ----
 * Measured (VC++ 2013 setup, Burn 3.7): Burn checks the Authenticode signature of each cached MSI with WinVerifyTrust
 * and stops on 0x800B0003 (TRUST_E_SUBJECT_FORM_UNKNOWN). WVT.EXE: Windows 98's MSI signature provider (msisip.dll,
 * {000C10F1-...}) verifies the version-3 VC++ 2010 packages (result 0), but does not recognise a version-4 file
 * (4 KB sectors; CryptSIPRetrieveSubjectGuid fails) -> 0x800B0003. The MSI signature covers the streams' contents,
 * not the sector size, so the file is verified through an exact version-3 copy (same streams, same classes, summary
 * untouched): a changed or unsigned package still fails exactly as before. Only WTD_CHOICE_FILE subjects that are
 * version-4 MSI compound files are touched. */
typedef struct { DWORD cb; LPCWSTR path; HANDLE hfile; GUID *known; } KWFI;
typedef struct { DWORD cb; void *pol, *sip; DWORD ui, revoke, choice; void *u; DWORD action; HANDLE state; } KWTD;
typedef LONG (WINAPI *T_WVT)(HWND, GUID *, void *);
LONG KEXAPI kex_WinVerifyTrust(HWND hwnd, GUID *action, void *data)
{
    static T_WVT p; KWTD *d = (KWTD *)data; KWFI *f, nf; WCHAR c[MAX_PATH]; char a[MAX_PATH], t[MAX_PATH], full[MAX_PATH], *fp; LONG r;
    if (!p) p = (T_WVT)(void *)kex_sysproc("WINTRUST.DLL", "WinVerifyTrust");
    if (!p) return (LONG)0x800B0001L;  /* TRUST_E_PROVIDER_UNKNOWN */
    if (!d || IsBadReadPtr(d, 28) || d->choice != 1 /* WTD_CHOICE_FILE */ || (d->cb >= 36 && d->action == 2 /* CLOSE */) ||
        !(f = (KWFI *)d->u) || IsBadReadPtr(f, 12) || !f->path || IsBadStringPtrW(f->path, MAX_PATH) ||
        !WideCharToMultiByte(CP_ACP, 0, f->path, -1, a, MAX_PATH, NULL, NULL) || !GetFullPathNameA(a, MAX_PATH, full, &fp) ||
        GetFileAttributesA(full) == INVALID_FILE_ATTRIBUTES || !convert(full, t, 1) ||
        !MultiByteToWideChar(CP_ACP, 0, t, -1, c, MAX_PATH))
        return p(hwnd, action, data);
    nf.cb = sizeof(nf) < f->cb ? sizeof(nf) : f->cb; nf.path = c; nf.hfile = NULL; nf.known = f->cb >= 16 ? f->known : NULL;
    d->u = &nf;
    r = p(hwnd, action, data);
    d->u = f;
    msilog("WinVerifyTrust through the exact copy", full, (DWORD)r);
    return r;
}

/* process end: remove the converted copies that are no longer open */
void kex_msicompat_exit(void)
{
    int i;
    for (i = 0; i < g_nconv; i++) if (g_conv[i].in_temp) DeleteFileA(g_conv[i].tmp);   /* copies beside the original stay: Windows Installer may need its source again */
}
