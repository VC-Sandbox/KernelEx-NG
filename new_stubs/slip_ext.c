/*
 * slip_ext.c - Windows Installer 3 patches (.msp) on Windows Installer 2.0: merged into the package (build 132).
 *
 * Windows 98 has Windows Installer 2.0. Patches made for 3.x are refused - measured: msiexec /p of the .NET 3.5 SP1
 * package's dotNetFX20\clr.msp: "Transform #T1ToU1 version 301 incompatible with engine; Min: 30, Max: 200", 1636.
 * The .NET Framework 2.0 SP2 component is such a set: netfx20a_x86.msi holds no files, nine patches carry all of them;
 * the setup asks MsiDetermineApplicablePatches (3.0 - Windows 98: none) and installs the package with PATCH=.
 *
 * Proven with probes/msslip.c on Windows 98's own MSI 2.0 (package installed, result 0, assemblies in the GAC): a patch's
 * data transform (T1ToU1, minimum installer 200) and its patch transform (#T1ToU1, minimum 301 only for bookkeeping
 * tables) both apply with MsiDatabaseApplyTransform once the second's minimum version reads 200; the patch's cabinet is
 * a stream of the .msp; every patch adds the same Media row (DiskId 101, cabinet "#PCW_CAB_NetFX", Source "PatchMediaSrc"
 * - a property of the 3.x patch engine) and numbers its files 1001..; Windows Installer 3 renumbers them at install time.
 *
 * Here, when an install's command line names patches that need Windows Installer 3, the package is merged first:
 *   copy of the package -> every transform of every patch applied (validation errors ignored, minimum version lowered)
 *   -> each patch's cabinet streams embedded under names unique to the patch -> the patch Media rows removed ->
 *   after the last patch, the files of each cabinet numbered in the cabinet's own order (later patches win for files
 *   several carry), one Media row per cabinet without a Source property.
 * The merged package (%WINDIR%\KEXMSI\<name>_kx98p.msi, kept for repair and removal) is installed without PATCH=.
 * MsiDetermineApplicablePatchesA/W report every patch as applicable, in the order given (the setup resolves the names). Only modern programs.
 */
#define COBJMACROS
#include "kexnt_common.h"
#include <objbase.h>

void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

static char *chr(const char *s, char c) { for (; *s; s++) if (*s == c) return (char *)s; return NULL; }
static char *rchr(const char *s, char c) { char *r = NULL; for (; *s; s++) if (*s == c) r = (char *)s; return r; }
static void cat_num(char *s, int n) { char t[12]; int k = 0; if (!n) t[k++] = '0'; while (n) { t[k++] = (char)('0' + n % 10); n /= 10; } s += lstrlenA(s); while (k) *s++ = t[--k]; *s = 0; }

typedef DWORD MH;
typedef UINT (WINAPI *T_ODB)(LPCSTR, LPCSTR, MH *);
typedef UINT (WINAPI *T_OV)(MH, LPCSTR, MH *);
typedef UINT (WINAPI *T_VE)(MH, MH);
typedef UINT (WINAPI *T_VF)(MH, MH *);
typedef UINT (WINAPI *T_H)(MH);
typedef UINT (WINAPI *T_RGS)(MH, UINT, LPSTR, DWORD *);
typedef int  (WINAPI *T_RGI)(MH, UINT);
typedef UINT (WINAPI *T_RSS)(MH, UINT, LPCSTR);
typedef UINT (WINAPI *T_RSI)(MH, UINT, int);
typedef MH   (WINAPI *T_CR)(UINT);
typedef UINT (WINAPI *T_AT)(MH, LPCSTR, int);
typedef UINT (WINAPI *T_GSI)(MH, LPCSTR, UINT, MH *);
typedef UINT (WINAPI *T_SGP)(MH, UINT, UINT *, INT *, FILETIME *, LPSTR, DWORD *);
typedef UINT (WINAPI *T_SSP)(MH, UINT, UINT, INT, FILETIME *, LPCSTR);
typedef UINT (WINAPI *T_RSST)(MH, UINT, LPCSTR);
typedef UINT (WINAPI *T_RRS)(MH, UINT, char *, DWORD *);
typedef UINT (WINAPI *T_VM)(MH, int, MH);
typedef HRESULT (WINAPI *T_SOS)(const WCHAR *, IStorage *, DWORD, SNB, DWORD, IStorage **);
typedef HRESULT (WINAPI *T_SCD)(const WCHAR *, DWORD, DWORD, IStorage **);

static struct {
    T_ODB odb; T_OV ov; T_VE ve; T_VF vf; T_H vc, ch, commit, persist; T_RGS rgs; T_RGI rgi; T_RSS rss; T_RSI rsi; T_CR cr;
    T_AT at; T_GSI gsi; T_SGP sgp; T_SSP ssp; T_RSST rsst; T_RRS rrs; T_VM vm; T_SOS sos; T_SCD scd; int ok;
} M;

static BOOL api(void)
{
#define P(f, n) (M.f = (void *)kex_sysproc("MSI.DLL", n))
    if (M.ok) return M.ok > 0;
    P(odb, "MsiOpenDatabaseA"); P(ov, "MsiDatabaseOpenViewA"); P(ve, "MsiViewExecute"); P(vf, "MsiViewFetch");
    P(vc, "MsiViewClose"); P(ch, "MsiCloseHandle"); P(commit, "MsiDatabaseCommit"); P(persist, "MsiSummaryInfoPersist");
    P(rgs, "MsiRecordGetStringA"); P(rgi, "MsiRecordGetInteger"); P(rss, "MsiRecordSetStringA"); P(rsi, "MsiRecordSetInteger");
    P(cr, "MsiCreateRecord"); P(at, "MsiDatabaseApplyTransformA"); P(gsi, "MsiGetSummaryInformationA");
    P(sgp, "MsiSummaryInfoGetPropertyA"); P(ssp, "MsiSummaryInfoSetPropertyA"); P(rsst, "MsiRecordSetStreamA"); P(rrs, "MsiRecordReadStream");
    P(vm, "MsiViewModify");
#undef P
    M.sos = (T_SOS)(void *)kex_sysproc("OLE32.DLL", "StgOpenStorage");
    M.scd = (T_SCD)(void *)kex_sysproc("OLE32.DLL", "StgCreateDocfile");
    M.ok = (M.odb && M.ov && M.ve && M.vf && M.vc && M.ch && M.commit && M.persist && M.rgs && M.rgi && M.rss && M.rsi && M.cr &&
            M.at && M.gsi && M.sgp && M.ssp && M.rsst && M.rrs && M.vm && M.sos && M.scd) ? 1 : -1;
    return M.ok > 0;
}

static UINT exec(MH db, const char *q, MH rec)
{
    MH v; UINT e = M.ov(db, q, &v);
    if (e) return e;
    e = M.ve(v, rec); M.vc(v); M.ch(v);
    return e;
}

/* the patch's transform list (summary PID 8, ":T1;:#T1") */
static BOOL transforms(const char *msp, char *out, DWORD cb)
{
    MH si; UINT t; INT iv; FILETIME ft; BOOL ok;
    if (M.gsi(0, msp, 0, &si)) return FALSE;
    ok = !M.sgp(si, 8, &t, &iv, &ft, out, &cb);
    M.ch(si);
    return ok;
}

/* minimum installer version of one transform substorage of the patch (summary PID 14); extracted to `mst` */
static int extract_transform(IStorage *stg, const char *name, const char *mst)
{
    WCHAR wn[80], wp[MAX_PATH]; IStorage *sub = NULL, *dst = NULL; HRESULT hr; int ver = -1;
    MultiByteToWideChar(CP_ACP, 0, name, -1, wn, 80); MultiByteToWideChar(CP_ACP, 0, mst, -1, wp, MAX_PATH);
    if (FAILED(IStorage_OpenStorage(stg, wn, NULL, STGM_READ | STGM_SHARE_EXCLUSIVE, NULL, 0, &sub))) return -1;
    hr = M.scd(wp, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, &dst);
    if (SUCCEEDED(hr)) { hr = IStorage_CopyTo(sub, 0, NULL, NULL, dst); if (SUCCEEDED(hr)) IStorage_Commit(dst, 0); IStorage_Release(dst); }
    IStorage_Release(sub);
    if (FAILED(hr)) return -1;
    {   MH si; UINT t; INT iv = 0; FILETIME ft; char b[8]; DWORD n = sizeof(b);
        if (!M.gsi(0, mst, 20, &si)) {
            if (!M.sgp(si, 14, &t, &iv, &ft, b, &n)) ver = iv;
            if (ver > 200) { M.ssp(si, 14, VT_I4, 200, NULL, NULL); M.persist(si); }
            M.ch(si);
        }
    }
    return ver;
}

/* does this patch need Windows Installer 3 (a transform with minimum version > 200)? */
static BOOL needs_msi3(const char *msp)
{
    char list[512], *p, *q, tmp[MAX_PATH], dir[MAX_PATH]; WCHAR wp[MAX_PATH]; IStorage *stg = NULL; BOOL need = FALSE;
    if (!transforms(msp, list, sizeof(list))) return FALSE;
    MultiByteToWideChar(CP_ACP, 0, msp, -1, wp, MAX_PATH);
    if (FAILED(M.sos(wp, NULL, STGM_READ | STGM_SHARE_DENY_WRITE, NULL, 0, &stg))) return FALSE;
    if (GetTempPathA(MAX_PATH, dir) && GetTempFileNameA(dir, "KXT", 0, tmp))
        for (p = list; p && *p && !need; p = q ? q + 1 : NULL) {
            if (*p == ':') p++;
            q = chr(p, ';'); if (q) *q = 0;
            if (extract_transform(stg, p, tmp) > 200) need = TRUE;
        }
    DeleteFileA(tmp);
    IStorage_Release(stg);
    return need;
}

/* file names in a cabinet, in the cabinet's order (CFHEADER/CFFILE); names[i] points into buf */
static int cab_names(const char *path, char *buf, int cb, char **names, int max)
{
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    BYTE h[36]; DWORD got, off; int n = 0, cf, i, used = 0;
    if (f == INVALID_HANDLE_VALUE) return 0;
    if (!ReadFile(f, h, 36, &got, NULL) || got != 36 || memcmp(h, "MSCF", 4)) { CloseHandle(f); return 0; }
    off = h[16] | (h[17] << 8) | (h[18] << 16) | ((DWORD)h[19] << 24);
    cf = h[28] | (h[29] << 8);
    SetFilePointer(f, (LONG)off, NULL, FILE_BEGIN);
    for (i = 0; i < cf && n < max; i++) {
        BYTE e[16]; char c; int k = 0;
        if (!ReadFile(f, e, 16, &got, NULL) || got != 16) break;
        names[n] = buf + used;
        while (ReadFile(f, &c, 1, &got, NULL) && got && c) if (used + k < cb - 1) buf[used + k++] = c;
        buf[used + k] = 0; used += k + 1; n++;
        if (used >= cb - 260) break;
    }
    CloseHandle(f);
    return n;
}

/* the merged package for pkg + patches; FALSE if it cannot be made */
static BOOL merge(const char *pkg, char patches[][MAX_PATH], int np, char *out)
{
    MH db; UINT e; int i; char dir[MAX_PATH], *base, cab[MAX_PATH], tmp[MAX_PATH], tdir[MAX_PATH];
    static char cabs[16][MAX_PATH]; int ncab = 0;
    if (!GetWindowsDirectoryA(dir, MAX_PATH - 40)) return FALSE;
    lstrcatA(dir, "\\KEXMSI"); CreateDirectoryA(dir, NULL);
    base = rchr(pkg, '\\'); base = base ? base + 1 : (char *)pkg;
    lstrcpyA(out, dir); lstrcatA(out, "\\"); lstrcatA(out, base);
    {   char *dot = rchr(out, '.'); if (dot && dot > rchr(out, '\\')) *dot = 0; lstrcatA(out, "_kx98p.msi"); }
    if (!CopyFileA(pkg, out, FALSE)) return FALSE;
    SetFileAttributesA(out, FILE_ATTRIBUTE_NORMAL);
    if (!GetTempPathA(MAX_PATH, tdir) || !GetTempFileNameA(tdir, "KXT", 0, tmp)) return FALSE;
    if ((e = M.odb(out, (LPCSTR)(ULONG_PTR)1 /* TRANSACT */, &db))) { kex_crashnote("MSI 3 patches: cannot open the package copy (error)", e, 0, 0, 0); return FALSE; }
    for (i = 0; i < np; i++) {
        char list[512], *p, *q; WCHAR wp[MAX_PATH]; IStorage *stg = NULL; MH pdb, v, r;
        if (!transforms(patches[i], list, sizeof(list))) continue;
        MultiByteToWideChar(CP_ACP, 0, patches[i], -1, wp, MAX_PATH);
        if (SUCCEEDED(M.sos(wp, NULL, STGM_READ | STGM_SHARE_DENY_WRITE, NULL, 0, &stg))) {
            for (p = list; p && *p; p = q ? q + 1 : NULL) {
                if (*p == ':') p++;
                q = chr(p, ';'); if (q) *q = 0;
                if (extract_transform(stg, p, tmp) >= 0) { e = M.at(db, tmp, 0x3F /* every validation error ignored */);
                    {   static LONG k; if (InterlockedIncrement(&k) <= 40) kex_crashnote("MSI 3 patches: transform applied to the merged package (patch #, result)", (DWORD)i, e, 0, 0); } }
            }
            IStorage_Release(stg);
        }
        /* the patch's cabinet streams (names are MSI-encoded in the file: read them through the MSI API) */
        if (!M.odb(patches[i], (LPCSTR)(ULONG_PTR)32 /* READONLY | PATCHFILE */, &pdb)) {
            if (!M.ov(pdb, "SELECT `Name`, `Data` FROM `_Streams`", &v) && !M.ve(v, 0)) {
                while (!M.vf(v, &r)) {
                    char an[128]; DWORD n = sizeof(an); an[0] = 0; M.rgs(r, 1, an, &n);
                    if (an[0] > ' ' && ncab < 16) {
                        HANDLE f; char buf[32768]; DWORD got, put;
                        lstrcpyA(cab, tdir); lstrcatA(cab, "kx98p"); cat_num(cab, ncab); lstrcatA(cab, ".cab");
                        f = CreateFileA(cab, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
                        if (f != INVALID_HANDLE_VALUE) {
                            do { got = sizeof(buf); if (M.rrs(r, 2, buf, &got) || !got) break; WriteFile(f, buf, got, &put, NULL); } while (got);
                            CloseHandle(f);
                            {   MH ir = M.cr(2); char nn[64]; lstrcpyA(nn, "KX98P_CAB"); cat_num(nn, ncab);
                                M.rss(ir, 1, nn); e = M.rsst(ir, 2, cab);
                                if (!e) e = exec(db, "INSERT INTO `_Streams` (`Name`, `Data`) VALUES (?, ?)", ir);
                                M.ch(ir);
                                if (!e) lstrcpyA(cabs[ncab++], cab); else DeleteFileA(cab);
                            }
                        }
                    }
                    M.ch(r);
                }
                M.vc(v); M.ch(v);
            }
            M.ch(pdb);
        }
        exec(db, "DELETE FROM `Media` WHERE `DiskId` >= 100 AND `DiskId` < 200", 0);   /* the patch's own Media row */
    }
    DeleteFileA(tmp);
    {   /* number every cabinet's files once, last cabinet wins; one Media row each */
        static char nbuf[128 * 1024]; static char *names[4096]; int c, k, nn, next = 2000; MH uv;
        for (c = 0; c < ncab; c++) {
            int first = next; char cn[64];
            nn = cab_names(cabs[c], nbuf, sizeof(nbuf), names, 4096);
            /* the file now comes from this cabinet: its sequence, and the Compressed attribute (a package whose
             * summary says "uncompressed" would otherwise look for it as a loose file next to the package) */
            if (!M.ov(db, "SELECT `Sequence`, `Attributes` FROM `File` WHERE `File` = ?", &uv)) {
                for (k = 0; k < nn; k++) {
                    MH ur = M.cr(1), fr; M.rss(ur, 1, names[k]);
                    if (!M.ve(uv, ur) && !M.vf(uv, &fr)) {
                        int a = M.rgi(fr, 2); if (a == (int)0x80000000) a = 0;
                        M.rsi(fr, 1, next + k); M.rsi(fr, 2, (a & ~0x2000) | 0x4000);   /* Noncompressed off, Compressed on */
                        M.vm(uv, 2 /* MSIMODIFY_UPDATE */, fr); M.ch(fr);
                    }
                    M.vc(uv); M.ch(ur);
                }
                M.ch(uv);
            }
            next += nn;
            {   MH ir = M.cr(6); lstrcpyA(cn, "#KX98P_CAB"); cat_num(cn, c);
                M.rsi(ir, 1, 300 + c); M.rsi(ir, 2, next - 1); M.rss(ir, 4, cn);
                e = exec(db, "INSERT INTO `Media` (`DiskId`, `LastSequence`, `DiskPrompt`, `Cabinet`, `VolumeLabel`, `Source`) VALUES (?, ?, ?, ?, ?, ?)", ir);
                M.ch(ir);
            }
            kex_crashnote("MSI 3 patches: cabinet merged (cabinet #, files, first sequence, Media insert result)", (DWORD)c, (DWORD)nn, (DWORD)first, e);
            DeleteFileA(cabs[c]);
        }
    }
    e = M.commit(db); M.ch(db);
    kex_crashnote("MSI 3 patches: merged package written (patches, cabinets, commit result, -)", (DWORD)np, (DWORD)ncab, e, 0);
    return e == 0;
}

/* an install command line with PATCH= naming Windows Installer 3 patches: merge them into the package.
 * TRUE: *newpkg is the merged package, newcmd the command line without PATCH= (heap, caller frees). */
BOOL kex_slip_install(LPCWSTR pkg, LPCWSTR cmd, WCHAR *newpkg, WCHAR **newcmd)
{
    static char patches[16][MAX_PATH]; int np = 0; const WCHAR *p, *s, *e; char apkg[MAX_PATH], out[MAX_PATH]; int i, need = 0;
    WCHAR *nc; int n;
    if (!pkg || !cmd || IsBadStringPtrW(cmd, 32767) || !api()) return FALSE;
    for (p = cmd; *p; p++)
        if ((p == cmd || p[-1] == L' ') && (p[0] | 32) == 'p' && (p[1] | 32) == 'a' && (p[2] | 32) == 't' && (p[3] | 32) == 'c' && (p[4] | 32) == 'h' && p[5] == L'=') break;
    if (!*p) return FALSE;
    s = p; p += 6;
    {   int q = *p == L'"'; if (q) p++;
        while (*p && (q ? *p != L'"' : *p != L' ') && np < 16) {
            WCHAR one[MAX_PATH]; int k = 0;
            while (*p && *p != L';' && (q ? *p != L'"' : *p != L' ') && k < MAX_PATH - 1) one[k++] = *p++;
            one[k] = 0;
            if (k && WideCharToMultiByte(CP_ACP, 0, one, -1, patches[np], MAX_PATH, NULL, NULL)) np++;
            if (*p == L';') p++;
        }
        if (q && *p == L'"') p++;
    }
    e = p;
    for (i = 0; i < np; i++) if (needs_msi3(patches[i])) need = 1;
    if (!need || !WideCharToMultiByte(CP_ACP, 0, pkg, -1, apkg, MAX_PATH, NULL, NULL)) return FALSE;
    if (!merge(apkg, patches, np, out)) return FALSE;
    n = lstrlenW(cmd);
    if (!(nc = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(WCHAR)))) return FALSE;
    CopyMemory(nc, cmd, (s - cmd) * sizeof(WCHAR)); lstrcpyW(nc + (s - cmd), e);
    MultiByteToWideChar(CP_ACP, 0, out, -1, newpkg, MAX_PATH);
    *newcmd = nc;
    return TRUE;
}

/* MsiDetermineApplicablePatches (Windows Installer 3.0): patch files apply, in the order given */
typedef struct { LPCWSTR data; int type; DWORD order; UINT status; } KSEQW;
typedef struct { LPCSTR data; int type; DWORD order; UINT status; } KSEQA;
UINT KEXAPI kex_MsiDetermineApplicablePatchesW(LPCWSTR pkg, DWORD count, KSEQW *info)
{
    DWORD i, k = 0;
    if (!pkg || !count || !info || IsBadWritePtr(info, count * sizeof(*info))) return ERROR_INVALID_PARAMETER;
    for (i = 0; i < count; i++)
        if (info[i].data) { info[i].order = k++; info[i].status = ERROR_SUCCESS; }   /* the setup passes names it resolves itself */
        else { info[i].order = (DWORD)-1; info[i].status = ERROR_PATCH_TARGET_NOT_FOUND; }
    {   static LONG n; if (InterlockedIncrement(&n) <= 5) kex_crashnote("MSI: MsiDetermineApplicablePatchesW (Windows Installer 3) - patch files reported applicable (count, applicable, -, -)", count, k, 0, 0); }
    return ERROR_SUCCESS;
}
UINT KEXAPI kex_MsiDetermineApplicablePatchesA(LPCSTR pkg, DWORD count, KSEQA *info)
{
    DWORD i, k = 0;
    if (!pkg || !count || !info || IsBadWritePtr(info, count * sizeof(*info))) return ERROR_INVALID_PARAMETER;
    for (i = 0; i < count; i++)
        if (info[i].data) { info[i].order = k++; info[i].status = ERROR_SUCCESS; }
        else { info[i].order = (DWORD)-1; info[i].status = ERROR_PATCH_TARGET_NOT_FOUND; }
    return ERROR_SUCCESS;
}
