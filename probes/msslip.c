/* msslip.c - probe: slipstream MSI 3.x patches (.msp) into a copy of their target package with Windows Installer 2.0's own
 * database API, so that Windows 98's MSI 2.0 can install the result without patching. Test for the .NET 3.5 SP1 setup's
 * .NET 2.0 SP2 component (netfx20a_x86.msi + 9 patches, MSI 2.0 refuses the patches: transform version 301 > 200).
 *   MSSLIP.EXE log.txt out.msi base.msi patch1.msp [patch2.msp ...]
 * For each patch: every transform substorage named in the patch summary (PID_LASTSAVED_BY, ":T1;:#T1") is copied to a
 * .mst file, its minimum installer version (summary PID 14) lowered to 200 if higher, and applied with every validation
 * error ignored; each embedded cabinet stream of the patch is added to the package under a name unique to the patch,
 * and the Media rows that point to it are renamed accordingly. Then table row counts are logged. */
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <msi.h>
#include <msiquery.h>
#include <stdio.h>
#pragma comment(lib, "msi")

static FILE *g_log;
#define LOG(...) do { fprintf(g_log, __VA_ARGS__); fflush(g_log); } while (0)

static int count(MSIHANDLE db, const char *table)
{
    char q[128]; MSIHANDLE v, r; int n = 0;
    sprintf(q, "SELECT * FROM `%s`", table);
    if (MsiDatabaseOpenViewA(db, q, &v) || MsiViewExecute(v, 0)) return -1;
    while (!MsiViewFetch(v, &r)) { n++; MsiCloseHandle(r); }
    MsiCloseHandle(v);
    return n;
}

/* copy substorage `name` of `stg` into a new compound file `path`; lower summary PID 14 to 200 */
static BOOL extract_transform(IStorage *stg, const WCHAR *name, const char *path)
{
    IStorage *sub = NULL, *dst = NULL; WCHAR wp[MAX_PATH]; HRESULT hr; BOOL ok = FALSE;
    MultiByteToWideChar(CP_ACP, 0, path, -1, wp, MAX_PATH);
    hr = IStorage_OpenStorage(stg, name, NULL, STGM_READ | STGM_SHARE_EXCLUSIVE, NULL, 0, &sub);
    if (FAILED(hr)) { LOG("  open substorage %ls: %08lx\n", name, hr); return FALSE; }
    hr = StgCreateDocfile(wp, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, &dst);
    if (SUCCEEDED(hr)) { hr = IStorage_CopyTo(sub, 0, NULL, NULL, dst); if (SUCCEEDED(hr)) { IStorage_Commit(dst, 0); ok = TRUE; } IStorage_Release(dst); }
    IStorage_Release(sub);
    if (!ok) { LOG("  copy %ls -> %s: %08lx\n", name, path, hr); return FALSE; }
    {   MSIHANDLE si; INT iv; FILETIME ft; char b[8]; DWORD n = sizeof(b); UINT t;
        if (!MsiGetSummaryInformationA(0, path, 20, &si)) {
            if (!MsiSummaryInfoGetPropertyA(si, 14, &t, &iv, &ft, b, &n)) {
                LOG("  %ls: minimum installer version %d\n", name, iv);
                if (iv > 200) { MsiSummaryInfoSetPropertyA(si, 14, VT_I4, 200, NULL, NULL); MsiSummaryInfoPersist(si); LOG("    lowered to 200\n"); }
            }
            MsiCloseHandle(si);
        }
    }
    return TRUE;
}


/* names of the files in a cabinet, in the cabinet's order (CFHEADER / CFFILE) */
static int cab_names(const char *path, char names[][128], int max)
{
    FILE *f = fopen(path, "rb"); unsigned char h[36]; long off; int n = 0, cf, i; unsigned short flags;
    if (!f) return 0;
    if (fread(h, 1, 36, f) != 36 || memcmp(h, "MSCF", 4)) { fclose(f); return 0; }
    off = h[16] | (h[17] << 8) | (h[18] << 16) | ((long)h[19] << 24);
    cf = h[28] | (h[29] << 8); flags = (unsigned short)(h[30] | (h[31] << 8));
    (void)flags;
    fseek(f, off, SEEK_SET);
    for (i = 0; i < cf && n < max; i++) {
        unsigned char e[16]; int c, k = 0;
        if (fread(e, 1, 16, f) != 16) break;
        while ((c = fgetc(f)) > 0) if (k < 127) names[n][k++] = (char)c;
        names[n][k] = 0; n++;
    }
    fclose(f);
    return n;
}

static void add_stream(MSIHANDLE db, const char *name, const char *file)
{
    MSIHANDLE v, r = MsiCreateRecord(2); UINT e;
    MsiRecordSetStringA(r, 1, name); e = MsiRecordSetStreamA(r, 2, file);
    if (!e && !(e = MsiDatabaseOpenViewA(db, "INSERT INTO `_Streams` (`Name`, `Data`) VALUES (?, ?)", &v))) { e = MsiViewExecute(v, r); MsiCloseHandle(v); }
    LOG("  stream %s from %s: %u\n", name, file, e);
    MsiCloseHandle(r);
}

int main(int argc, char **argv)
{
    MSIHANDLE db; UINT e; int i;
    if (argc < 5 || !(g_log = fopen(argv[1], "w"))) return 1;
    CoInitialize(NULL);
    if (!CopyFileA(argv[3], argv[2], FALSE)) { LOG("copy base failed %lu\n", GetLastError()); return 2; }
    SetFileAttributesA(argv[2], FILE_ATTRIBUTE_NORMAL);
    if ((e = MsiOpenDatabaseA(argv[2], MSIDBOPEN_TRANSACT, &db))) { LOG("open db %u\n", e); return 3; }
    LOG("base: File %d Media %d Component %d\n", count(db, "File"), count(db, "Media"), count(db, "Component"));
    for (i = 4; i < argc; i++) {
        WCHAR wp[MAX_PATH], tn[64]; IStorage *stg = NULL; HRESULT hr; char trans[512]; DWORD n = sizeof(trans); MSIHANDLE si; UINT t; INT iv; FILETIME ft;
        LOG("== %s\n", argv[i]);
        if (MsiGetSummaryInformationA(0, argv[i], 0, &si) || MsiSummaryInfoGetPropertyA(si, 8, &t, &iv, &ft, trans, &n)) { LOG("  no summary\n"); continue; }
        MsiCloseHandle(si);
        LOG("  transforms %s\n", trans);
        MultiByteToWideChar(CP_ACP, 0, argv[i], -1, wp, MAX_PATH);
        hr = StgOpenStorage(wp, NULL, STGM_READ | STGM_SHARE_DENY_WRITE, NULL, 0, &stg);
        if (FAILED(hr)) { LOG("  StgOpenStorage %08lx\n", hr); continue; }
        {   char *p = trans, *q;
            while (p && *p) {
                char mst[MAX_PATH]; if (*p == ':') p++;
                q = strchr(p, ';'); if (q) *q = 0;
                MultiByteToWideChar(CP_ACP, 0, p, -1, tn, 64);
                sprintf(mst, "C:\\SLIP%d_%s.MST", i, *p == '#' ? "P" : "D");
                if (extract_transform(stg, tn, mst)) {
                    e = MsiDatabaseApplyTransformA(db, mst, 0x3F /* ignore every error */);
                    LOG("  apply %s: %u\n", p, e);
                }
                p = q ? q + 1 : NULL;
            }
        }
        {   /* this patch's files: File rows whose Sequence changed with it -> own range, own Media row, own cabinet */
            MSIHANDLE pdb, v, r; char an[128], file[MAX_PATH], nn[160], q2[300]; DWORD n2; UINT e2;
            int minseq = 0x7FFFFFFF, maxseq = 0, cnt = 0;
            /* the cabinets, through the MSI API (stream names in the file are MSI-encoded) */
            if (!MsiOpenDatabaseA(argv[i], (LPCSTR)(ULONG_PTR)(0 /* READONLY */ | 32 /* MSIDBOPEN_PATCHFILE */), &pdb)) {
                if (!MsiDatabaseOpenViewA(pdb, "SELECT `Name`, `Data` FROM `_Streams`", &v) && !MsiViewExecute(v, 0)) {
                    while (!MsiViewFetch(v, &r)) {
                        n2 = sizeof(an); an[0] = 0; MsiRecordGetStringA(r, 1, an, &n2);
                        if (an[0] > ' ' && an[0] != 5) {
                            FILE *o; char buf[65536]; DWORD got;
                            sprintf(file, "C:\\SLIP%d.CAB", i); sprintf(nn, "%s_%d", an, i);
                            if ((o = fopen(file, "wb"))) {
                                do { got = sizeof(buf); if (MsiRecordReadStream(r, 2, buf, &got) || !got) break; fwrite(buf, 1, got, o); } while (got);
                                fclose(o);
                                add_stream(db, nn, file);
                            }
                        }
                        MsiCloseHandle(r);
                    }
                    MsiCloseHandle(v);
                } else LOG("  _Streams of the patch: cannot query\n");
                MsiCloseHandle(pdb);
            } else LOG("  open patch as database failed\n");
            /* the patch's media row (DiskId 101 in every .NET patch) and its files */
            if (!MsiDatabaseOpenViewA(db, "SELECT `DiskId`, `LastSequence`, `Cabinet` FROM `Media` WHERE `DiskId` >= 100 AND `DiskId` < 200", &v) && !MsiViewExecute(v, 0)) {
                while (!MsiViewFetch(v, &r)) { n2 = sizeof(an); MsiRecordGetStringA(r, 3, an, &n2); LOG("  patch media %d last %d %s\n", MsiRecordGetInteger(r, 1), MsiRecordGetInteger(r, 2), an); MsiCloseHandle(r); }
                MsiCloseHandle(v);
            }
            if (!MsiDatabaseOpenViewA(db, "SELECT `Sequence` FROM `File` WHERE `Sequence` > 1000 AND `Sequence` < 2000", &v) && !MsiViewExecute(v, 0)) {
                while (!MsiViewFetch(v, &r)) { int sq = MsiRecordGetInteger(r, 1); if (sq < 100000) { if (sq < minseq) minseq = sq; if (sq > maxseq) maxseq = sq; cnt++; } MsiCloseHandle(r); }
                MsiCloseHandle(v);
            }
            LOG("  files of this patch: %d, sequence %d..%d\n", cnt, minseq, maxseq);
            if (cnt) {
                static int next_free = 2000; int base;            /* compact ranges above every patch range (1001..1211) */
                {   MSIHANDLE dv; if (!MsiDatabaseOpenViewA(db, "DELETE FROM `Media` WHERE `DiskId` = 101", &dv)) { e2 = MsiViewExecute(dv, 0); MsiCloseHandle(dv); LOG("  media 101 deleted: %u\n", e2); } }
                (void)base;
            }
        }
        IStorage_Release(stg);
        LOG("  now: File %d Media %d Patch %d PatchPackage %d MsiPatchSequence %d\n", count(db, "File"), count(db, "Media"), count(db, "Patch"), count(db, "PatchPackage"), count(db, "MsiPatchSequence"));
    }
    {   MSIHANDLE v, r; char cab[128], ls[16]; DWORD n;
        if (!MsiDatabaseOpenViewA(db, "SELECT `DiskId`, `LastSequence`, `Cabinet` FROM `Media`", &v) && !MsiViewExecute(v, 0)) {
            while (!MsiViewFetch(v, &r)) { n = sizeof(cab); cab[0] = 0; MsiRecordGetStringA(r, 3, cab, &n); LOG("Media %d last %d %s\n", MsiRecordGetInteger(r, 1), MsiRecordGetInteger(r, 2), cab); MsiCloseHandle(r); }
            MsiCloseHandle(v);
        }
        (void)ls;
    }
    {   /* all transforms applied: number the files by the cabinets that hold them (later patches win), one Media row each */
        static char keys[4096][128]; int k, nk, next_free = 2000; MSIHANDLE uv, iv; UINT e3;
        for (i = 4; i < argc; i++) {
            char cabf[MAX_PATH], cabn[64]; int base = next_free; UINT fails = 0;
            sprintf(cabf, "C:\\SLIP%d.CAB", i); sprintf(cabn, "#PCW_CAB_NetFX_%d", i);
            nk = cab_names(cabf, keys, 4096);
            if (!nk) continue;
            if (!MsiDatabaseOpenViewA(db, "UPDATE `File` SET `Sequence` = ? WHERE `File` = ?", &uv)) {
                for (k = 0; k < nk; k++) { MSIHANDLE ur = MsiCreateRecord(2); MsiRecordSetInteger(ur, 1, base + k); MsiRecordSetStringA(ur, 2, keys[k]); if (MsiViewExecute(uv, ur)) fails++; MsiViewClose(uv); MsiCloseHandle(ur); }
                MsiCloseHandle(uv);
            }
            next_free = base + nk;
            if (!MsiDatabaseOpenViewA(db, "INSERT INTO `Media` (`DiskId`, `LastSequence`, `DiskPrompt`, `Cabinet`, `VolumeLabel`, `Source`) VALUES (?, ?, ?, ?, ?, ?)", &iv)) {
                MSIHANDLE ir = MsiCreateRecord(6);
                MsiRecordSetInteger(ir, 1, 200 + i); MsiRecordSetInteger(ir, 2, next_free - 1); MsiRecordSetStringA(ir, 4, cabn);
                e3 = MsiViewExecute(iv, ir); MsiCloseHandle(ir); MsiCloseHandle(iv);
                LOG("cabinet %s: %d files -> %d..%d (%u failed), media %d: %u\n", cabn, nk, base, next_free - 1, fails, 200 + i, e3);
            }
        }
    }
    {   MSIHANDLE v, r; char key[160]; DWORD kn; int left = 0;
        if (!MsiDatabaseOpenViewA(db, "SELECT `File`, `Sequence` FROM `File` WHERE `Sequence` > 500 AND `Sequence` < 2000", &v) && !MsiViewExecute(v, 0)) {
            while (!MsiViewFetch(v, &r)) { kn = sizeof(key); MsiRecordGetStringA(r, 1, key, &kn); if (left++ < 10) LOG("not in any cabinet: %s (%d)\n", key, MsiRecordGetInteger(r, 2)); MsiCloseHandle(r); }
            MsiCloseHandle(v);
        }
        LOG("files not in any cabinet: %d\n", left);
    }
    e = MsiDatabaseCommit(db); LOG("commit %u\n", e);
    MsiCloseHandle(db);
    return 0;
}
