/* msiq.c - MSIQ.EXE <out> <msi> <sql>...: run SELECT queries through Windows Installer and print the rows (Windows 4.0 program) */
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); MSIHANDLE db = 0; UINT r; int i;
    r = MsiOpenDatabaseA(argv[2], MSIDBOPEN_READONLY, &db); fprintf(o, "open %u\n", r);
    for (i = 3; i < argc && !r; i++) {
        MSIHANDLE v = 0, rec = 0; UINT q = MsiDatabaseOpenViewA(db, argv[i], &v);
        fprintf(o, "== %s -> %u\n", argv[i], q);
        if (q) continue;
        MsiViewExecute(v, 0);
        while (MsiViewFetch(v, &rec) == ERROR_SUCCESS) {
            UINT n = MsiRecordGetFieldCount(rec), k;
            for (k = 1; k <= n; k++) { char b[2048]; DWORD cb = sizeof(b); b[0] = 0; MsiRecordGetStringA(rec, k, b, &cb); fprintf(o, "%s%s", k > 1 ? " | " : "", b); }
            fprintf(o, "\n"); MsiCloseHandle(rec);
        }
        MsiCloseHandle(v);
    }
    if (db) MsiCloseHandle(db);
    fclose(o); return 0;
}
