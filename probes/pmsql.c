/* pmsql.c - run Places' database setup (Pale Moon / Gecko 52 Database.cpp) with a program's own SQLite DLL
 * and log SQLite's OS-level error lines. Usage: PMSQL <sqlite dll> <db path>   -> PMSQL.LOG next to the exe.
 * A modern program for kexnt's gate (KexNG_ModernProcess), like the browser. */
#include <windows.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
typedef int (*T_CFG)(int, ...); typedef int (*T_OPEN)(const char *, void **, int, const char *);
typedef int (*T_EXEC)(void *, const char *, void *, void *, char **); typedef const char *(*T_ERR)(void *);
typedef int (*T_INIT)(void);
static FILE *g; static void lg(void *u, int c, const char *m) { fprintf(g, "  sqlite log (%d): %s\n", c, m); fflush(g); }
int main(int argc, char **argv)
{
    HMODULE h; T_CFG cfg; T_OPEN op; T_EXEC ex; T_ERR er; T_INIT in; void *db = NULL; int i, r; char *e;
    static const char *sql[] = { "PRAGMA page_size = 32768", "PRAGMA page_size", "PRAGMA temp_store = MEMORY",
        "PRAGMA journal_mode = wal", "PRAGMA wal_autocheckpoint = 16", "PRAGMA journal_size_limit = 1536000",
        "PRAGMA busy_timeout = 100",
        "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR)",
        "INSERT INTO moz_places (url) VALUES ('about:blank')", "SELECT count(*) FROM moz_places", NULL };
    char lp[MAX_PATH]; GetModuleFileNameA(NULL, lp, MAX_PATH); strcpy(strrchr(lp, '\\') + 1, "PMSQL.LOG");
    g = fopen(lp, "w");
    if (argc < 3) { fprintf(g, "usage\n"); return 1; }
    {   /* load the DLL's own dependencies from its folder first, one by one, to see which one fails */
        static const char *dep[] = { "VCRUNTIME140.DLL", "mozglue.dll", NULL }; char d[MAX_PATH]; int k;
        for (k = 0; dep[k]; k++) { HMODULE m; strcpy(d, argv[1]); strcpy(strrchr(d, '\\') + 1, dep[k]);
            m = LoadLibraryExA(d, NULL, 8); fprintf(g, "  dependency %s -> %p (%lu)\n", d, (void *)m, m ? 0 : GetLastError()); fflush(g); }
    }
    h = LoadLibraryExA(argv[1], NULL, 8 /*LOAD_WITH_ALTERED_SEARCH_PATH*/);
    fprintf(g, "LoadLibrary %s -> %p (%lu)\n", argv[1], (void *)h, h ? 0 : GetLastError());
    if (!h) return 2;
    cfg = (T_CFG)GetProcAddress(h, "sqlite3_config"); op = (T_OPEN)GetProcAddress(h, "sqlite3_open_v2");
    ex = (T_EXEC)GetProcAddress(h, "sqlite3_exec"); er = (T_ERR)GetProcAddress(h, "sqlite3_errmsg");
    in = (T_INIT)GetProcAddress(h, "sqlite3_initialize");
    if (!op || !ex || !er) { fprintf(g, "exports missing\n"); return 3; }
    if (cfg) fprintf(g, "config log: %d\n", cfg(16 /*SQLITE_CONFIG_LOG*/, lg, (void *)0));
    if (in) in();
    DeleteFileA(argv[2]);
    r = op(argv[2], &db, 6 /*READWRITE|CREATE*/, NULL);
    fprintf(g, "open %s: %d %s\n", argv[2], r, db ? er(db) : "");
    for (i = 0; db && sql[i]; i++) { e = NULL; r = ex(db, sql[i], NULL, NULL, &e); fprintf(g, "%-60s -> %d %s\n", sql[i], r, r ? er(db) : "ok"); fflush(g); }
    fclose(g); return 0;
}
