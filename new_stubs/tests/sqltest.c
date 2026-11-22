/* sqltest.c - SQLite the way Chromium uses it, on Windows 98 + KernelEx-NG (2026-11-10, build 24).
 *
 * Chromium's profile databases (History, Web Data, Login Data, Affiliation Database, ...) are SQLite with:
 * memory-mapped reads (PRAGMA mmap_size=256 MB), exclusive locking mode, TRUNCATE journal, 4 KB pages
 * (sql/database.cc). On Win98 they fail ("Profile error occurred", "Failed to set up eq_classes table").
 * This program runs the same sequence with SQLite's own Windows layer (NT code path: SQLITE_WIN32_GETVERSIONEX=0,
 * so W functions and LockFileEx, as in Chromium) and logs every SQLite error together with SQLite's own
 * OS-level log lines (which name the failing Windows call and its error code).
 * Output: SQLTEST.LOG next to the program.  SQLite is public domain (sqlite.org).
 */
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "sqlite3.h"

/* build 132: be a modern program for kexnt's gate (gate_ext.c), like KEXTEST: a subsystem-4.0 tool otherwise gets
 * KernelEx 4.5's old functions (exclusive LockFileEx) and does not test kexnt at all */
__declspec(dllexport) int KexNG_ModernProcess = 1;
static FILE *g_log;
static int g_pass, g_fail;
static void LOG(const char *f, ...)
{
    va_list a; va_start(a, f); vfprintf(stdout, f, a); va_end(a);
    if (g_log) { va_start(a, f); vfprintf(g_log, f, a); va_end(a); fflush(g_log); }
}
static void sqlog(void *u, int code, const char *msg) { (void)u; LOG("    sqlite log: (%d) %s\n", code, msg); }

static int run(sqlite3 *db, const char *what, const char *sql)
{
    char *err = NULL;
    int r = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (r == SQLITE_OK) { g_pass++; return 1; }
    g_fail++;
    LOG("  FAIL %s: %d / extended %d: %s\n", what, r, sqlite3_extended_errcode(db), err ? err : sqlite3_errmsg(db));
    sqlite3_free(err);
    return 0;
}

static long long scalar(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st; long long v = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) { LOG("  FAIL prepare %s: %s\n", sql, sqlite3_errmsg(db)); g_fail++; return -1; }
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    else { LOG("  FAIL step %s: %s\n", sql, sqlite3_errmsg(db)); g_fail++; }
    sqlite3_finalize(st);
    return v;
}

static void one_round(const char *path, int mmap, int wal)
{
    sqlite3 *db = NULL; char p[600]; int i, r; long long n;
    LOG("[%s, mmap %s, %s]\n", path, mmap ? "on" : "off", wal ? "WAL" : "exclusive + TRUNCATE journal");
    for (i = 0; i < 4; i++) {
        static const char *sfx[] = { "", "-journal", "-wal", "-shm" };
        sprintf(p, "%s%s", path, sfx[i]); DeleteFileA(p);
    }
    r = sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (r != SQLITE_OK) { LOG("  FAIL open: %d %s\n", r, db ? sqlite3_errmsg(db) : "?"); g_fail++; sqlite3_close(db); return; }
    g_pass++;
    run(db, "page_size", "PRAGMA page_size=4096");
    run(db, "cache_size", "PRAGMA cache_size=500");
    if (wal) run(db, "journal_mode=WAL", "PRAGMA journal_mode=WAL");
    else {
        run(db, "locking_mode=EXCLUSIVE", "PRAGMA locking_mode=EXCLUSIVE");
        run(db, "journal_mode=TRUNCATE", "PRAGMA journal_mode=TRUNCATE");
    }
    if (mmap) run(db, "mmap_size", "PRAGMA mmap_size=268435456");
    run(db, "foreign_keys", "PRAGMA foreign_keys=1");
    if (run(db, "create meta", "CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)") &&
        run(db, "insert meta", "INSERT INTO meta(key,value) VALUES('version','6'),('last_compatible_version','1')"))
        LOG("    meta table written\n");
    run(db, "create eq_classes", "CREATE TABLE eq_classes(id INTEGER PRIMARY KEY, last_update_time INTEGER)");
    run(db, "create members", "CREATE TABLE eq_class_members(id INTEGER PRIMARY KEY, facet_uri LONGVARCHAR NOT NULL UNIQUE ON CONFLICT REPLACE,"
                              " set_id INTEGER NOT NULL REFERENCES eq_classes(id) ON DELETE CASCADE)");
    run(db, "index", "CREATE INDEX index_on_eq_class_members_set_id ON eq_class_members (set_id)");
    run(db, "begin", "BEGIN");
    for (i = 0; i < 2000; i++) {
        char sql[200];
        sprintf(sql, "INSERT INTO eq_classes(id,last_update_time) VALUES(%d,%d);"
                     "INSERT INTO eq_class_members(facet_uri,set_id) VALUES('https://site%05d.example/',%d)", i + 1, i * 7, i, i + 1);
        if (!run(db, "insert row", sql)) break;
    }
    run(db, "commit", "COMMIT");
    n = scalar(db, "SELECT count(*) FROM eq_class_members");
    if (n == 2000) g_pass++; else { g_fail++; LOG("  FAIL row count %I64d (2000)\n", n); }
    run(db, "update", "UPDATE eq_classes SET last_update_time = last_update_time + 1");
    run(db, "delete", "DELETE FROM eq_classes WHERE id > 1000");
    n = scalar(db, "SELECT count(*) FROM eq_class_members");
    if (n == 1000) g_pass++; else { g_fail++; LOG("  FAIL row count after cascade delete %I64d (1000)\n", n); }
    run(db, "vacuum", "VACUUM");
    n = scalar(db, "PRAGMA integrity_check") ; (void)n;
    {
        sqlite3_stmt *st; const char *t = "?";
        if (sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
            t = (const char *)sqlite3_column_text(st, 0);
        if (t && !strcmp(t, "ok")) g_pass++; else { g_fail++; LOG("  FAIL integrity_check: %s\n", t ? t : "(null)"); }
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    db = NULL;
    r = sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL);
    if (r == SQLITE_OK) {
        if (mmap) run(db, "mmap_size (reopen)", "PRAGMA mmap_size=268435456");
        n = scalar(db, "SELECT count(*) FROM eq_class_members");
        if (n == 1000) g_pass++; else { g_fail++; LOG("  FAIL row count after reopen %I64d (1000)\n", n); }
    } else { g_fail++; LOG("  FAIL reopen: %d %s\n", r, sqlite3_errmsg(db)); }
    sqlite3_close(db);
}

/* build 131: Places-like (Pale Moon/Firefox places.sqlite): 32 KB pages, WAL, a second connection reading while the
 * first writes, the first checkpointing - places.sqlite was judged corrupt at every Pale Moon start */
static void places_round(const char *path)
{
    sqlite3 *a = NULL, *b = NULL; char p[600]; int i; long long n;
    LOG("[%s, Places-like: 32 KB pages, WAL, 2 connections]\n", path);
    for (i = 0; i < 4; i++) { static const char *sfx[] = { "", "-journal", "-wal", "-shm" }; sprintf(p, "%s%s", path, sfx[i]); DeleteFileA(p); }
    if (sqlite3_open_v2(path, &a, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) { LOG("  FAIL open A\n"); g_fail++; return; }
    run(a, "page_size 32768", "PRAGMA page_size=32768");
    run(a, "cache_size", "PRAGMA cache_size=-2048");
    run(a, "temp_store", "PRAGMA temp_store=MEMORY");
    run(a, "journal_mode=WAL", "PRAGMA journal_mode=WAL");
    run(a, "wal_autocheckpoint", "PRAGMA wal_autocheckpoint=16");
    run(a, "journal_size_limit", "PRAGMA journal_size_limit=1536000");
    run(a, "foreign_keys", "PRAGMA foreign_keys=ON");
    run(a, "create", "CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0)");
    run(a, "index", "CREATE INDEX moz_places_url ON moz_places(url)");
    run(a, "user_version", "PRAGMA user_version=36");
    if (sqlite3_open_v2(path, &b, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) { LOG("  FAIL open B (read-only clone): %s\n", sqlite3_errmsg(b)); g_fail++; }
    else g_pass++;
    for (i = 0; i < 300; i++) {
        char sql[200];
        sprintf(sql, "INSERT INTO moz_places(url,title) VALUES('https://site%05d.example/','Site %d')", i, i);
        if (!run(a, "insert", sql)) break;
        if (b && !(i % 25)) { n = scalar(b, "SELECT count(*) FROM moz_places"); if (n < 0) break; }
    }
    if (b) { n = scalar(b, "SELECT count(*) FROM moz_places"); if (n == 300) g_pass++; else { g_fail++; LOG("  FAIL B sees %I64d rows (300)\n", n); } }
    run(a, "checkpoint", "PRAGMA wal_checkpoint(TRUNCATE)");
    n = scalar(a, "PRAGMA user_version"); if (n == 36) g_pass++; else { g_fail++; LOG("  FAIL user_version %I64d\n", n); }
    {
        sqlite3_stmt *st; const char *t = "?";
        if (sqlite3_prepare_v2(b ? b : a, "PRAGMA integrity_check", -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
            t = (const char *)sqlite3_column_text(st, 0);
        if (t && !strcmp(t, "ok")) g_pass++; else { g_fail++; LOG("  FAIL integrity_check: %s\n", t ? t : "(null)"); }
        sqlite3_finalize(st);
    }
    sqlite3_close(b); sqlite3_close(a);
    a = NULL;
    if (sqlite3_open_v2(path, &a, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK) {
        n = scalar(a, "SELECT count(*) FROM moz_places");
        if (n == 300) g_pass++; else { g_fail++; LOG("  FAIL count after reopen %I64d\n", n); }
    } else { g_fail++; LOG("  FAIL reopen\n"); }
    sqlite3_close(a);
    LOG("    done\n");
}

int main(void)
{
    char dir[MAX_PATH], path[MAX_PATH], *s;
    GetModuleFileNameA(NULL, dir, MAX_PATH);
    if ((s = strrchr(dir, '\\'))) s[1] = 0;
    sprintf(path, "%sSQLTEST.LOG", dir);
    g_log = fopen(path, "w");
    sqlite3_config(SQLITE_CONFIG_LOG, sqlog, NULL);
    LOG("sqltest: SQLite %s, Windows layer on the NT path (as in Chromium)\n", sqlite3_libversion());
    GetTempPathA(MAX_PATH, dir);
    sprintf(path, "%skxsql_a.db", dir); one_round(path, 0, 0);
    sprintf(path, "%skxsql_b.db", dir); one_round(path, 1, 0);
    sprintf(path, "%skxsql_c.db", dir); one_round(path, 1, 1);
    sprintf(path, "%skxsql_d.db", dir); places_round(path);
    LOG("\n%d passed, %d failed\n", g_pass, g_fail);
    if (g_log) fclose(g_log);
    return g_fail != 0;
}
