#include "../kexng_build.h"
/*
 * kexsetup.c - installs KernelEx-NG's kexnt.dll into an existing KernelEx installation.
 *
 *   kexsetup        install / update   (run from the folder that holds kexnt.dll + api-ms-win-*.dll)
 *   kexsetup /u     uninstall
 *   kexsetup /finish  (set up automatically in RunOnce) copies files that were in use and have long names
 *
 * Install:
 *   1. copies kexnt.dll to <KernelEx dir>\KEXNT.DLL (if it is in use: scheduled via WININIT.INI)
 *   2. core.ini: backup to CORE.KNG once, then appends ",KEXNT" to every "contents=" line, so the
 *      KernelEx resolver loads kexnt.dll as an api library (last in the list = its names win)
 *   3. HKLM\Software\KernelEx\KnownDLLs  KEXNT = KEXNT.DLL  (so "kexnt.dll" imports from the
 *      api-ms forwarders find the same file in the KernelEx dir)
 *   4. copies api-ms-win-*.dll to the SYSTEM dir; the list goes to <KernelEx dir>\KEXNG.LST
 *   5. copies the stub DLLs of stub_dlls.txt (winhttp, dbghelp, ...) to SYSTEM where Windows has none
 *   6. KernelEx 4.5.2 core: shared heap 1 MB -> 8 MB (backup KERNELEX.KNG)
 * Uninstall reverses 2-4 and deletes KEXNT.DLL. A restart is needed either way (KernelEx reads
 * core.ini at boot). Log: kexsetup.log next to this program.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static FILE *g_log;
static int g_err;
#define LOG(...) do { printf(__VA_ARGS__); if (g_log) { fprintf(g_log, __VA_ARGS__); fflush(g_log); } } while (0)
#define ERR(...) do { g_err++; LOG("ERROR: " __VA_ARGS__); } while (0)

static char g_kexdir[MAX_PATH], g_srcdir[MAX_PATH], g_sysdir[MAX_PATH];

static void join(char *out, const char *dir, const char *file)
{
    size_t n = strlen(dir);
    snprintf(out, MAX_PATH, "%s%s%s", dir, (n && dir[n - 1] == '\\') ? "" : "\\", file);
}

/* Add "key=value" right after [rename] in WININIT.INI (processed by Windows on next boot, before
 * any DLL is loaded). WININIT runs in real mode: both paths must be short 8.3 paths. */
static BOOL wininit_add(const char *key, const char *value)
{
    char path[MAX_PATH], *buf = NULL, *pos;
    long size = 0;
    FILE *f;
    GetWindowsDirectoryA(path, sizeof(path));
    join(path, path, "WININIT.INI");
    if ((f = fopen(path, "rb"))) {
        fseek(f, 0, SEEK_END); size = ftell(f); fseek(f, 0, SEEK_SET);
        buf = (char *)calloc(1, size + 1);
        if (buf && fread(buf, 1, size, f) != (size_t)size) size = 0;
        fclose(f);
    }
    if (!(f = fopen(path, "wb"))) { free(buf); return FALSE; }
    pos = buf ? strstr(buf, "[rename]") : NULL;
    if (!pos && buf) pos = strstr(buf, "[Rename]");
    if (pos) {
        pos += 8;
        while (*pos == '\r' || *pos == '\n') pos++;
        fwrite(buf, 1, pos - buf, f);
        fprintf(f, "%s=%s\r\n", key, value);
        fwrite(pos, 1, size - (pos - buf), f);
    } else {
        if (buf) fwrite(buf, 1, size, f);
        fprintf(f, "\r\n[rename]\r\n%s=%s\r\n", key, value);
    }
    fclose(f);
    free(buf);
    return TRUE;
}

static BOOL short_path(const char *in, char *out)
{
    DWORD n = GetShortPathNameA(in, out, MAX_PATH);
    return n && n < MAX_PATH;
}

/* Copy src -> dst; if dst is locked (DLL loaded somewhere) stage it and replace at next boot. */
/* 8.3 base name? WININIT.INI runs in real-mode DOS before Windows and only knows short names: a long
 * name replaced through it loses its long name (bcryptprimitives.dll became just BCRYPT~1.DLL). */
static BOOL is_83(const char *path)
{
    const char *b = strrchr(path, '\\'), *dot; int n, e;
    b = b ? b + 1 : path;
    dot = strchr(b, '.');
    n = dot ? (int)(dot - b) : (int)strlen(b);
    e = dot ? (int)strlen(dot + 1) : 0;
    if (n < 1 || n > 8 || e > 3 || (dot && strchr(dot + 1, '.'))) return FALSE;
    for (; *b; b++) if (*b == ' ' || (*b >= 'a' && *b <= 'z')) return FALSE;
    return TRUE;
}

/* Long names in use: finished by "KEXSETUP /finish" from RunOnce at the next logon (inside Windows,
 * so long names survive). Pairs go to <KernelEx dir>\KEXNG.PND as "destination|staged copy". */
static BOOL pending_add(const char *dst, const char *stage)
{
    char pnd[MAX_PATH], exe[MAX_PATH], sexe[MAX_PATH], cmd[MAX_PATH + 16]; FILE *f; HKEY k;
    join(pnd, g_kexdir, "KEXNG.PND");
    if (!(f = fopen(pnd, "a"))) return FALSE;
    fprintf(f, "%s|%s\n", dst, stage);
    fclose(f);
    GetModuleFileNameA(NULL, exe, sizeof(exe));
    if (!short_path(exe, sexe)) lstrcpyA(sexe, exe);
    snprintf(cmd, sizeof(cmd), "%s /finish", sexe);
    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", &k) != ERROR_SUCCESS)
        return FALSE;
    RegSetValueExA(k, "KexNgFinish", 0, REG_SZ, (const BYTE *)cmd, (DWORD)strlen(cmd) + 1);
    RegCloseKey(k);
    return TRUE;
}

/* Files copied from the CD keep the CD's read-only attribute, and CopyFile cannot overwrite a read-only
 * file (error 5, the same code as "in use"). Clear it on every destination we write. */
/* build 39: KEXAUDIO.DLL (Core Audio over waveOut) in SYSTEM, registered as the in-process server of
 * CLSID_MMDeviceEnumerator - what Chromium and other Vista+ programs CoCreateInstance for sound. */
#define MMDEV_KEY "CLSID\\{BCDE0395-E52F-467C-8E3D-C4579291692E}"
static void audio_register(BOOL add, const char *dll)
{
    HKEY k; char old[MAX_PATH]; DWORD sz = sizeof(old), type;
    if (add) {
        if (RegOpenKeyExA(HKEY_CLASSES_ROOT, MMDEV_KEY "\\InprocServer32", 0, KEY_READ, &k) == ERROR_SUCCESS) {
            if (RegQueryValueExA(k, NULL, NULL, &type, (BYTE *)old, &sz) == ERROR_SUCCESS && !strstr(old, "KEXAUDIO") && !strstr(old, "kexaudio")) {
                RegCloseKey(k); LOG("  MMDeviceEnumerator already registered to %s - left alone\n", old); return;
            }
            RegCloseKey(k);
        }
        if (RegCreateKeyExA(HKEY_CLASSES_ROOT, MMDEV_KEY, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) == ERROR_SUCCESS) {
            RegSetValueExA(k, NULL, 0, REG_SZ, (const BYTE *)"MMDeviceEnumerator class (KernelEx-NG)", 39); RegCloseKey(k);
        }
        if (RegCreateKeyExA(HKEY_CLASSES_ROOT, MMDEV_KEY "\\InprocServer32", 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) == ERROR_SUCCESS) {
            RegSetValueExA(k, NULL, 0, REG_SZ, (const BYTE *)dll, (DWORD)strlen(dll) + 1);
            RegSetValueExA(k, "ThreadingModel", 0, REG_SZ, (const BYTE *)"Both", 5);
            RegCloseKey(k);
            LOG("  registry: MMDeviceEnumerator (Core Audio) -> %s\n", dll);
        } else ERR("cannot register MMDeviceEnumerator (error %lu)\n", GetLastError());
    } else {
        if (RegOpenKeyExA(HKEY_CLASSES_ROOT, MMDEV_KEY "\\InprocServer32", 0, KEY_READ, &k) == ERROR_SUCCESS) {
            BOOL ours = RegQueryValueExA(k, NULL, NULL, &type, (BYTE *)old, &sz) == ERROR_SUCCESS && (strstr(old, "KEXAUDIO") || strstr(old, "kexaudio"));
            RegCloseKey(k);
            if (!ours) return;
        }
        RegDeleteKeyA(HKEY_CLASSES_ROOT, MMDEV_KEY "\\InprocServer32");
        RegDeleteKeyA(HKEY_CLASSES_ROOT, MMDEV_KEY);
        LOG("  registry: MMDeviceEnumerator registration removed\n");
    }
}

static void make_writable(const char *path)
{
    DWORD a = GetFileAttributesA(path);
    if (a != 0xFFFFFFFF && (a & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)))
        SetFileAttributesA(path, a & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM));
}

/* build 54: same content already installed? (a file Windows keeps loaded - e.g. a .cpl while Explorer or the
 * Control Panel shows it - cannot be replaced, and need not be) */
static BOOL same_content(const char *a, const char *b)
{
    HANDLE fa = CreateFileA(a, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL), fb;
    static char ba[65536], bb[65536]; DWORD na, nb; BOOL same = FALSE;
    if (fa == INVALID_HANDLE_VALUE) return FALSE;
    fb = CreateFileA(b, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (fb == INVALID_HANDLE_VALUE) { CloseHandle(fa); return FALSE; }
    if (GetFileSize(fa, NULL) == GetFileSize(fb, NULL)) {
        same = TRUE;
        for (;;) {
            if (!ReadFile(fa, ba, sizeof(ba), &na, NULL) || !ReadFile(fb, bb, sizeof(bb), &nb, NULL) || na != nb) { same = FALSE; break; }
            if (!na) break;
            if (memcmp(ba, bb, na)) { same = FALSE; break; }
        }
    }
    CloseHandle(fa); CloseHandle(fb);
    return same;
}
/* CopyFile with a few retries (Explorer or an antivirus may hold the file for a moment) */
static BOOL copy_retry(const char *src, const char *dst)
{
    int i;
    for (i = 0; i < 4; i++) { if (CopyFileA(src, dst, FALSE)) return TRUE; Sleep(400); }
    return FALSE;
}

static void install_file(const char *src, const char *dst)
{
    char stage[MAX_PATH], sdst[MAX_PATH], sstage[MAX_PATH];
    if (same_content(src, dst)) { LOG("  same     %s (already installed)\n", dst); return; }
    make_writable(dst);
    if (copy_retry(src, dst)) { make_writable(dst); LOG("  copied   %s\n", dst); return; }
    /* destination is in use (error 5 = ACCESS_DENIED) */
    snprintf(stage, sizeof(stage), "%s.NEW", dst);
    make_writable(stage);
    DeleteFileA(stage);                                         /* remove stale .NEW from a previous run */
    if (!copy_retry(src, stage)) { ERR("cannot copy %s -> %s (error %lu) - close Control Panel / Explorer windows showing it and run KEXSETUP again\n", src, stage, GetLastError()); return; }
    make_writable(stage);
    if (is_83(dst)) {
        if (short_path(dst, sdst) && short_path(stage, sstage) && wininit_add(sdst, sstage)) {
            LOG("  in use   %s -> will be replaced at restart (WININIT)\n", dst);
            return;
        }
    } else if (pending_add(dst, stage)) {
        LOG("  in use   %s -> will be replaced after restart (KEXSETUP /finish at logon)\n", dst);
        return;
    }
    ERR("cannot copy %s -> %s (error %lu)\n", src, dst, GetLastError());
}

/* KEXSETUP /finish (from RunOnce): copy the staged files whose destinations were in use. */
static void finish_pending(void)
{
    char pnd[MAX_PATH], line[2 * MAX_PATH + 4], *bar, *nl; FILE *f; int n = 0;
    join(pnd, g_kexdir, "KEXNG.PND");
    if (!(f = fopen(pnd, "r"))) { LOG("  nothing pending\n"); return; }
    while (fgets(line, sizeof(line), f)) {
        if ((nl = strpbrk(line, "\r\n"))) *nl = 0;
        if (!(bar = strchr(line, '|'))) continue;
        *bar++ = 0;
        make_writable(line); make_writable(bar);
        if (CopyFileA(bar, line, FALSE)) { make_writable(line); DeleteFileA(bar); LOG("  replaced %s\n", line); n++; }
        else ERR("cannot replace %s (error %lu) - run KEXSETUP again\n", line, GetLastError());
    }
    fclose(f);
    DeleteFileA(pnd);
    LOG("  %d pending file(s) replaced\n", n);
}

static void remove_file(const char *path)
{
    char s[MAX_PATH];
    if (GetFileAttributesA(path) == 0xFFFFFFFF) return;
    make_writable(path);
    if (DeleteFileA(path)) { LOG("  deleted  %s\n", path); return; }
    if (short_path(path, s) && wininit_add("NUL", s)) { LOG("  in use   %s -> deleted at restart\n", path); return; }
    ERR("cannot delete %s (error %lu)\n", path, GetLastError());
}

/* Add or remove ",KEXNT" on every "contents=" line of core.ini (text edit keeps comments/order). */
static void edit_core_ini(BOOL add)
{
    char ini[MAX_PATH], bak[MAX_PATH], tmp[MAX_PATH], line[1024];
    FILE *in, *out;
    int changed = 0;
    join(ini, g_kexdir, "core.ini");
    join(bak, g_kexdir, "CORE.KNG");
    join(tmp, g_kexdir, "CORE.TMP");
    if (add && GetFileAttributesA(bak) == 0xFFFFFFFF && !CopyFileA(ini, bak, TRUE))
        { ERR("cannot back up %s (error %lu)\n", ini, GetLastError()); return; }
    if (!(in = fopen(ini, "r"))) { ERR("cannot read %s\n", ini); return; }
    if (!(out = fopen(tmp, "w"))) { fclose(in); ERR("cannot write %s\n", tmp); return; }
    while (fgets(line, sizeof(line) - 16, in)) {
        char *nl = strpbrk(line, "\r\n"), *val;
        if (nl) *nl = 0;
        /* SHELL32.SHParseDisplayName in [WINXP.names] stays KernelEx's own "=kexbasen.0". Earlier builds changed it
         * (16:28: ";KEXNG " comment - KernelEx cannot parse it and dropped every XP+ profile; 16:38: "=KEXNT.0") for
         * Mypal's xul.dll; the real cause was KernelEx's app rule *\XUL.DLL = NT2K (see xul_rule). Both are put back. */
        {
            static const char kb[] = "SHELL32.SHParseDisplayName=kexbasen.0", kn[] = "SHELL32.SHParseDisplayName=KEXNT.0";
            char *l = line;
            if (!strnicmp(l, ";KEXNG ", 7)) { l += 7; changed++; }
            if (!stricmp(l, kn)) { fprintf(out, "%s\n", kb); changed++; continue; }
            if (l != line) { fprintf(out, "%s\n", l); continue; }
        }
        /* KERNEL32.CreateIoCompletionPort is pinned to KernelEx's queue-only ports in [NT40.names] (inherited by every
         * NT profile): programs created KernelEx ports while Get/PostQueuedCompletionStatus went to kexnt (build 20-22).
         * Point the pin at kexnt's ports (iocp_ext.c); uninstall puts KernelEx's line back. */
        {
            static const char pk[] = "KERNEL32.CreateIoCompletionPort=kexbases.0", pn[] = "KERNEL32.CreateIoCompletionPort=KEXNT.0";
            if (add && !stricmp(line, pk)) { fprintf(out, "%s\n", pn); changed++; continue; }
            if (!add && !stricmp(line, pn)) { fprintf(out, "%s\n", pk); changed++; continue; }
        }
        if (!strnicmp(line, "contents=", 9)) {
            val = line + 9;
            char up[1024];
            strcpy(up, val); strupr(up);
            if (add && stricmp(val, "none") && !strstr(up, "KEXNT")) { strcat(line, ",KEXNT"); changed++; }
            if (!add) {
                char *p = strstr(up, ",KEXNT");
                if (p) { memmove(val + (p - up), val + (p - up) + 6, strlen(val + (p - up) + 6) + 1); changed++; }
            }
        }
        fprintf(out, "%s\n", line);
    }
    fclose(in); fclose(out);
    /* CopyFile over the original (no MoveFileEx on 9x): core.ini is never missing, even on failure. */
    if (!CopyFileA(tmp, ini, FALSE)) { ERR("cannot replace %s (error %lu)\n", ini, GetLastError()); return; }
    DeleteFileA(tmp);
    LOG("  core.ini: %d line(s) changed (%s)\n", changed, add ? "contents= include KEXNT" : "KEXNT removed, original lines restored");
    if (add && !changed) LOG("  (kexnt was already listed)\n");
}

/* KernelEx ships the app rule  *\XUL.DLL = NT2K  (for Firefox 3/4, HKLM\Software\KernelEx\AppSettings\Configs).
 * A module's own rule beats the program's setting, so Mypal / Firefox 52 / Pale Moon's xul.dll was resolved as
 * Windows 2000 whatever mypal.exe was set to - and Windows 2000 mode hides SHParseDisplayName, which those
 * xul.dlls import statically (2026-11-01). The first fix pinned the rule to WINXP, which then pinned the Windows
 * version the browser reports, whatever the user picked on the KernelEx tab (2026-11-02).
 * Now: the xul.dll rule is REMOVED, so xul.dll follows its program's setting (KernelEx falls back to the
 * process exe's settings for a module without an entry), and the known Gecko browsers get a default of
 * Windows XP through wildcard program rules (*\MYPAL.EXE = WINXP, ...). The KernelEx tab writes an exact path,
 * which beats a wildcard - so the tab now decides. Old values are kept under HKLM\Software\KernelEx\KexNG
 * (XulRule, and ExeRules = the wildcard rules we added); uninstall puts everything back. Effective after restart. */
/* Build 124: the same Windows XP default for the Visual C++ redistributable setups. Their setup code needs
 * VerifyVersionInfoW, which KernelEx's Default mode hides on purpose (core.ini DCFG1.names: none):
 *   VCREDIST_X86.EXE   Visual C++ 2005-2013 redistributable (2013: WiX Burn, which re-runs itself from %TEMP%)
 *   VC_REDIST.X86.EXE  Visual C++ 2015-2022 redistributable (WiX Burn)
 *   SETUPENGINE.DLL    Visual Studio 2010 setup engine (Visual C++ 2010, .NET 4.0): a module rule, because its
 *                      Setup.exe runs from a randomly named folder and "SETUP.EXE" would catch every setup */
static const char *g_gecko_exes[] = { "*\\MYPAL.EXE", "*\\PALEMOON.EXE", "*\\BASILISK.EXE", "*\\SERPENT.EXE",
                                      "*\\FIREFOX.EXE", "*\\SEAMONKEY.EXE", "*\\K-MELEON.EXE",
                                      "*\\VCREDIST_X86.EXE", "*\\VC_REDIST.X86.EXE", "*\\SETUPENGINE.DLL",
                                      /* build 131: browser installers (7-Zip SFX + NSIS setup.exe in %TEMP%: the setup
                                       * inherits the SFX's setting - KernelEx core/resolver.cpp takes the parent's) */
                                      "*\\PALEMOON-*.EXE", "*\\FIREFOX?SETUP*.EXE", "*\\FIREFOX?INSTALLER*.EXE",
                                      /* build 132: Basilisk's installer ("requires Windows 7 or newer", same NSIS check) */
                                      "*\\BASILISK-*.EXE",
                                      /* build 131: K-Lite Codec Pack (Inno Setup 6.4: Windows 7+, MinVersion checked) */
                                      "*\\K-LITE_CODEC_PACK_*.EXE",
                                      /* build 131: Google Chrome setups (Omaha: Chrome 110+ needs Windows 10) */
                                      "*\\CHROMESTANDALONESETUP*.EXE", "*\\CHROMESETUP*.EXE",
                                      /* build 132: .NET Framework 4.0 (its SFX; Setup.exe itself is covered by SETUPENGINE.DLL) */
                                      "*\\DOTNETFX40*.EXE",
                                      /* build 132: the .NET Framework's own native DLLs (clr.dll, clrjit.dll, mscoreei.dll, ...)
                                       * and its loader shim SYSTEM\mscoree.dll import XP API (clr.dll: VerifyVersionInfoW,
                                       * hidden by KernelEx's Default mode) - KernelEx picks the configuration per module, and
                                       * a .NET program's EXE is a Windows 4.0 image, so these modules need their own rule */
                                      "*\\MICROSOFT.NET\\FRAMEWORK\\*", "*\\MSCOREE.DLL" };
/* build 126: Visual C++ 2015-2022 (14.44: bundle condition "VersionNT >= v6.1") needs Windows 7; it then also
 * needs the Universal CRT (SYSTEM\ucrtbase.dll, else it runs wusa.exe for KB2999226, which Windows 98 cannot). */
/* build 131: Visual C++ v14 14.50+ ("2017-present", 14.52.37029) has the bundle condition "VersionNT >= v6.3"
 * (Burn log: "can only be installed on Windows 10, Windows Server 2016, and newer") - with Windows 10 21H2 both the
 * old 14.44 and the new setups install (measured in the VM: 14.52 /q exit 0, both MSIs result 0). */
/* build 131: Pale Moon 35's setup stops with "requires Microsoft Windows 7 or newer" (NSIS version check, measured);
 * Firefox 115 ESR's needs Windows 7, Firefox 116+ (160.0.1 here) Windows 10 - Windows 10 21H2 satisfies all of them. */
static const char *default_profile(const char *exe)
{
    if (!strcmp(exe, "*\\VC_REDIST.X86.EXE") || !strncmp(exe, "*\\FIREFOX?", 10) || !strncmp(exe, "*\\K-LITE", 9) || !strncmp(exe, "*\\CHROME", 8)) return "WIN10_21H2";
    if (!strcmp(exe, "*\\PALEMOON-*.EXE") || !strcmp(exe, "*\\BASILISK-*.EXE")) return "WIN7";
    if (!strcmp(exe, "*\\SETUPENGINE.DLL") || !strcmp(exe, "*\\DOTNETFX40*.EXE") ||
        !strcmp(exe, "*\\MICROSOFT.NET\\FRAMEWORK\\*") || !strcmp(exe, "*\\MSCOREE.DLL")) return "WINXPSP3";   /* build 132 */
    return "WINXP";
}
static void xul_rule(BOOL add)
{
    HKEY k, ng; char v[64] = "", old[64] = "", added[512] = ""; DWORD t, n = sizeof(v), no = sizeof(old), na = sizeof(added);
    static const char name[] = "*\\XUL.DLL"; int i;
    if (RegOpenKeyA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\AppSettings\\Configs", &k) != ERROR_SUCCESS) {
        LOG("  app rule %s: KernelEx AppSettings key missing - left alone\n", name); return;
    }
    RegQueryValueExA(k, name, NULL, &t, (BYTE *)v, &n);
    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", &ng) != ERROR_SUCCESS) { RegCloseKey(k); return; }
    if (add) {
        if (RegQueryValueExA(ng, "XulRule", NULL, &t, (BYTE *)old, &no) != ERROR_SUCCESS)   /* first install: remember KernelEx's own */
            RegSetValueExA(ng, "XulRule", 0, REG_SZ, (BYTE *)(v[0] ? v : "-"), lstrlenA(v[0] ? v : "-") + 1);
        if (v[0]) { RegDeleteValueA(k, name); LOG("  app rule %s (%s) removed: xul.dll now follows its program's KernelEx setting\n", name, v); }
        else LOG("  app rule %s: none (xul.dll follows its program's KernelEx setting)\n", name);
        RegQueryValueExA(ng, "ExeRules", NULL, &t, (BYTE *)added, &na);
        for (i = 0; i < (int)(sizeof(g_gecko_exes) / sizeof(g_gecko_exes[0])); i++) {
            char cur[64] = ""; DWORD nc = sizeof(cur);
            const char *want = default_profile(g_gecko_exes[i]);
            if (RegQueryValueExA(k, g_gecko_exes[i], NULL, &t, (BYTE *)cur, &nc) == ERROR_SUCCESS) {
                /* build 126: a default this setup wrote earlier (in ExeRules, still WINXP) follows a changed default */
                if (strcmp(want, cur) && (!strcmp(cur, "WINXP") || !strcmp(cur, "WIN7")) && strstr(added, g_gecko_exes[i])) {
                    RegSetValueExA(k, g_gecko_exes[i], 0, REG_SZ, (BYTE *)want, lstrlenA(want) + 1);
                    LOG("  default rule %s = %s (was this setup's %s)\n", g_gecko_exes[i], want, cur);
                } else LOG("  default rule %s = %s (kept)\n", g_gecko_exes[i], cur);
                continue;
            }
            RegSetValueExA(k, g_gecko_exes[i], 0, REG_SZ, (BYTE *)want, lstrlenA(want) + 1);
            if (lstrlenA(added) + lstrlenA(g_gecko_exes[i]) + 2 < (int)sizeof(added)) { lstrcatA(added, g_gecko_exes[i]); lstrcatA(added, ";"); }
            LOG("  default rule %s = %s (the KernelEx tab overrides it)\n", g_gecko_exes[i], want);
        }
        RegSetValueExA(ng, "ExeRules", 0, REG_SZ, (BYTE *)added, lstrlenA(added) + 1);
        {   /* build 131: KernelEx 4.5's own settings.reg has "*\FIREFOX SETUP *.EXE" = WINXP (for Firefox 3-4 setups).
             * It sorts before our "*\FIREFOX?SETUP*.EXE" (KernelEx takes the first wildcard in name order), so
             * Firefox 115 ESR / 160 setups ran as XP and stopped. KernelEx's value (WINXP, nothing else) is
             * retargeted; the old one is kept in KexNG\KxRetarget for the uninstall. */
            static const char *const kx_def[][3] = { { "*\\FIREFOX SETUP *.EXE", "WINXP", "WIN10_21H2" },
                /* KernelEx's Default mode for every firefox.exe: Firefox 115 ESR then fails with error 31
                 * (NtOpenFile...); Windows 7 is Firefox 115's own minimum. An exact path set on the KernelEx tab
                 * (your Firefox 52) still wins over this wildcard. */
                { "*\\FIREFOX.EXE", "DCFG1", "WIN7" } };
            char ret[512] = ""; DWORD nr = sizeof(ret);
            RegQueryValueExA(ng, "KxRetarget", NULL, &t, (BYTE *)ret, &nr);
            for (i = 0; i < (int)(sizeof(kx_def) / sizeof(kx_def[0])); i++) {
                char cur[64] = ""; DWORD nc = sizeof(cur);
                if (RegQueryValueExA(k, kx_def[i][0], NULL, &t, (BYTE *)cur, &nc) != ERROR_SUCCESS) continue;
                if (!strcmp(cur, kx_def[i][1])) {
                    RegSetValueExA(k, kx_def[i][0], 0, REG_SZ, (const BYTE *)kx_def[i][2], lstrlenA(kx_def[i][2]) + 1);
                    if (!strstr(ret, kx_def[i][0]) && lstrlenA(ret) + lstrlenA(kx_def[i][0]) + lstrlenA(cur) + 3 < (int)sizeof(ret)) {
                        lstrcatA(ret, kx_def[i][0]); lstrcatA(ret, "="); lstrcatA(ret, cur); lstrcatA(ret, ";");
                    }
                    LOG("  KernelEx rule %s = %s (was KernelEx's %s)\n", kx_def[i][0], kx_def[i][2], cur);
                } else LOG("  KernelEx rule %s = %s (kept)\n", kx_def[i][0], cur);
            }
            if (ret[0]) RegSetValueExA(ng, "KxRetarget", 0, REG_SZ, (BYTE *)ret, lstrlenA(ret) + 1);
        }
    } else {
        if (RegQueryValueExA(ng, "XulRule", NULL, &t, (BYTE *)old, &no) == ERROR_SUCCESS) {
            if (!strcmp(old, "-")) RegDeleteValueA(k, name); else RegSetValueExA(k, name, 0, REG_SZ, (BYTE *)old, lstrlenA(old) + 1);
            RegDeleteValueA(ng, "XulRule");
            LOG("  app rule %s restored to %s\n", name, old);
        }
        if (RegQueryValueExA(ng, "ExeRules", NULL, &t, (BYTE *)added, &na) == ERROR_SUCCESS) {
            char *p = added, *e;
            while (*p && (e = strchr(p, ';'))) { *e = 0; RegDeleteValueA(k, p); LOG("  default rule %s removed\n", p); p = e + 1; }
            RegDeleteValueA(ng, "ExeRules");
        }
        {   char ret[512] = ""; DWORD nr = sizeof(ret);
            if (RegQueryValueExA(ng, "KxRetarget", NULL, &t, (BYTE *)ret, &nr) == ERROR_SUCCESS) {
                char *p = ret, *e, *eq;
                while (*p && (e = strchr(p, ';'))) {
                    *e = 0;
                    if ((eq = strrchr(p, '='))) { *eq = 0; RegSetValueExA(k, p, 0, REG_SZ, (BYTE *)(eq + 1), lstrlenA(eq + 1) + 1);
                                                  LOG("  KernelEx rule %s restored to %s\n", p, eq + 1); }
                    p = e + 1;
                }
                RegDeleteValueA(ng, "KxRetarget");
            }
        }
    }
    RegCloseKey(ng); RegCloseKey(k);
}

static void known_dll(BOOL add)
{
    HKEY k;
    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KnownDLLs", &k) != ERROR_SUCCESS)
        { ERR("cannot open HKLM\\Software\\KernelEx\\KnownDLLs\n"); return; }
    if (add) {
        if (RegSetValueExA(k, "KEXNT", 0, REG_SZ, (const BYTE *)"KEXNT.DLL", 10) == ERROR_SUCCESS)
            LOG("  registry: KnownDLLs KEXNT = KEXNT.DLL\n");
        else ERR("cannot write KnownDLLs\\KEXNT\n");
    } else if (RegDeleteValueA(k, "KEXNT") == ERROR_SUCCESS) LOG("  registry: KnownDLLs KEXNT removed\n");
    RegCloseKey(k);
}

/* build 132: Windows 98's loader must already accept movable DLLs without relocations, and resolve a program's own
 * forwarder DLLs with the program's configuration (kexnt, veh_ext.c kex_KexLoaderFix), when the first modern program
 * after boot maps the DLLs it ships - before kexnt's own start-up runs. RunServices starts it once per boot. */
static void loader_boot(BOOL add)
{
    HKEY k; char cmd[MAX_PATH + 64];
    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", &k) != ERROR_SUCCESS)
        { ERR("cannot open RunServices\n"); return; }
    if (add) {
        wsprintfA(cmd, "rundll32.exe %s\\KEXNT.DLL,KexNGBoot", g_kexdir);
        if (RegSetValueExA(k, "KexNGLoader", 0, REG_SZ, (const BYTE *)cmd, lstrlenA(cmd) + 1) == ERROR_SUCCESS)
            LOG("  registry: RunServices KexNGLoader = %s\n", cmd);
        else ERR("cannot write RunServices\\KexNGLoader\n");
    } else if (RegDeleteValueA(k, "KexNGLoader") == ERROR_SUCCESS) LOG("  registry: RunServices KexNGLoader removed\n");
    RegCloseKey(k);
}

/* ---- version profiles (KEXVER.DLL) in core.ini, the KernelEx way: [ApiConfigurations] N=NAME + sections ---- */
static const struct { const char *name, *desc; } g_profiles[] = {   /* index = kexver.<N> */
    { "WIN7",       "Windows 7 SP1" },
    { "WIN2K8R2",   "Windows Server 2008 R2 SP1" },
    { "WIN8",       "Windows 8" },
    { "WIN2K12",    "Windows Server 2012" },
    { "WIN81",      "Windows 8.1" },
    { "WIN2K12R2",  "Windows Server 2012 R2" },
    { "WIN10_1511", "Windows 10 1511" },
    { "WIN10_1607", "Windows 10 1607" },
    { "WIN2K16",    "Windows Server 2016" },
    { "WIN10_1809", "Windows 10 1809" },
    { "WIN2K19",    "Windows Server 2019" },
    { "WIN10_21H2", "Windows 10 21H2" },
    { "WIN2K22",    "Windows Server 2022" },
    { "WIN11",      "Windows 11 24H2" },
    { "WIN2K25",    "Windows Server 2025" },
    { "WINXPSP3",   "Windows XP SP3" },          /* build 132: .NET Framework 4.0 setup (see kexver.c) */
};
#define NPROFILES (sizeof(g_profiles) / sizeof(g_profiles[0]))
static const char *g_ver_funcs[] = {
    "KERNEL32.GetVersion", "KERNEL32.GetVersionExA", "KERNEL32.GetVersionExW",
    "KERNEL32.VerifyVersionInfoA", "KERNEL32.VerifyVersionInfoW", "KERNEL32.GetProductInfo",
    "NTDLL.RtlGetVersion", "NTDLL.RtlVerifyVersionInfo", "NTDLL.RtlGetNtVersionNumbers",
};

/* "/probe": 8 empty, hidden configurations (no inherit, no contents = almost no memory) placed before our
 * profiles. kexcfg then shows whether the core's limit is a COUNT (probes push our profiles out) or MEMORY
 * (probes load and the cut-off moves later). */
#define NPROBES 8
static BOOL g_probe;

static int is_ours(const char *name)
{
    int i;
    for (i = 0; i < (int)NPROFILES; i++) if (!stricmp(name, g_profiles[i].name)) return 1;
    if (!strnicmp(name, "KXPROBE", 7)) return 1;
    return 0;
}

/* Rewrite [ApiConfigurations] as: KernelEx entries before NOHEAP, our profiles (if add), NOHEAP and
 * whatever followed it. Keys stay contiguous (KernelEx stops at the first gap); "default=" is untouched
 * because every entry before NOHEAP keeps its index. Per-program choices are stored by name, not index. */
static void rebuild_list(const char *ini, BOOL add)
{
    static char names[256][64];
    char key[8];
    int n = 0, total, i, j, tail = -1, out = 0;
    for (i = 0; i < 256; i++) {
        sprintf(key, "%d", i);
        if (!GetPrivateProfileStringA("ApiConfigurations", key, "", names[n], 64, ini)) break;
        if (is_ours(names[n])) continue;                          /* re-added below in our order */
        if (tail < 0 && !stricmp(names[n], "NOHEAP")) tail = n;
        n++;
    }
    total = i;
    if (tail < 0) tail = n;                                       /* no NOHEAP: append at the end */
    for (i = 0; i < tail; i++) { sprintf(key, "%d", out++); WritePrivateProfileStringA("ApiConfigurations", key, names[i], ini); }
    if (add && g_probe)
        for (j = 1; j <= NPROBES; j++) {
            char pn[16]; sprintf(pn, "KXPROBE%d", j);
            sprintf(key, "%d", out++); WritePrivateProfileStringA("ApiConfigurations", key, pn, ini);
        }
    if (add)
        for (j = 0; j < (int)NPROFILES; j++) { sprintf(key, "%d", out++); WritePrivateProfileStringA("ApiConfigurations", key, g_profiles[j].name, ini); }
    for (i = tail; i < n; i++) { sprintf(key, "%d", out++); WritePrivateProfileStringA("ApiConfigurations", key, names[i], ini); }
    for (i = out; i < total + (int)NPROFILES + NPROBES; i++) { sprintf(key, "%d", i); WritePrivateProfileStringA("ApiConfigurations", key, NULL, ini); }
}

static void profiles(BOOL add)
{
    char ini[MAX_PATH], sect[64], body[2048], *p;
    int i, j;
    join(ini, g_kexdir, "core.ini");
    if (add && !GetPrivateProfileStringA("WIN2K8", "desc", "", sect, sizeof(sect), ini)) {
        ERR("core.ini has no WIN2K8 configuration to inherit from - version profiles not added\n");
        return;
    }
    for (i = 0; i < (int)NPROFILES; i++) {
        sprintf(sect, "%s.names", g_profiles[i].name);
        WritePrivateProfileStringA(g_profiles[i].name, NULL, NULL, ini);   /* drop old version of the section */
        WritePrivateProfileStringA(sect, NULL, NULL, ini);
        if (!add) continue;
        /* [NAME]: inherit the newest KernelEx NT profile, load KEXVER, describe it */
        p = body;
        /* build 132: Windows XP SP3 builds on KernelEx's own Windows XP configuration (the XP API set), the others on
         * its newest NT profile */
        p += sprintf(p, "inherit=%s", (!strcmp(g_profiles[i].name, "WINXPSP3") && GetPrivateProfileStringA("WINXP", "desc", "", sect, sizeof(sect), ini)) ? "WINXP" : "WIN2K8") + 1;
        sprintf(sect, "%s.names", g_profiles[i].name);
        p += sprintf(p, "contents=KEXVER") + 1;
        p += sprintf(p, "desc=%s", g_profiles[i].desc) + 1;
        *p = 0;
        WritePrivateProfileSectionA(g_profiles[i].name, body, ini);
        /* [NAME.names]: every version function -> kexver.<profile index> */
        p = body;
        for (j = 0; j < (int)(sizeof(g_ver_funcs) / sizeof(g_ver_funcs[0])); j++)
            p += sprintf(p, "%s=kexver.%d", g_ver_funcs[j], i) + 1;
        *p = 0;
        WritePrivateProfileSectionA(sect, body, ini);
    }
    for (i = 1; i <= NPROBES; i++) {
        char pn[16]; sprintf(pn, "KXPROBE%d", i);
        WritePrivateProfileStringA(pn, NULL, NULL, ini);
        if (add && g_probe) {
            p = body;
            p += sprintf(p, "inherit=none") + 1;
            p += sprintf(p, "contents=none") + 1;
            p += sprintf(p, "desc=Limit probe %d", i) + 1;
            p += sprintf(p, "noshow=1") + 1;
            *p = 0;
            WritePrivateProfileSectionA(pn, body, ini);
        }
    }
    rebuild_list(ini, add);
    WritePrivateProfileStringA(NULL, NULL, NULL, ini);                       /* flush the 9x INI cache */
    LOG("  core.ini: %s %d version profiles (list order: KernelEx, Windows 7 ... Server 2025, Disable custom heap)\n",
        add ? "installed" : "removed", (int)NPROFILES);
}

/* ---- KernelEx 4.5.x core: lift the 1 MB shared-heap cap that limits it to ~17 configurations ----
 * KERNELEX.DLL 4.5.2 create_shared_heap():  68 00 00 10 00   push 100000h (dwMaximumSize = 1 MB)
 *                                           6A 00            push 0
 *                                           68 00 00 00 04   push HEAP_SHARED
 *                                           FF 15 ...        call [HeapCreate]
 * Every configuration copies ~53 KB of tables into that heap (measured: 17 fit). We raise the maximum to 4 MB.
 * The sequence must occur exactly once; KERNELEX.KNG keeps the original for /u. The file is in use, so the
 * patched copy replaces it at the next boot (WININIT.INI), like every other in-use file here. */
#define HEAP_MAX_NEW 0x00800000UL   /* 8 MB: kexnt now overrides 18 system DLLs per configuration */
#define HEAP_MAX_OLD 0x00400000UL   /* what earlier KernelEx-NG CDs set */
static void core_heap(BOOL add)
{
    char dll[MAX_PATH], bak[MAX_PATH], pat[MAX_PATH];
    static const BYTE sig[] = { 0x68, 0x00, 0x00, 0x10, 0x00, 0x6A, 0x00, 0x68, 0x00, 0x00, 0x00, 0x04, 0xFF, 0x15 };
    BYTE *buf;
    FILE *f;
    long n, i, hit = -1, hits = 0, done = 0;
    join(dll, g_kexdir, "KERNELEX.DLL");
    join(bak, g_kexdir, "KERNELEX.KNG");
    join(pat, g_kexdir, "KERNELEX.PAT");
    if (!add) {
        if (GetFileAttributesA(bak) == 0xFFFFFFFF) { LOG("  KernelEx core: no backup, left as is\n"); return; }
        install_file(bak, dll);
        LOG("  KernelEx core: original restored from KERNELEX.KNG\n");
        return;
    }
    if (!(f = fopen(dll, "rb"))) { ERR("cannot read %s\n", dll); return; }
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    buf = (BYTE *)malloc(n);
    if (!buf || fread(buf, 1, n, f) != (size_t)n) { fclose(f); free(buf); ERR("cannot read %s\n", dll); return; }
    fclose(f);
    for (i = 0; i + (long)sizeof(sig) <= n; i++) {
        if (!memcmp(buf + i, sig, sizeof(sig))) { hit = i; hits++; }
        else if (buf[i] == 0x68 && *(DWORD *)(buf + i + 1) == HEAP_MAX_OLD && !memcmp(buf + i + 5, sig + 5, sizeof(sig) - 5)) { hit = i; hits++; }
        else if (buf[i] == 0x68 && *(DWORD *)(buf + i + 1) == HEAP_MAX_NEW && !memcmp(buf + i + 5, sig + 5, sizeof(sig) - 5)) done++;
    }
    if (done == 1 && !hits) { LOG("  KernelEx core: shared heap already raised to %lu MB\n", HEAP_MAX_NEW >> 20); free(buf); return; }
    if (hits != 1) {
        LOG("  KernelEx core: 1 MB heap sequence found %ld times - not patched (only KernelEx 4.5.x is known)\n", hits);
        free(buf); return;
    }
    if (GetFileAttributesA(bak) == 0xFFFFFFFF && !CopyFileA(dll, bak, TRUE)) { ERR("cannot back up %s\n", dll); free(buf); return; }
    *(DWORD *)(buf + hit + 1) = HEAP_MAX_NEW;
    if (!(f = fopen(pat, "wb")) || fwrite(buf, 1, n, f) != (size_t)n) { if (f) fclose(f); ERR("cannot write %s\n", pat); free(buf); return; }
    fclose(f); free(buf);
    install_file(pat, dll);
    DeleteFileA(pat);
    LOG("  KernelEx core: shared heap 1 MB -> %lu MB (file offset 0x%lx; backup KERNELEX.KNG)\n", HEAP_MAX_NEW >> 20, hit + 1);
}

/* build 132: NO LONGER USED to add values - only to remove the ones builds 126-131 wrote. A program that ships its own
 * api-ms-win-*.dll must load it (user's rule: no substituting the program's DLLs). Why those copies failed on Windows 98
 * is fixed in kexnt instead (veh_ext.c: "DLLs without relocations", "forwarders of NT 5+ DLLs"; fwdload_pic.c).
 * Programs that do not ship them still find ours in SYSTEM.
 * Old note - build 126: API-set names resolve to the SYSTEM copies even when a program brings its own, as on Windows 10 (API sets
 * are never loaded from the program's folder there). Measured: Mypal 29 / Firefox 52.9 as installed by their setups
 * carry Microsoft's app-local api-ms-win-core-* / api-ms-win-crt-* forwarders (all at ImageBase 0x10000000, no
 * relocations, forwarding to KERNEL32 functions Windows 98 does not have) -> "Windows cannot run this program because
 * it is in an invalid format" / "API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL ... not relocatable". KernelEx's own redirection
 * (HKLM\Software\KernelEx\KnownDLLs, value = path relative to the KernelEx folder) sends the name to SYSTEM; with it
 * Mypal starts in the test VM. Only names this setup installed; /u removes exactly those values. */
static void apiset_known(const char *file, BOOL add)
{
    HKEY k; char name[MAX_PATH], val[MAX_PATH], *dot; const char *sysname = strrchr(g_sysdir, '\\');
    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KnownDLLs", &k) != ERROR_SUCCESS) return;
    lstrcpynA(name, file, sizeof(name));
    if ((dot = strrchr(name, '.')) && !stricmp(dot, ".DLL")) *dot = 0;
    if (add) {
        wsprintfA(val, "..\\%s\\%s", sysname ? sysname + 1 : "SYSTEM", file);
        RegSetValueExA(k, name, 0, REG_SZ, (const BYTE *)val, lstrlenA(val) + 1);
    } else RegDeleteValueA(k, name);
    RegCloseKey(k);
}

static void apisets_install(void)
{
    static const char *const pats[] = { "api-ms-win-*.dll", "ext-ms-win-*.dll" };
    char pat[MAX_PATH], src[MAX_PATH], dst[MAX_PATH], lst[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    FILE *l;
    int n = 0, total = 0, p;
    join(lst, g_kexdir, "KEXNG.LST");
    l = fopen(lst, "w");
    for (p = 0; p < 2; p++) {
        join(pat, g_srcdir, pats[p]);
        if ((h = FindFirstFileA(pat, &fd)) != INVALID_HANDLE_VALUE) {
            do {
                int before = g_err;
                total++;
                join(src, g_srcdir, fd.cFileName);
                join(dst, g_sysdir, fd.cFileName);
                install_file(src, dst);
                if (g_err == before) { n++; if (l) fprintf(l, "%s\n", fd.cFileName); apiset_known(fd.cFileName, FALSE); }
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
    }
    if (l) fclose(l);
    LOG("  %d/%d api-ms-win-*.dll / ext-ms-win-*.dll installed to %s\n", n, total, g_sysdir);
    LOG("  registry: KnownDLLs - no API-set redirection: a program that ships its own api-ms-win-*.dll uses it\n");
    if (!total) ERR("no api-ms-win-*.dll found next to kexsetup.exe\n");
}

/* Stub DLLs for Windows DLLs that Win98 does not have (winhttp, dbghelp, dwrite, ...), listed in
 * stub_dlls.txt. A DLL already present in SYSTEM is never replaced unless an earlier KEXSETUP put it
 * there ("stub:" lines in KEXNG.LST). */
static char g_oldlist[16384];
static void read_old_list(void)
{
    char lst[MAX_PATH]; FILE *l; size_t n;
    join(lst, g_kexdir, "KEXNG.LST");
    g_oldlist[0] = 0;
    if ((l = fopen(lst, "r"))) { n = fread(g_oldlist, 1, sizeof(g_oldlist) - 1, l); g_oldlist[n] = 0; fclose(l); }
}
/* Our stubs are linked by LLD, which adds a ".buildid" section; Microsoft's DLLs never have one.
 * Used when KEXNG.LST lost its "stub:" lines (a failed run rewrites the list). */
static BOOL looks_like_our_stub(const char *path)
{
    char buf[4096]; FILE *f = fopen(path, "rb"); size_t n, i;
    if (!f) return FALSE;
    n = fread(buf, 1, sizeof(buf), f); fclose(f);
    for (i = 0; i + 8 <= n; i++) if (!memcmp(buf + i, ".buildid", 8)) return TRUE;
    return FALSE;
}

static BOOL was_our_stub(const char *name)
{
    char key[MAX_PATH + 8], *p = g_oldlist; size_t k;
    sprintf(key, "stub:%s", name); k = strlen(key);
    while ((p = strstr(p, key))) { if ((p == g_oldlist || p[-1] == '\n') && (p[k] == '\n' || p[k] == '\r' || !p[k])) return TRUE; p += k; }
    return FALSE;
}
/* build 132: a Microsoft DLL (its version resource names "Microsoft Corporation", UTF-16) - one the user installed over
 * our stub (e.g. the GDI+ redistributable's gdiplus.dll). Our stubs never carry that string. */
static BOOL is_microsoft_dll(const char *path)
{
    static const char w[] = "M\0i\0c\0r\0o\0s\0o\0f\0t\0 \0C\0o\0r\0p\0o\0r\0a\0t\0i\0o\0n\0";
    FILE *f = fopen(path, "rb"); static char buf[65536]; size_t n, i; BOOL hit = FALSE; long sz;
    if (!f) return FALSE;
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, sz > (long)sizeof(buf) ? sz - (long)sizeof(buf) : 0, SEEK_SET);   /* resources sit at the end */
    n = fread(buf, 1, sizeof(buf), f); fclose(f);
    for (i = 0; i + sizeof(w) - 1 <= n && !hit; i++) if (!memcmp(buf + i, w, sizeof(w) - 1)) hit = TRUE;
    return hit;
}
static void stubs_install(void)
{
    char lstp[MAX_PATH], list[MAX_PATH], line[MAX_PATH], src[MAX_PATH], dst[MAX_PATH];
    FILE *in, *l;
    int n = 0, kept = 0;
    join(list, g_srcdir, "stub_dlls.txt");
    if (!(in = fopen(list, "r"))) { ERR("stub_dlls.txt not found next to kexsetup.exe\n"); return; }
    join(lstp, g_kexdir, "KEXNG.LST");
    l = fopen(lstp, "a");
    while (fgets(line, sizeof(line), in)) {
        char *sp = strpbrk(line, " \t\r\n");
        int before = g_err;
        if (sp) *sp = 0;
        if (!line[0]) continue;
        join(src, g_srcdir, "WIN10");
        join(dst, src, line);
        {   char w[MAX_PATH], *d; join(w, g_srcdir, line); if ((d = strrchr(w, '.'))) strcpy(d, ".w10");
            if (GetFileAttributesA(dst) != 0xFFFFFFFF || GetFileAttributesA(w) != 0xFFFFFFFF) {
                LOG("  skipped  stub %s (your Windows 10 copy is next to kexsetup.exe)\n", line); continue; } }
        join(src, g_srcdir, line);
        join(dst, g_sysdir, line);
        /* build 132: decided by the file's content - a real DLL that replaced our stub (Microsoft's GDI+ redistributable
         * over the gdiplus.dll stub, so WinForms works) is kept although KEXNG.LST still lists the name as our stub */
        if (GetFileAttributesA(dst) != 0xFFFFFFFF && !looks_like_our_stub(dst) && (!was_our_stub(line) || is_microsoft_dll(dst))) {
            LOG("  kept     %s (Windows already has it)\n", dst); kept++; continue;
        }
        install_file(src, dst);
        if (g_err == before) { n++; if (l) fprintf(l, "stub:%s\n", line); }
    }
    fclose(in);
    if (l) fclose(l);
    LOG("  %d stub DLL(s) installed to %s, %d existing DLL(s) left alone\n", n, g_sysdir, kept);
}

/* Genuine Windows 10 DLLs copied from a Windows 10 installation (never shipped with KernelEx-NG):
 * every *.dll in the WIN10 folder next to kexsetup.exe goes to SYSTEM, replacing a missing DLL, one of our
 * stubs, or one an earlier KEXSETUP put there ("w10:" lines in KEXNG.LST). A Windows 98 DLL of the same
 * name is never replaced. */
static BOOL was_ours(const char *tag, const char *name)
{
    char key[MAX_PATH + 8], *p = g_oldlist; size_t k;
    sprintf(key, "%s:%s", tag, name); k = strlen(key);
    while ((p = strstr(p, key))) { if ((p == g_oldlist || p[-1] == '\n') && (p[k] == '\n' || p[k] == '\r' || !p[k])) return TRUE; p += k; }
    return FALSE;
}
/* one Windows 10 DLL: src -> SYSTEM\<name> */
static void win10_one(const char *src, const char *name, FILE *l, int *n, int *kept)
{
    char dst[MAX_PATH]; int before = g_err;
    join(dst, g_sysdir, name);
    if (GetFileAttributesA(dst) != 0xFFFFFFFF && !was_ours("w10", name) && !was_ours("stub", name) && !looks_like_our_stub(dst)) {
        LOG("  kept     %s (Windows 98 has its own - not replaced by the Windows 10 copy)\n", dst); (*kept)++; return;
    }
    install_file(src, dst);
    if (g_err == before) {
        (*n)++; LOG("  Windows 10 %s -> %s\n", name, dst); if (l) fprintf(l, "w10:%s\n", name);
        /* build 131: a program's own DWrite.dll is not used once SYSTEM has the Windows 10 one. Measured: Supermium 150
         * ships an XP DirectWrite in its folder; on Windows 98 it throws (DWRITE_E 0x88985001) and the browser stops
         * at a CHECK (CHROME.DLL+191a886, the DirectWrite font proxy). With that file out of the way Supermium loads
         * SYSTEM's Windows 10 DWrite.dll (the one Chromium uses here) and opens its window. */
        if (!stricmp(name, "DWrite.dll")) { apiset_known(name, TRUE); LOG("  registry: KnownDLLs - DWrite.dll always resolves to %s\n", g_sysdir); }
    }
}
/* Windows 10 DLLs come as <name>.W10 next to kexsetup.exe (the test CD has no folders) or as <name>.dll in a
 * WIN10 folder next to it */
static void win10_install(void)
{
    char pat[MAX_PATH], src[MAX_PATH], dir[MAX_PATH], lstp[MAX_PATH], name[MAX_PATH], *dot;
    WIN32_FIND_DATAA fd; HANDLE h; FILE *l; int n = 0, kept = 0;
    join(lstp, g_kexdir, "KEXNG.LST");
    l = fopen(lstp, "a");
    join(pat, g_srcdir, "*.w10");
    if ((h = FindFirstFileA(pat, &fd)) != INVALID_HANDLE_VALUE) {
        do {
            join(src, g_srcdir, fd.cFileName);
            strcpy(name, fd.cFileName);
            if ((dot = strrchr(name, '.'))) strcpy(dot, ".dll");
            win10_one(src, name, l, &n, &kept);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    join(dir, g_srcdir, "WIN10");
    join(pat, dir, "*.dll");
    if ((h = FindFirstFileA(pat, &fd)) != INVALID_HANDLE_VALUE) {
        do { join(src, dir, fd.cFileName); win10_one(src, fd.cFileName, l, &n, &kept); } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    if (l) fclose(l);
    if (!n && !kept) LOG("  no Windows 10 DLLs next to kexsetup.exe (*.W10 or a WIN10 folder)\n");
    else LOG("  %d Windows 10 DLL(s) installed, %d left alone\n", n, kept);
}

static void apisets_remove(void)
{
    char lst[MAX_PATH], name[MAX_PATH], path[MAX_PATH];
    FILE *l;
    int n = 0;
    join(lst, g_kexdir, "KEXNG.LST");
    if (!(l = fopen(lst, "r"))) { LOG("  no KEXNG.LST, api-ms files left alone\n"); return; }
    while (fgets(name, sizeof(name), l)) {
        char *nl = strpbrk(name, "\r\n");
        if (nl) *nl = 0;
        if (!strnicmp(name, "stub:", 5)) memmove(name, name + 5, strlen(name + 5) + 1);   /* our stub DLLs */
        else if (!strnicmp(name, "w10:", 4)) { memmove(name, name + 4, strlen(name + 4) + 1);  /* Windows 10 drop-ins we copied */
            if (!stricmp(name, "DWrite.dll")) apiset_known(name, FALSE); }                     /* build 131 */
        else if (strnicmp(name, "api-ms-win-", 11) && strnicmp(name, "ext-ms-win-", 11)) continue;  /* never delete anything else */
        else apiset_known(name, FALSE);                                                       /* build 126 */
        join(path, g_sysdir, name);
        make_writable(path);
        if (DeleteFileA(path)) n++;
        else if (GetFileAttributesA(path) != 0xFFFFFFFF) ERR("cannot delete %s (error %lu)\n", path, GetLastError());
    }
    fclose(l);
    DeleteFileA(lst);
    LOG("  deleted  %d api-ms-win-*.dll / stub DLL(s) from %s\n", n, g_sysdir);
}


/* build 125: the public root certificate "Microsoft Root Certificate Authority" (2001) into the local machine's trusted
 * roots, as on Windows XP and later. Measured: the VC++ 2013 setup (WiX Burn) verifies the signature of each package
 * with WinVerifyTrust; on Windows 98 SE + IE 6 SP1 the chain ends at this root, which is not in the store ->
 * 0x800B010A (CERT_E_CHAINING) and the setup stops. Added through CRYPT32 (no prompt for the local machine store);
 * only removed by /u if this setup added it. */
#include "msroot2001.h"
typedef void *(WINAPI *T_COS)(LPCSTR, DWORD, ULONG_PTR, DWORD, const void *);
typedef BOOL (WINAPI *T_CAE)(void *, DWORD, const BYTE *, DWORD, DWORD, void **);
typedef BOOL (WINAPI *T_CCS)(void *, DWORD);
typedef void *(WINAPI *T_CCC)(DWORD, const BYTE *, DWORD);
typedef void *(WINAPI *T_CFC)(void *, DWORD, DWORD, DWORD, const void *, void *);
typedef BOOL (WINAPI *T_CDC)(void *);
typedef BOOL (WINAPI *T_CFR)(void *);
static void root_cert(BOOL add)
{
    HMODULE c = LoadLibraryA("CRYPT32.DLL"); T_COS cos; T_CAE cae; T_CCS ccs; void *st; HKEY ng; DWORD v = 0, cb = sizeof(v), t;
    if (!c) { LOG("  CRYPT32.DLL not found - root certificate not added\n"); return; }
    cos = (T_COS)GetProcAddress(c, "CertOpenStore"); cae = (T_CAE)GetProcAddress(c, "CertAddEncodedCertificateToStore");
    ccs = (T_CCS)GetProcAddress(c, "CertCloseStore");
    if (!cos || !cae || !ccs) { LOG("  CRYPT32 without CertOpenStore - root certificate not added\n"); return; }
    /* CERT_STORE_PROV_SYSTEM_A (9), CERT_SYSTEM_STORE_LOCAL_MACHINE (2 << 16) */
    st = cos((LPCSTR)9, 0, 0, 2UL << 16, "ROOT");
    if (!st) { LOG("  cannot open the local machine ROOT store (%lu)\n", GetLastError()); return; }
    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", &ng) != ERROR_SUCCESS) ng = NULL;
    if (add) {
        if (cae(st, 1 /* X509_ASN_ENCODING */, g_msroot2001, sizeof(g_msroot2001), 1 /* CERT_STORE_ADD_NEW */, NULL)) {
            LOG("  root certificate \"Microsoft Root Certificate Authority\" (2001) added to the trusted roots\n");
            v = 1; if (ng) RegSetValueExA(ng, "AddedRootCert2001", 0, REG_DWORD, (BYTE *)&v, 4);
        } else if (GetLastError() == 0x80092005UL /* CRYPT_E_EXISTS */) LOG("  root certificate \"Microsoft Root Certificate Authority\" already trusted\n");
        else LOG("  root certificate not added (%08lx)\n", GetLastError());
    } else if (ng && RegQueryValueExA(ng, "AddedRootCert2001", NULL, &t, (BYTE *)&v, &cb) == ERROR_SUCCESS && v == 1) {
        T_CCC ccc = (T_CCC)GetProcAddress(c, "CertCreateCertificateContext"); T_CFC cfc = (T_CFC)GetProcAddress(c, "CertFindCertificateInStore");
        T_CDC cdc = (T_CDC)GetProcAddress(c, "CertDeleteCertificateFromStore"); T_CFR cfr = (T_CFR)GetProcAddress(c, "CertFreeCertificateContext");
        void *me = ccc ? ccc(1, g_msroot2001, sizeof(g_msroot2001)) : NULL, *f = (me && cfc) ? cfc(st, 1, 0, 0x000D0000UL /* CERT_FIND_EXISTING */, me, NULL) : NULL;
        if (f && cdc && cdc(f)) LOG("  root certificate added by setup removed\n"); else LOG("  root certificate added by setup not found\n");
        if (me && cfr) cfr(me);
        RegDeleteValueA(ng, "AddedRootCert2001");
    }
    if (ng) RegCloseKey(ng);
    ccs(st, 0);
}

int main(int argc, char **argv)
{
    BOOL uninstall = argc > 1 && (!stricmp(argv[1], "/u") || !stricmp(argv[1], "-u"));
    BOOL finish = argc > 1 && (!stricmp(argv[1], "/finish") || !stricmp(argv[1], "-finish"));
    g_probe = argc > 1 && (!stricmp(argv[1], "/probe") || !stricmp(argv[1], "-probe"));
    char path[MAX_PATH], *slash;
    DWORD type, size = sizeof(g_kexdir);
    HKEY k;

    GetModuleFileNameA(NULL, g_srcdir, sizeof(g_srcdir));
    if ((slash = strrchr(g_srcdir, '\\'))) *slash = 0;
    join(path, g_srcdir, "kexsetup.log");
    g_log = fopen(path, "a");
    GetSystemDirectoryA(g_sysdir, sizeof(g_sysdir));
    LOG("KernelEx-NG setup, build %d (%s)\n", KEXNG_BUILD, finish ? "finish" : uninstall ? "uninstall" : "install");

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx", 0, KEY_READ, &k) != ERROR_SUCCESS
            || RegQueryValueExA(k, "InstallDir", NULL, &type, (BYTE *)g_kexdir, &size) != ERROR_SUCCESS
            || type != REG_SZ) {
        ERR("KernelEx is not installed (HKLM\\Software\\KernelEx\\InstallDir missing). Install KernelEx first.\n");
        goto done;
    }
    RegCloseKey(k);
    join(path, g_kexdir, "core.ini");
    LOG("KernelEx dir: %s\n", g_kexdir);
    if (GetFileAttributesA(path) == 0xFFFFFFFF) { ERR("%s not found\n", path); goto done; }

    if (finish) {                             /* RunOnce after a restart: no further steps, no prompt */
        finish_pending();
        if (g_log) fclose(g_log);
        return g_err;
    }

    if (!uninstall) {
        char src[MAX_PATH];
        join(src, g_srcdir, "kexnt.dll");
        if (GetFileAttributesA(src) == 0xFFFFFFFF) { ERR("kexnt.dll not found next to kexsetup.exe\n"); goto done; }
        join(path, g_kexdir, "KEXNT.DLL");
        install_file(src, path);
        if (g_err) goto done;                 /* don't point core.ini at a DLL that isn't there */
        known_dll(TRUE); xul_rule(TRUE); loader_boot(TRUE);
        read_old_list();
        apisets_install();
        stubs_install();
        win10_install();
        edit_core_ini(TRUE);
        join(src, g_srcdir, "kexver.dll");
        join(path, g_kexdir, "KEXVER.DLL");
        if (GetFileAttributesA(src) == 0xFFFFFFFF) ERR("kexver.dll not found next to kexsetup.exe\n");
        else { install_file(src, path); profiles(TRUE); }
        join(src, g_srcdir, "kexalias.vxd");            /* second views of shared memory (shm_ext.c) */
        join(path, g_kexdir, "KEXALIAS.VXD");
        if (GetFileAttributesA(src) == 0xFFFFFFFF) LOG("  kexalias.vxd not next to kexsetup.exe - skipped\n");
        else install_file(src, path);
        join(src, g_srcdir, "kexaudio.dll");               /* Core Audio over waveOut (build 39) */
        join(path, g_sysdir, "KEXAUDIO.DLL");
        if (GetFileAttributesA(src) == 0xFFFFFFFF) LOG("  kexaudio.dll not next to kexsetup.exe - skipped\n");
        else { install_file(src, path); audio_register(TRUE, path); }
        /* build 58: KernelEx tab (sheet.dll) with "Report real OS version to websites" for browsers. The
         * KernelEx 4.5.2 original is kept as SHEET.ORG (put back by /u). Explorer holds sheet.dll -> WININIT. */
        join(src, g_srcdir, "sheet.dll");
        if (GetFileAttributesA(src) == 0xFFFFFFFF) LOG("  sheet.dll not next to kexsetup.exe - KernelEx tab left as it is\n");
        else {
            char org[MAX_PATH];
            join(path, g_kexdir, "sheet.dll"); join(org, g_kexdir, "SHEET.ORG");
            if (GetFileAttributesA(org) == 0xFFFFFFFF && GetFileAttributesA(path) != 0xFFFFFFFF && !same_content(src, path)) {
                if (CopyFileA(path, org, TRUE)) LOG("  saved    %s (KernelEx's own KernelEx tab)\n", org);
            }
            install_file(src, path);
        }
        /* build 131: KernelEx's psapi.dll + GetModuleInformation / GetMappedFileName (Supermium's XP wrappers import
         * them statically; KernelEx's resolver never extends a DLL outside SYSTEM). Original kept as PSAPI.ORG. */
        join(src, g_srcdir, "psapi.dll");
        if (GetFileAttributesA(src) == 0xFFFFFFFF) LOG("  psapi.dll not next to kexsetup.exe - KernelEx's psapi.dll left as it is\n");
        else {
            char org[MAX_PATH];
            join(path, g_kexdir, "psapi.dll"); join(org, g_kexdir, "PSAPI.ORG");
            if (GetFileAttributesA(org) == 0xFFFFFFFF && GetFileAttributesA(path) != 0xFFFFFFFF && !same_content(src, path)) {
                if (CopyFileA(path, org, TRUE)) LOG("  saved    %s (KernelEx's own psapi.dll)\n", org);
            }
            install_file(src, path);
        }
        /* build 131: the same for KernelEx's userenv.dll + EnterCriticalPolicySection/LeaveCriticalPolicySection
         * (Google Chrome's standalone setup imports them statically). Original kept as USERENV.ORG. */
        join(src, g_srcdir, "userenv.dll");
        if (GetFileAttributesA(src) == 0xFFFFFFFF) LOG("  userenv.dll not next to kexsetup.exe - KernelEx's userenv.dll left as it is\n");
        else {
            char org[MAX_PATH];
            join(path, g_kexdir, "userenv.dll"); join(org, g_kexdir, "USERENV.ORG");
            if (GetFileAttributesA(org) == 0xFFFFFFFF && GetFileAttributesA(path) != 0xFFFFFFFF && !same_content(src, path)) {
                if (CopyFileA(path, org, TRUE)) LOG("  saved    %s (KernelEx's own userenv.dll)\n", org);
            }
            install_file(src, path);
        }
        core_heap(TRUE);
        root_cert(TRUE);
    } else {
        edit_core_ini(FALSE);                 /* first, so KernelEx stops loading kexnt even if a delete fails */
        profiles(FALSE);
        core_heap(FALSE);
        join(path, g_kexdir, "KEXVER.DLL");
        remove_file(path);
        join(path, g_kexdir, "KEXALIAS.VXD");
        if (GetFileAttributesA(path) != 0xFFFFFFFF) remove_file(path);
        known_dll(FALSE); xul_rule(FALSE); root_cert(FALSE); loader_boot(FALSE);
        audio_register(FALSE, NULL);
        join(path, g_sysdir, "KEXAUDIO.DLL");
        if (GetFileAttributesA(path) != 0xFFFFFFFF) remove_file(path);
        apisets_remove();
        {   char org[MAX_PATH];                 /* build 58: KernelEx's own KernelEx tab back */
            join(org, g_kexdir, "SHEET.ORG"); join(path, g_kexdir, "sheet.dll");
            if (GetFileAttributesA(org) != 0xFFFFFFFF) install_file(org, path);
        }
        {   char org[MAX_PATH];                 /* build 131: KernelEx's own psapi.dll back */
            join(org, g_kexdir, "PSAPI.ORG"); join(path, g_kexdir, "psapi.dll");
            if (GetFileAttributesA(org) != 0xFFFFFFFF) install_file(org, path);
        }
        {   char org[MAX_PATH];                 /* build 131: KernelEx's own userenv.dll back */
            join(org, g_kexdir, "USERENV.ORG"); join(path, g_kexdir, "userenv.dll");
            if (GetFileAttributesA(org) != 0xFFFFFFFF) install_file(org, path);
        }
        join(path, g_kexdir, "KEXNT.DLL");
        remove_file(path);
    }
done:
    LOG(g_err ? "\n%d error(s) - see above. Nothing else needed if you fix them and run again.\n"
              : "\nDone. RESTART WINDOWS now so KernelEx reloads core.ini.\n", g_err);
    if (g_log) fclose(g_log);
    printf("\nPress Enter to close...");
    fflush(stdout);
    getchar();
    return g_err;
}
