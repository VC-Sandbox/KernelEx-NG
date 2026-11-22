/*
 * realos_ext.c - KernelEx-NG: "Report real OS version to websites" (KernelEx tab, browsers only).
 *
 * The compatibility profile (e.g. Windows 10 21H2) stays as it is for the program; only the User-Agent a browser
 * sends to websites names the real Windows (98 / 98 SE -> "Windows 98", ME -> "Windows 98; Win 9x 4.90",
 * 95 -> "Windows 95"). Done through each browser family's own documented override, no browser code is touched:
 *   Chromium (chrome.dll next to the exe or one folder below): the --user-agent=<UA> switch, added to the command
 *     line the browser process reads (GetCommandLineW/A); child processes get it from the browser itself.
 *   Gecko / UXP (xul.dll next to the exe): <exe dir>\defaults\pref\kexng-realos.js with
 *     pref("general.useragent.override", "<UA>") - written at start when the option is on, deleted when off.
 * Setting: HKLM\Software\KernelEx\KexNG\RealOSUA, value = the program's full path in upper case, DWORD 1
 * (written by the KernelEx tab, sheet.dll).
 */
#include "kexnt_common.h"

void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);   /* crashlog_ext.c */
FARPROC kex_prev_impl(const char *dll, const char *name);                   /* gdiguard_ext.c */

static char  g_exe[MAX_PATH], g_dir[MAX_PATH];
static int   g_family;                  /* 0 none, 1 Chromium, 2 Gecko */
static int   g_on;
static WCHAR *g_cmdw; static char *g_cmda;
static char  g_ua[220];                 /* Chromium: the UA to add, built at process start */
static volatile LONG g_built;

static void upcase(char *s) { for (; *s; s++) if (*s >= 'a' && *s <= 'z') *s -= 32; }
static BOOL file_exists(const char *p) { return GetFileAttributesA(p) != 0xFFFFFFFF; }

static BOOL setting_on(void)
{
    HKEY k; DWORD v = 0, t, n = sizeof(v); char p[MAX_PATH], q[MAX_PATH]; BOOL on = FALSE;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG\\RealOSUA", 0, KEY_READ, &k) != ERROR_SUCCESS) return FALSE;
    lstrcpynA(p, g_exe, MAX_PATH); upcase(p);
    if (RegQueryValueExA(k, p, NULL, &t, (BYTE *)&v, &n) == ERROR_SUCCESS && t == REG_DWORD && v) on = TRUE;
    if (!on) {                                       /* the tab stores the long path; Windows may give the short one */
        typedef DWORD (WINAPI *T_GLPN)(LPCSTR, LPSTR, DWORD);
        T_GLPN glpn = (T_GLPN)(void *)GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "GetLongPathNameA");
        if (glpn && glpn(g_exe, q, MAX_PATH)) {
            upcase(q); n = sizeof(v);
            if (RegQueryValueExA(k, q, NULL, &t, (BYTE *)&v, &n) == ERROR_SUCCESS && t == REG_DWORD && v) on = TRUE;
        }
    }
    RegCloseKey(k);
    return on;
}

/* the real Windows, from KERNEL32 itself (kexnt's own import is not version-spoofed) */
static const char *os_token(void)
{
    OSVERSIONINFOA v; v.dwOSVersionInfoSize = sizeof(v);
    if (!GetVersionExA(&v) || v.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS) return NULL;
    if (v.dwMajorVersion == 4 && v.dwMinorVersion >= 90) return "Windows 98; Win 9x 4.90";
    if (v.dwMajorVersion == 4 && v.dwMinorVersion >= 10) return "Windows 98";
    return "Windows 95";
}

/* major file version of the running exe: VS_FIXEDFILEINFO found in the mapped image (no VERSION.DLL) */
static DWORD exe_major_version(void)
{
    BYTE *b = (BYTE *)GetModuleHandleA(NULL); IMAGE_NT_HEADERS *nt; DWORD sz, i;
    if (!b) return 0;
    nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    sz = nt->OptionalHeader.SizeOfImage;
    for (i = 0; i + 16 < sz; i += 4) {
        MEMORY_BASIC_INFORMATION m;
        if ((i & 0xFFF) == 0 && (!VirtualQuery(b + i, &m, sizeof(m)) || m.State != MEM_COMMIT)) { i += 0xFFC; continue; }
        if (*(DWORD *)(b + i) == 0xFEEF04BD) return *(DWORD *)(b + i + 8) >> 16;   /* dwFileVersionMS high word */
    }
    return 0;
}

static char g_extra[400];              /* text added to the browser's command line: only the opt-in --user-agent */

static BOOL has_switch(const char *cl, const char *sw)
{
    int n = 0, i;
    while (sw[n] && sw[n] != '=') n++;
    for (i = 0; cl[i]; i++)
        if (cl[i] == '-' && cl[i + 1] == '-' && (i == 0 || cl[i - 1] == ' ' || cl[i - 1] == '"' || cl[i - 1] == '\t') &&
            !memcmp(cl + i, sw, n) && (cl[i + n] == 0 || cl[i + n] == '=' || cl[i + n] == ' ' || cl[i + n] == '"' || cl[i + n] == '\t'))
            return TRUE;
    return FALSE;
}

/* at process start (DLL_PROCESS_ATTACH): only decide and build the text - no loader calls */
static void chromium_prepare(const char *os)
{
    const char *ca = GetCommandLineA(); char num[12]; DWORD maj; int n, i;
    g_extra[0] = 0;
    if (!os || has_switch(ca, "--type") || has_switch(ca, "--user-agent")) return;   /* child process, or UA given */
    maj = exe_major_version();
    if (!maj) maj = 100;
    for (n = 0, i = (int)maj; i; i /= 10) n++;
    for (i = n - 1, num[n] = 0; i >= 0; i--, maj /= 10) num[i] = (char)('0' + maj % 10);
    lstrcpyA(g_ua, "Mozilla/5.0 ("); lstrcatA(g_ua, os);
    lstrcatA(g_ua, ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/"); lstrcatA(g_ua, num); lstrcatA(g_ua, ".0.0.0 Safari/537.36");
    if (lstrlenA(g_extra) + lstrlenA(g_ua) + 20 < (int)sizeof(g_extra)) {
        lstrcatA(g_extra, " \"--user-agent="); lstrcatA(g_extra, g_ua); lstrcatA(g_extra, "\"");
    }
}
/* on the first GetCommandLine call: the browser's command line + --user-agent (opt-in KernelEx tab setting) */
static void chromium_build(void)
{
    typedef LPWSTR (WINAPI *T_GCLW)(void);
    const char *ca; const WCHAR *cw; T_GCLW gclw; int i, k, lw, le; char *a; WCHAR *w;
    if (!g_extra[0] || InterlockedExchange(&g_built, 1)) return;
    gclw = (T_GCLW)(void *)kex_prev_impl("KERNEL32.DLL", "GetCommandLineW");
    ca = GetCommandLineA(); cw = gclw ? gclw() : NULL; lw = cw ? lstrlenW(cw) : 0; le = lstrlenA(g_extra);
    if ((a = (char *)HeapAlloc(GetProcessHeap(), 0, lstrlenA(ca) + le + 8)) != NULL) { lstrcpyA(a, ca); lstrcatA(a, g_extra); }
    if ((w = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (lw + lstrlenA(ca) + le + 8) * sizeof(WCHAR))) != NULL) {
        k = 0;
        if (cw) for (i = 0; i < lw; i++) w[k++] = cw[i];
        else for (i = 0; ca[i]; i++) w[k++] = (WCHAR)(BYTE)ca[i];
        for (i = 0; g_extra[i]; i++) w[k++] = (WCHAR)(BYTE)g_extra[i];
        w[k] = 0;
    }
    g_cmda = a; g_cmdw = w;
    if (g_ua[0]) kex_crashnote("Report real OS version to websites: Chromium --user-agent added (Chrome major)", exe_major_version(), 0, 0, 0);
    kex_crashnote(g_extra, 0, 0, 0, 0);
}

static void gecko_pref(const char *os)
{
    char file[MAX_PATH + 40], ini[MAX_PATH + 20], mile[32] = "", name[64] = "", ver[32] = "", ua[260], body[400], old[400];
    int major = 0, i; HANDLE h; DWORD w;
    lstrcpyA(file, g_dir); lstrcatA(file, "\\defaults\\pref\\kexng-realos.js");
    if (!os) { DeleteFileA(file); return; }
    lstrcpyA(ini, g_dir); lstrcatA(ini, "\\platform.ini");
    GetPrivateProfileStringA("Build", "Milestone", "", mile, sizeof(mile), ini);
    lstrcpyA(ini, g_dir); lstrcatA(ini, "\\application.ini");
    GetPrivateProfileStringA("App", "Name", "", name, sizeof(name), ini);
    GetPrivateProfileStringA("App", "Version", "", ver, sizeof(ver), ini);
    for (i = 0; mile[i] >= '0' && mile[i] <= '9'; i++) major = major * 10 + (mile[i] - '0');
    if (major < 20) major = 102;                     /* UXP (Goanna milestone): Firefox-compatible token */
    {
        char num[12]; int n = 0, m = major, j;
        for (j = m; j; j /= 10) n++;
        for (j = n - 1, num[n] = 0; j >= 0; j--, m /= 10) num[j] = (char)('0' + m % 10);
        lstrcpyA(ua, "Mozilla/5.0 ("); lstrcatA(ua, os); lstrcatA(ua, "; rv:"); lstrcatA(ua, num);
        lstrcatA(ua, ".0) Gecko/20100101 Firefox/"); lstrcatA(ua, num); lstrcatA(ua, ".0");
        if (name[0] && lstrcmpiA(name, "Firefox") && ver[0]) { lstrcatA(ua, " "); lstrcatA(ua, name); lstrcatA(ua, "/"); lstrcatA(ua, ver); }
    }
    lstrcpyA(body, "// written by KernelEx-NG (KernelEx tab: Report real OS version to websites)\r\npref(\"general.useragent.override\", \"");
    lstrcatA(body, ua); lstrcatA(body, "\");\r\n");
    h = CreateFileA(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD r = 0; ReadFile(h, old, sizeof(old) - 1, &r, NULL); old[r] = 0; CloseHandle(h);
        if (!lstrcmpA(old, body)) return;            /* already there */
    }
    lstrcpyA(ini, g_dir); lstrcatA(ini, "\\defaults"); CreateDirectoryA(ini, NULL);
    lstrcatA(ini, "\\pref"); CreateDirectoryA(ini, NULL);
    h = CreateFileA(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) { WriteFile(h, body, lstrlenA(body), &w, NULL); CloseHandle(h); }
    kex_crashnote("Report real OS version to websites: Gecko pref file written (ok)", h != INVALID_HANDLE_VALUE, 0, 0, 0);
    kex_crashnote(ua, 0, 0, 0, 0);
}

static volatile LONG g_done;
static void realos_init(void)
{
    char p[MAX_PATH + 20]; int i, slash = -1; const char *os;
    if (InterlockedExchange(&g_done, 1)) return;
    if (!GetModuleFileNameA(NULL, g_exe, MAX_PATH)) return;
    for (i = 0; g_exe[i]; i++) if (g_exe[i] == '\\') slash = i;
    if (slash < 0) return;
    lstrcpynA(g_dir, g_exe, slash + 1);
    lstrcpyA(p, g_dir); lstrcatA(p, "\\xul.dll");
    if (file_exists(p)) g_family = 2;
    else {
        lstrcpyA(p, g_dir); lstrcatA(p, "\\chrome.dll");
        if (file_exists(p)) g_family = 1;
        else {                                       /* installed Chrome: <dir>\<version>\chrome.dll */
            WIN32_FIND_DATAA fd; HANDLE f; char q[MAX_PATH + 20];
            lstrcpyA(q, g_dir); lstrcatA(q, "\\*");
            if ((f = FindFirstFileA(q, &fd)) != INVALID_HANDLE_VALUE) {
                int seen = 0;
                do {
                    if (++seen > 64) break;
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == '.') continue;
                    lstrcpyA(q, g_dir); lstrcatA(q, "\\"); lstrcatA(q, fd.cFileName); lstrcatA(q, "\\chrome.dll");
                    if (file_exists(q)) { g_family = 1; break; }
                } while (FindNextFileA(f, &fd));
                FindClose(f);
            }
        }
    }
    if (!g_family) return;
    g_on = setting_on();
    os = g_on ? os_token() : NULL;
    if (g_family == 2) gecko_pref(os);
    else if (os) chromium_prepare(os);
}

/* kexnt.c DLL_PROCESS_ATTACH */
void kex_realos_attach(void) { realos_init(); }

LPWSTR KEXAPI kex_GetCommandLineW(void)
{
    typedef LPWSTR (WINAPI *T_GCLW)(void); static T_GCLW prev;
    realos_init(); chromium_build();
    if (g_cmdw) return g_cmdw;
    if (!prev) prev = (T_GCLW)(void *)kex_prev_impl("KERNEL32.DLL", "GetCommandLineW");
    return prev ? prev() : NULL;
}
LPSTR KEXAPI kex_GetCommandLineA(void)
{
    realos_init(); chromium_build();
    return g_cmda ? g_cmda : GetCommandLineA();
}
