/*
 * env_ext.c - Windows NT's standard path variables for modern programs (build 132).
 *
 * Every Windows NT system defines SystemDrive, SystemRoot, ProgramFiles and CommonProgramFiles in the environment of
 * every process. Windows 98 defines none of them (it has windir). Measured:
 *   - .NET Framework 3.5 SP1 setup (WapUI.dll reads GetEnvironmentVariableW("SystemDrive")): "Setup requires 350 MB of
 *     free space on System Drive, but only 0 MB is available" (dd_dotnetfx35install.txt), setup cannot continue;
 *   - Office 2007 setup: "Failed to check free space in drive "%SystemRoot%" ErrorCode: 2" -> return code 30015;
 *   - .NET 3.5 SP1's WFServicesReg.exe (custom action of the 3.5 package) takes the system as 64-bit unless
 *     GetEnvironmentVariableW("PROCESSOR_ARCHITECTURE") equals "x86", looks for Framework64\v2.0.50727\config\
 *     machine.config and fails (0x80004005), so the 3.5 package rolls back. NT sets PROCESSOR_ARCHITECTURE=x86 on every
 *     32-bit x86 system, and Windows 98 runs only on x86.
 * Here, in programs kexnt serves, a lookup of one of these names (and PROCESSOR_ARCHITECTURE) that the environment does not hold gets the
 * Windows 98 location NT would report: SystemDrive = the Windows folder's drive ("C:"), SystemRoot = the Windows folder,
 * ProgramFiles / CommonProgramFiles = the folders Windows 98 records (HKLM\Software\Microsoft\Windows\CurrentVersion
 * ProgramFilesDir / CommonFilesDir). GetEnvironmentVariableA/W answer them; ExpandEnvironmentStringsA/W replace
 * %NAME% for them before the system expands the rest. A variable that is set is never changed, and the process
 * environment itself is not touched, so Windows 98 programs (also ones a modern program starts) see nothing new.
 */
#include "kexnt_common.h"

FARPROC kex_prev_impl(const char *dll, const char *name);   /* gdiguard_ext.c */

static int name_eq(const char *a, const char *b) { return lstrcmpiA(a, b) == 0; }
static const char *chr(const char *s, char c) { for (; *s; s++) if (*s == c) return s; return NULL; }

static BOOL reg_dir(const char *value, char *out)
{
    HKEY k; DWORD t, n = MAX_PATH; BOOL ok = FALSE;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        ok = RegQueryValueExA(k, value, NULL, &t, (BYTE *)out, &n) == ERROR_SUCCESS && (t == REG_SZ || t == REG_EXPAND_SZ) && out[0];
        RegCloseKey(k);
    }
    return ok;
}

/* the NT default for name (ANSI), or FALSE if name is not one of ours */
static BOOL nt_default(const char *name, char *out)
{
    char w[MAX_PATH];
    if (!name) return FALSE;
    if (name_eq(name, "SystemRoot")) return GetWindowsDirectoryA(out, MAX_PATH) != 0;
    if (name_eq(name, "SystemDrive")) {
        if (!GetWindowsDirectoryA(w, MAX_PATH) || w[1] != ':') return FALSE;
        out[0] = w[0]; out[1] = ':'; out[2] = 0;
        return TRUE;
    }
    if (name_eq(name, "ProgramFiles")) return reg_dir("ProgramFilesDir", out);
    if (name_eq(name, "CommonProgramFiles")) return reg_dir("CommonFilesDir", out);
    if (name_eq(name, "PROCESSOR_ARCHITECTURE")) { lstrcpyA(out, "x86"); return TRUE; }
    return FALSE;
}

typedef DWORD (WINAPI *T_GEVA)(LPCSTR, LPSTR, DWORD);
typedef DWORD (WINAPI *T_GEVW)(LPCWSTR, LPWSTR, DWORD);
typedef DWORD (WINAPI *T_EESA)(LPCSTR, LPSTR, DWORD);
typedef DWORD (WINAPI *T_EESW)(LPCWSTR, LPWSTR, DWORD);

DWORD KEXAPI kex_GetEnvironmentVariableA(LPCSTR name, LPSTR buf, DWORD size)
{
    static T_GEVA prev; char v[MAX_PATH]; DWORD n, r;
    if (!prev) prev = (T_GEVA)(void *)kex_prev_impl("KERNEL32.DLL", "GetEnvironmentVariableA");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    r = prev(name, buf, size);
    if (r || GetLastError() != ERROR_ENVVAR_NOT_FOUND || !nt_default(name, v)) return r;
    n = (DWORD)lstrlenA(v);
    if (!buf || size <= n) return n + 1;
    lstrcpyA(buf, v);
    SetLastError(ERROR_SUCCESS);
    return n;
}

DWORD KEXAPI kex_GetEnvironmentVariableW(LPCWSTR name, LPWSTR buf, DWORD size)
{
    static T_GEVW prev; char an[256], v[MAX_PATH]; DWORD r; int n;
    if (!prev) prev = (T_GEVW)(void *)kex_prev_impl("KERNEL32.DLL", "GetEnvironmentVariableW");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    r = prev(name, buf, size);
    if (r || GetLastError() != ERROR_ENVVAR_NOT_FOUND || !name ||
        !WideCharToMultiByte(CP_ACP, 0, name, -1, an, sizeof(an), NULL, NULL) || !nt_default(an, v)) return r;
    n = MultiByteToWideChar(CP_ACP, 0, v, -1, NULL, 0);           /* with the zero */
    if (n <= 0) return r;
    if (!buf || size < (DWORD)n) return (DWORD)n;
    MultiByteToWideChar(CP_ACP, 0, v, -1, buf, (int)size);
    SetLastError(ERROR_SUCCESS);
    return (DWORD)(n - 1);
}

/* src with %NAME% of our variables (where unset) replaced; NULL if nothing to replace. HeapFree the result. */
static char *pre_expand(const char *src)
{
    const char *p, *q; char name[256], v[MAX_PATH], *o; size_t cap, pos = 0; BOOL any = FALSE;
    static T_GEVA prev;
    if (!src) return NULL;
    if (!prev) prev = (T_GEVA)(void *)kex_prev_impl("KERNEL32.DLL", "GetEnvironmentVariableA");
    cap = (size_t)lstrlenA(src) + 1;
    for (p = src; (p = chr(p, '%')) && (q = chr(p + 1, '%')); p = q + 1) {
        size_t l = (size_t)(q - p - 1);
        if (l && l < sizeof(name)) { memcpy(name, p + 1, l); name[l] = 0;
            if ((!prev || !prev(name, v, MAX_PATH)) && nt_default(name, v)) { any = TRUE; cap += (size_t)lstrlenA(v); } }
    }
    if (!any || !(o = (char *)HeapAlloc(GetProcessHeap(), 0, cap))) return NULL;
    for (p = src; *p; ) {
        if (*p == '%' && (q = chr(p + 1, '%'))) {
            size_t l = (size_t)(q - p - 1);
            if (l && l < sizeof(name)) { memcpy(name, p + 1, l); name[l] = 0;
                if ((!prev || !prev(name, v, MAX_PATH)) && nt_default(name, v)) {
                    lstrcpyA(o + pos, v); pos += (size_t)lstrlenA(v); p = q + 1; continue; } }
            memcpy(o + pos, p, (size_t)(q - p)); pos += (size_t)(q - p); p = q;   /* keep "%...", the second % may open the next */
            continue;
        }
        o[pos++] = *p++;
    }
    o[pos] = 0;
    return o;
}

DWORD KEXAPI kex_ExpandEnvironmentStringsA(LPCSTR src, LPSTR dst, DWORD size)
{
    static T_EESA prev; char *s; DWORD r;
    if (!prev) prev = (T_EESA)(void *)kex_prev_impl("KERNEL32.DLL", "ExpandEnvironmentStringsA");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    if (!(s = pre_expand(src))) return prev(src, dst, size);
    r = prev(s, dst, size);
    HeapFree(GetProcessHeap(), 0, s);
    return r;
}

DWORD KEXAPI kex_ExpandEnvironmentStringsW(LPCWSTR src, LPWSTR dst, DWORD size)
{
    static T_EESW prev; char *a, *s; int n; WCHAR *w; DWORD r;
    if (!prev) prev = (T_EESW)(void *)kex_prev_impl("KERNEL32.DLL", "ExpandEnvironmentStringsW");
    if (!prev) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    if (!src || (n = WideCharToMultiByte(CP_ACP, 0, src, -1, NULL, 0, NULL, NULL)) <= 0 ||
        !(a = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)n))) return prev(src, dst, size);
    WideCharToMultiByte(CP_ACP, 0, src, -1, a, n, NULL, NULL);
    s = pre_expand(a);
    HeapFree(GetProcessHeap(), 0, a);
    if (!s) return prev(src, dst, size);
    n = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    w = n > 0 ? (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)n * sizeof(WCHAR)) : NULL;
    if (!w) { HeapFree(GetProcessHeap(), 0, s); return prev(src, dst, size); }
    MultiByteToWideChar(CP_ACP, 0, s, -1, w, n);
    HeapFree(GetProcessHeap(), 0, s);
    r = prev(w, dst, size);
    HeapFree(GetProcessHeap(), 0, w);
    return r;
}
