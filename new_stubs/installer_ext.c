/* installer_ext.c - functions installers and runtimes import that Windows 98 + KernelEx 4.5.2 lack (build 124).
 *
 * Found by running the programs in the test VM (GPA.EXE probe = GetProcAddress through KernelEx's resolver,
 * and the "linked to missing export" box):
 *   NTDLL    NtShutdownSystem          Visual C++ 2010 redistributable (vcredist_x86.exe, the extractor)
 *   KERNEL32 GetSystemWow64DirectoryA/W Visual C++ 2013 redistributable (WiX Burn bootstrapper)
 *   KERNEL32 GetNumaHighestNodeNumber  msvcr120.dll (Visual C++ 2013 runtime) - static import, so every
 *                                      program built with VS 2013 failed to start
 *   ADVAPI32 StartTraceA/W, ControlTraceA/W, EnableTrace, EnumerateTraceGuids
 *                                      Visual Studio 2010 setup engine (SetupEngine.dll, event tracing)
 * Behaviour (documentation only):
 *   GetSystemWow64Directory    on 32-bit Windows: returns 0, last error ERROR_CALL_NOT_IMPLEMENTED.
 *   GetNumaHighestNodeNumber   a machine without NUMA has one node: 0, TRUE.
 *   Event tracing (ETW)        Windows 98 has no event tracing: the session functions answer
 *                              ERROR_ACCESS_DENIED - the result a program gets on NT when it may not start a
 *                              trace session, so its existing error path runs; EnumerateTraceGuids lists none.
 *   NtShutdownSystem(action)   0 shut down, 1 restart, 2 power off - through USER32 ExitWindowsEx with EWX_FORCE
 *                              (NtShutdownSystem does not ask programs either). Logged in KEXCRASH. */
#include "kexnt_common.h"

void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);   /* crashlog_ext.c */

UINT KEXAPI kex_GetSystemWow64DirectoryA(LPSTR buf, UINT n)
{ (void)buf; (void)n; SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
UINT KEXAPI kex_GetSystemWow64DirectoryW(LPWSTR buf, UINT n)
{ (void)buf; (void)n; SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }

BOOL KEXAPI kex_GetNumaHighestNodeNumber(PULONG highest)
{
    if (!highest || IsBadWritePtr(highest, sizeof(*highest))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *highest = 0;
    return TRUE;
}

ULONG KEXAPI kex_StartTraceW(PVOID handle, LPCWSTR name, PVOID props)
{ (void)handle; (void)name; (void)props; return ERROR_ACCESS_DENIED; }
ULONG KEXAPI kex_StartTraceA(PVOID handle, LPCSTR name, PVOID props)
{ (void)handle; (void)name; (void)props; return ERROR_ACCESS_DENIED; }
ULONG KEXAPI kex_ControlTraceW(ULONGLONG handle, LPCWSTR name, PVOID props, ULONG code)
{ (void)handle; (void)name; (void)props; (void)code; return ERROR_ACCESS_DENIED; }
ULONG KEXAPI kex_ControlTraceA(ULONGLONG handle, LPCSTR name, PVOID props, ULONG code)
{ (void)handle; (void)name; (void)props; (void)code; return ERROR_ACCESS_DENIED; }
ULONG KEXAPI kex_EnableTrace(ULONG enable, ULONG flags, ULONG level, LPCGUID guid, ULONGLONG session)
{ (void)enable; (void)flags; (void)level; (void)guid; (void)session; return ERROR_ACCESS_DENIED; }
ULONG KEXAPI kex_EnumerateTraceGuids(PVOID *props, ULONG count, PULONG got)
{
    (void)props; (void)count;
    if (!got || IsBadWritePtr(got, sizeof(*got))) return ERROR_INVALID_PARAMETER;
    *got = 0;
    return ERROR_SUCCESS;
}

NTSTATUS KEXAPI kex_NtShutdownSystem(ULONG action)
{
    typedef BOOL (WINAPI *T_EWX)(UINT, DWORD);
    T_EWX ewx = (T_EWX)(void *)kex_sysproc("USER32.DLL", "ExitWindowsEx");
    UINT how = action == 1 ? EWX_REBOOT : action == 2 ? EWX_POWEROFF : EWX_SHUTDOWN;
    if (action > 2) return STATUS_INVALID_PARAMETER;
    kex_crashnote("NtShutdownSystem: Windows shut down / restarted by this program (action, 0 = off, 1 = restart, 2 = power off)",
                  action, 0, 0, 0);
    if (!ewx || !ewx(how | EWX_FORCE, 0)) return STATUS_NOT_SUPPORTED;
    return STATUS_SUCCESS;
}

/* SECUR32 GetComputerObjectNameA/W (Visual Studio 2010 setup engine): the computer's name in a directory
 * service. A Windows 98 machine is not a domain member: FALSE, ERROR_CANT_ACCESS_DOMAIN_INFO (as NT answers
 * for a workgroup machine). The size is left as given. */
BOOLEAN KEXAPI kex_GetComputerObjectNameW(int format, LPWSTR name, PULONG size)
{ (void)format; (void)name; (void)size; SetLastError(ERROR_CANT_ACCESS_DOMAIN_INFO); return FALSE; }
BOOLEAN KEXAPI kex_GetComputerObjectNameA(int format, LPSTR name, PULONG size)
{ (void)format; (void)name; (void)size; SetLastError(ERROR_CANT_ACCESS_DOMAIN_INFO); return FALSE; }

/* ---- Windows Installer 3.x functions on Windows Installer 2.0 (MSI.DLL 2.0.2600, the last for Windows 98) ----
 * Setup programs import these BY ORDINAL (Visual Studio 2010's SetupEngine.dll: 242, 244, 246, 254, 270, 281), so
 * with MSI 2.0 the DLL does not load at all. Ordinals: Windows Installer's own numbering (also used by Wine's
 * msi.spec). What each answers on a machine that only has Windows Installer 2.0 - per-machine installs only (no
 * per-user contexts, no user SIDs), and no Windows Installer 3 patches (MSI 2.0 cannot apply them):
 *   MsiEnumProductsExW (246)      the products MSI 2.0 knows, in the machine context (MsiEnumProductsW /
 *                                 MsiQueryProductStateW); a user SID or a user-only context: none
 *   MsiEnumPatchesExW (270)       none installed (ERROR_NO_MORE_ITEMS)
 *   MsiGetPatchInfoExW (244)      ERROR_UNKNOWN_PATCH
 *   MsiExtractPatchXMLDataW (242) ERROR_PATCH_PACKAGE_OPEN_FAILED (this installer cannot read it)
 *   MsiDeterminePatchSequenceW (254) every patch "does not apply" (dwOrder -1, ERROR_PATCH_TARGET_NOT_FOUND):
 *                                 Windows Installer 2.0 cannot install them
 *   MsiSetExternalUIRecord (281)  record UI bridged onto MSI 2.0's string UI (below)
 *   MsiRemovePatchesA/W (237/238) ERROR_PATCH_REMOVAL_UNSUPPORTED. Windows Installer 2.0 exports DllCanUnloadNow,
 *                                 DllGetClassObject, DllRegisterServer, DllUnregisterServer at 237-240; programs
 *                                 for Windows Installer 3 import MsiRemovePatches/MsiApplyMultiplePatches there
 *                                 and would have called the wrong function.
 *   MsiApplyMultiplePatchesA/W (239/240) each patch of the ';' list through Windows Installer 2.0's MsiApplyPatch
 * Every call is noted once in the program's KEXCRASH log. */
#define MSICTX_USERMANAGED   1
#define MSICTX_USERUNMANAGED 2
#define MSICTX_MACHINE       4
typedef struct { LPCWSTR data; int type; DWORD order; UINT status; } KEX_MSIPATCHSEQINFOW;
static void msi_note(int i, const char *what)
{
    static volatile LONG seen[12];
    if (i >= 0 && i < 12 && !InterlockedExchange((LONG *)&seen[i], 1))
        kex_crashnote(what, 0, 0, 0, 0);
}

UINT KEXAPI kex_MsiEnumProductsExW(LPCWSTR product, LPCWSTR sid, DWORD ctx, DWORD index, WCHAR code[39],
                                   DWORD *got_ctx, LPWSTR got_sid, LPDWORD sid_len)
{
    typedef UINT (WINAPI *T_EP)(DWORD, LPWSTR);
    typedef int (WINAPI *T_QS)(LPCWSTR);
    WCHAR buf[39];
    msi_note(0, "MSI: MsiEnumProductsExW (Windows Installer 3) answered from Windows Installer 2.0's product list");
    if (sid || !(ctx & MSICTX_MACHINE)) return ERROR_NO_MORE_ITEMS;   /* no per-user installs on Windows 98 */
    if (product) {
        T_QS qs = (T_QS)(void *)kex_sysproc("MSI.DLL", "MsiQueryProductStateW");
        if (index || !qs || qs(product) < 1 /* INSTALLSTATE_ADVERTISED */) return ERROR_NO_MORE_ITEMS;
        lstrcpynW(buf, product, 39);
    } else {
        T_EP ep = (T_EP)(void *)kex_sysproc("MSI.DLL", "MsiEnumProductsW");
        UINT r;
        if (!ep) return ERROR_NO_MORE_ITEMS;
        if ((r = ep(index, buf)) != ERROR_SUCCESS) return r;
    }
    if (code) lstrcpynW(code, buf, 39);
    if (got_ctx) *got_ctx = MSICTX_MACHINE;
    if (sid_len) { if (got_sid && *sid_len) got_sid[0] = 0; *sid_len = 0; }
    return ERROR_SUCCESS;
}

UINT KEXAPI kex_MsiEnumPatchesExW(LPCWSTR product, LPCWSTR sid, DWORD ctx, DWORD filter, DWORD index, WCHAR patch[39],
                                  WCHAR target[39], DWORD *got_ctx, LPWSTR got_sid, LPDWORD sid_len)
{
    (void)product; (void)sid; (void)ctx; (void)filter; (void)index; (void)patch; (void)target; (void)got_ctx;
    (void)got_sid; (void)sid_len;
    msi_note(1, "MSI: MsiEnumPatchesExW (Windows Installer 3) - none (Windows Installer 2.0)");
    return ERROR_NO_MORE_ITEMS;
}

UINT KEXAPI kex_MsiGetPatchInfoExW(LPCWSTR patch, LPCWSTR product, LPCWSTR sid, DWORD ctx, LPCWSTR prop, LPWSTR val, LPDWORD len)
{
    (void)patch; (void)product; (void)sid; (void)ctx; (void)prop; (void)val; (void)len;
    msi_note(2, "MSI: MsiGetPatchInfoExW (Windows Installer 3) - unknown patch (Windows Installer 2.0)");
    return ERROR_UNKNOWN_PATCH;
}

UINT KEXAPI kex_MsiExtractPatchXMLDataW(LPCWSTR patch, DWORD reserved, LPWSTR buf, LPDWORD len)
{
    (void)patch; (void)reserved; (void)buf; (void)len;
    msi_note(3, "MSI: MsiExtractPatchXMLDataW (Windows Installer 3) - refused (Windows Installer 2.0)");
    return ERROR_PATCH_PACKAGE_OPEN_FAILED;
}

UINT KEXAPI kex_MsiDeterminePatchSequenceW(LPCWSTR product, LPCWSTR sid, DWORD ctx, DWORD count, KEX_MSIPATCHSEQINFOW *info)
{
    DWORD i;
    (void)product; (void)sid; (void)ctx;
    msi_note(4, "MSI: MsiDeterminePatchSequenceW (Windows Installer 3) - patches do not apply (Windows Installer 2.0)");
    if (!count || !info || IsBadWritePtr(info, count * sizeof(*info))) return ERROR_INVALID_PARAMETER;
    for (i = 0; i < count; i++) { info[i].order = (DWORD)-1; info[i].status = ERROR_PATCH_TARGET_NOT_FOUND; }
    return ERROR_SUCCESS;
}

/* MsiSourceListAddSourceExA/W (Windows Installer 3.0) on Windows Installer 2.0's MsiSourceListAddSourceA/W (build 125).
 * Measured (VC++ 2013 setup, WiX Burn 3.7): the elevated Burn process loads it with GetProcAddress and, after a package
 * installed, calls it without a NULL check (vcredist_x86.exe+34271 "call [MsiSourceListAddSourceExW]") -> with no
 * export it called address 0 ("invalid instruction at 0000:00000017", the bytes of the real-mode interrupt table).
 * Products: the source is added to the product's network source list (2.0 has one list; dwIndex/position and the
 * URL type have no 2.0 equivalent, the source is appended). Patches (MSICODE_PATCH) are unknown to 2.0. */
#define K_MSICODE_PATCH 0x40000000UL
typedef UINT (WINAPI *T_SLASW)(LPCWSTR, LPCWSTR, DWORD, LPCWSTR);
typedef UINT (WINAPI *T_SLASA)(LPCSTR, LPCSTR, DWORD, LPCSTR);
UINT KEXAPI kex_MsiSourceListAddSourceExW(LPCWSTR code, LPCWSTR sid, DWORD ctx, DWORD opt, LPCWSTR src, DWORD index)
{
    static T_SLASW f;
    (void)sid; (void)ctx; (void)index;
    msi_note(8, "MSI: MsiSourceListAddSourceExW (Windows Installer 3) -> Windows Installer 2.0 MsiSourceListAddSourceW");
    if (!code || !src) return ERROR_INVALID_PARAMETER;
    if (opt & K_MSICODE_PATCH) return ERROR_UNKNOWN_PATCH;
    if (!f) f = (T_SLASW)(void *)kex_sysproc("MSI.DLL", "MsiSourceListAddSourceW");
    if (!f) return ERROR_CALL_NOT_IMPLEMENTED;
    return f(code, NULL, 0, src);
}
UINT KEXAPI kex_MsiSourceListAddSourceExA(LPCSTR code, LPCSTR sid, DWORD ctx, DWORD opt, LPCSTR src, DWORD index)
{
    static T_SLASA f;
    (void)sid; (void)ctx; (void)index;
    if (!code || !src) return ERROR_INVALID_PARAMETER;
    if (opt & K_MSICODE_PATCH) return ERROR_UNKNOWN_PATCH;
    if (!f) f = (T_SLASA)(void *)kex_sysproc("MSI.DLL", "MsiSourceListAddSourceA");
    if (!f) return ERROR_CALL_NOT_IMPLEMENTED;
    return f(code, NULL, 0, src);
}

/* MsiSetExternalUIRecord (Windows Installer 3.1) on top of Windows Installer 2.0's string UI (build 125).
 * Visual Studio 2010's setup engine decides "Windows Installer 3.1 or higher is required" by
 * GetProcAddress(msi.dll, "MsiSetExternalUIRecord") (measured: SetupEngine.dll+6d22a), then uses it for progress.
 * Here MSI 2.0's MsiSetExternalUIW gets kexnt's string handler, which turns every message into a record:
 *   PROGRESS / COMMONDATA ("1: a 2: b 3: c 4: d")  -> integer fields 1..4, as Windows Installer 3.1 sends them
 *   everything else                                 -> the message text in field 0 (MsiFormatRecord gives it back)
 * and calls the program's record handler with it; its answer goes back to Windows Installer. */
typedef int (WINAPI *T_RECUI)(LPVOID, UINT, DWORD);
typedef int (WINAPI *T_STRUI)(LPVOID, UINT, LPCWSTR);
static T_RECUI g_recui; static LPVOID g_recctx;
static int WINAPI rec_bridge(LPVOID ctx, UINT type, LPCWSTR msg)
{
    typedef DWORD (WINAPI *T_CR)(UINT); typedef UINT (WINAPI *T_SI)(DWORD, UINT, int);
    typedef UINT (WINAPI *T_SS)(DWORD, UINT, LPCWSTR); typedef UINT (WINAPI *T_CH)(DWORD);
    static T_CR cr; static T_SI si; static T_SS ss; static T_CH ch;
    T_RECUI h = g_recui; DWORD rec; int r, kind = (int)((type >> 24) & 0xFF);
    (void)ctx;
    if (!h) return 0;
    if (!cr) { cr = (T_CR)(void *)kex_sysproc("MSI.DLL", "MsiCreateRecord"); si = (T_SI)(void *)kex_sysproc("MSI.DLL", "MsiRecordSetInteger");
               ss = (T_SS)(void *)kex_sysproc("MSI.DLL", "MsiRecordSetStringW"); ch = (T_CH)(void *)kex_sysproc("MSI.DLL", "MsiCloseHandle"); }
    if (!cr || !si || !ss || !ch) return 0;
    if ((kind == 0x0A || kind == 0x0B) && msg) {          /* INSTALLMESSAGE_PROGRESS / _COMMONDATA */
        int f, v, neg; const WCHAR *q = msg;
        rec = cr(4);
        if (!rec) return 0;
        while (*q) {
            while (*q == L' ') q++;
            if (*q < L'0' || *q > L'9') break;
            for (f = 0; *q >= L'0' && *q <= L'9'; q++) f = f * 10 + (*q - L'0');
            if (*q != L':') break;
            q++; while (*q == L' ') q++;
            neg = *q == L'-'; if (neg) q++;
            for (v = 0; *q >= L'0' && *q <= L'9'; q++) v = v * 10 + (*q - L'0');
            if (f >= 1 && f <= 4) si(rec, (UINT)f, neg ? -v : v);
            while (*q && *q != L' ') q++;
        }
    } else {
        rec = cr(0);
        if (!rec) return 0;
        if (msg) ss(rec, 0, msg);
    }
    r = h(g_recctx, type, rec);
    ch(rec);
    return r;
}
UINT KEXAPI kex_MsiSetExternalUIRecord(PVOID handler, DWORD filter, PVOID ctx, PVOID *prev)
{
    typedef T_STRUI (WINAPI *T_SEUI)(T_STRUI, DWORD, LPVOID);
    T_SEUI seui = (T_SEUI)(void *)kex_sysproc("MSI.DLL", "MsiSetExternalUIW");
    msi_note(5, "MSI: MsiSetExternalUIRecord (Windows Installer 3.1) -> Windows Installer 2.0 MsiSetExternalUIW + kexnt record bridge");
    if (prev) { if (IsBadWritePtr(prev, sizeof(*prev))) return ERROR_INVALID_PARAMETER; *prev = (PVOID)g_recui; }
    if (!seui) return ERROR_CALL_NOT_IMPLEMENTED;
    g_recctx = ctx; g_recui = (T_RECUI)handler;
    seui(handler ? rec_bridge : NULL, handler ? filter : 0, NULL);
    return ERROR_SUCCESS;
}

/* ---- QueryDosDeviceA/W ----
 * Windows 98's own QueryDosDevice fails every call (ERROR_INVALID_PARAMETER, measured with QDD.EXE in the test
 * VM). The Visual C++ 2010 redistributable's extractor picks the drive to unpack to with QueryDosDeviceA("x:")
 * and only takes a drive whose NT device name contains "harddisk" or "ramdisk" -> on Windows 98 it found none:
 * "Unable to find a volume for file extraction". kexnt answers with the NT device names (documented format):
 *   fixed disk          \Device\HarddiskVolumeN   (N = 1, 2, ... in drive-letter order)
 *   A: / B: floppy      \Device\Floppy0 / 1        other removable drives \Device\HarddiskVolumeN too
 *   CD-ROM              \Device\CdRomN             (N = 0, 1, ...)
 *   network drive       \Device\LanmanRedirector\;X:0
 *   RAM disk            \Device\Ramdisk
 *   NUL, COMn, LPTn     \Device\Null, \Device\Serial(n-1), \Device\Parallel(n-1)
 *   NULL name           the list of drive letters in use, then NUL, COM1..4, LPT1..3 (double-0 terminated)
 * Return value: characters stored, including both terminating zeros (as on NT). Unknown names:
 * ERROR_FILE_NOT_FOUND. Windows 98 programs keep Windows' own answer (gate). */
static BOOL ci_prefix(const char *s, const char *p)   /* ASCII, case-insensitive */
{
    for (; *p; s++, p++) if ((*s | 32) != (*p | 32)) return FALSE;
    return TRUE;
}
/* NT device name for one DOS device name -> out (double-0 terminated); characters stored, or (DWORD)-1 + error */
static DWORD dosdev_target(const char *name, char *out, DWORD cap)
{
    char t[96], root[4]; int n, k, idx = 0, len = lstrlenA(name);
    if (len == 2 && name[1] == ':' && (name[0] | 32) >= 'a' && (name[0] | 32) <= 'z') {
        char L = (char)(name[0] & ~32); UINT type;
        root[0] = L; root[1] = ':'; root[2] = '\\'; root[3] = 0;
        type = GetDriveTypeA(root);
        if (type == DRIVE_NO_ROOT_DIR || type == DRIVE_UNKNOWN) { SetLastError(ERROR_FILE_NOT_FOUND); return (DWORD)-1; }
        if (type == DRIVE_REMOVABLE && (L == 'A' || L == 'B')) { lstrcpyA(t, "\\Device\\Floppy0"); t[14] = (char)('0' + (L - 'A')); }
        else if (type == DRIVE_CDROM || type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
            for (k = 'C'; k < L; k++) {           /* earlier drives of the same family (A:/B: are floppies) */
                UINT t2; root[0] = (char)k; t2 = GetDriveTypeA(root);
                if (type == DRIVE_CDROM ? t2 == DRIVE_CDROM : (t2 == DRIVE_FIXED || t2 == DRIVE_REMOVABLE)) idx++;
            }
            if (type == DRIVE_CDROM) lstrcpyA(t, "\\Device\\CdRom");
            else { lstrcpyA(t, "\\Device\\HarddiskVolume"); idx++; }
            n = lstrlenA(t);
            if (idx >= 10) t[n++] = (char)('0' + idx / 10);
            t[n++] = (char)('0' + idx % 10); t[n] = 0;
        } else if (type == DRIVE_REMOTE) { lstrcpyA(t, "\\Device\\LanmanRedirector\\;X:0"); t[26] = L; }
        else lstrcpyA(t, "\\Device\\Ramdisk");
    } else if (len == 3 && ci_prefix(name, "NUL")) lstrcpyA(t, "\\Device\\Null");
    else if (len == 4 && (ci_prefix(name, "COM") || ci_prefix(name, "LPT")) && name[3] >= '1' && name[3] <= '9') {
        lstrcpyA(t, ci_prefix(name, "COM") ? "\\Device\\Serial" : "\\Device\\Parallel");
        n = lstrlenA(t); t[n++] = (char)(name[3] - 1); t[n] = 0;
    } else { SetLastError(ERROR_FILE_NOT_FOUND); return (DWORD)-1; }
    n = lstrlenA(t);
    if ((DWORD)n + 2 > cap) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return (DWORD)-1; }
    memcpy(out, t, n); out[n] = 0; out[n + 1] = 0;
    return (DWORD)n + 2;
}
/* NULL name: every DOS device name (drive letters in use, NUL, COM1-4, LPT1-3), double-0 terminated */
static DWORD dosdev_list(char *out, DWORD cap)
{
    static const char *dev[] = { "NUL", "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3" };
    DWORD drives = GetLogicalDrives(), pos = 0; int k, i;
    char d[3] = "A:";
    for (k = 0; k < 26 + 8; k++) {
        const char *s;
        if (k < 26) { if (!(drives & (1u << k))) continue; d[0] = (char)('A' + k); s = d; } else s = dev[k - 26];
        i = lstrlenA(s);
        if (pos + i + 2 > cap) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
        memcpy(out + pos, s, i + 1); pos += i + 1;
    }
    if (pos + 1 > cap) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
    out[pos++] = 0;
    return pos;
}
DWORD KEXAPI kex_QueryDosDeviceA(LPCSTR name, LPSTR buf, DWORD cap)
{
    DWORD r;
    if (!buf || (cap && IsBadWritePtr(buf, cap))) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!name) return dosdev_list(buf, cap);
    if (IsBadStringPtrA(name, MAX_PATH)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    r = dosdev_target(name, buf, cap);
    return r == (DWORD)-1 ? 0 : r;
}
DWORD KEXAPI kex_QueryDosDeviceW(LPCWSTR name, LPWSTR buf, DWORD cap)
{
    char an[MAX_PATH], tmp[2048]; DWORD r, i;
    if (!buf || (cap && IsBadWritePtr(buf, cap * sizeof(WCHAR)))) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (name) {
        if (IsBadStringPtrW(name, MAX_PATH)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
        for (i = 0; name[i] && i < MAX_PATH - 1; i++) { if (name[i] > 127) { SetLastError(ERROR_FILE_NOT_FOUND); return 0; } an[i] = (char)name[i]; }
        an[i] = 0;
    }
    r = kex_QueryDosDeviceA(name ? an : NULL, tmp, cap < sizeof(tmp) ? cap : sizeof(tmp));
    for (i = 0; i < r; i++) buf[i] = (WCHAR)(BYTE)tmp[i];   /* device names are ASCII */
    return r;
}

/* ---- WLDAP32 ber_free (ordinal 301) ----
 * Windows 98's WLDAP32.DLL has no ber_free. libcurl (here 7.26.0, shipped with Geometry Dash) imports it by
 * ordinal 301 for its LDAP support, so the program did not start: "LIBCURL.DLL is linked to missing export
 * WLDAP32.DLL:301". (301 = ber_free: libcurl's LDAP code calls 16 WLDAP32 functions, the other 15 are imported by
 * ordinals Windows 98's WLDAP32 maps to their names.) Windows 98's LDAP library allocates the BerElement that
 * ldap_first_attribute hands out by its own means, which we cannot free safely - so this ber_free gives
 * nothing back: one small block per LDAP search result is left, and only in programs that do LDAP. cdecl. */
void __cdecl kex_c_ber_free(void *ber, int fbuf) { (void)ber; (void)fbuf; }

UINT KEXAPI kex_MsiRemovePatchesW(LPCWSTR list, LPCWSTR product, int type, LPCWSTR props)
{
    (void)list; (void)product; (void)type; (void)props;
    msi_note(6, "MSI: MsiRemovePatchesW (Windows Installer 3) - not possible with Windows Installer 2.0");
    return ERROR_PATCH_REMOVAL_UNSUPPORTED;
}
UINT KEXAPI kex_MsiRemovePatchesA(LPCSTR list, LPCSTR product, int type, LPCSTR props)
{
    (void)list; (void)product; (void)type; (void)props;
    msi_note(6, "MSI: MsiRemovePatchesA (Windows Installer 3) - not possible with Windows Installer 2.0");
    return ERROR_PATCH_REMOVAL_UNSUPPORTED;
}
/* MsiApplyPatch(patch, install package or NULL, INSTALLTYPE_DEFAULT, command line) per list entry */
UINT KEXAPI kex_MsiApplyMultiplePatchesW(LPCWSTR list, LPCWSTR product, LPCWSTR props)
{
    typedef UINT (WINAPI *T_AP)(LPCWSTR, LPCWSTR, int, LPCWSTR);
    T_AP ap = (T_AP)(void *)kex_sysproc("MSI.DLL", "MsiApplyPatchW");
    WCHAR one[MAX_PATH]; UINT r = ERROR_SUCCESS; int n;
    (void)product;   /* MSI 2.0 applies a patch to every product it targets */
    msi_note(7, "MSI: MsiApplyMultiplePatchesW (Windows Installer 3) -> Windows Installer 2.0 MsiApplyPatchW per patch");
    if (!list || !*list) return ERROR_INVALID_PARAMETER;
    if (!ap) return ERROR_CALL_NOT_IMPLEMENTED;
    while (*list && r == ERROR_SUCCESS) {
        for (n = 0; list[n] && list[n] != L';' && n < MAX_PATH - 1; n++) one[n] = list[n];
        one[n] = 0; list += n; if (*list == L';') list++;
        if (n) r = ap(one, NULL, 0, props);
    }
    return r;
}
UINT KEXAPI kex_MsiApplyMultiplePatchesA(LPCSTR list, LPCSTR product, LPCSTR props)
{
    WCHAR wl[1024], wp[1024]; (void)product;
    if (!list || !MultiByteToWideChar(CP_ACP, 0, list, -1, wl, 1024)) return ERROR_INVALID_PARAMETER;
    if (props && !MultiByteToWideChar(CP_ACP, 0, props, -1, wp, 1024)) return ERROR_INVALID_PARAMETER;
    return kex_MsiApplyMultiplePatchesW(wl, NULL, props ? wp : NULL);
}

/* ---- GetPrivateProfileStringW: the default value, as on NT ----
 * Windows 9x strips trailing white space - including a newline - from lpDefault; NT strips trailing blanks (spaces)
 * only. NSIS 3 (the Unicode NSIS of the Firefox 52 ESR and Mypal 29 installers) reads INI values with the default
 * "\n" and treats an answer that starts with "\n" as "no such key". On Windows 98 the answer was "" - "the key
 * exists and is empty" - so Mozilla's installer script, which looks for the first free "ShortcutN" entry in
 * uninstall\shortcuts_log.ini, looped forever near the end of the install (found with SAMPLE.EXE / DUMPMEM.EXE in
 * the test VM: the install thread spinning in NSIS string code, shortcuts_log.ini + "STARTMENU" in its variables;
 * INI.EXE: Windows 98 / KernelEx return "" for a missing key with default "\n", "xyz" for default "xyz").
 * Here: Windows 98's own GetPrivateProfileStringA is asked (W -> A in the ANSI code page, as UNICOWS does) with a
 * sentinel default that has no white space; if the
 * sentinel comes back the key (or section, or file) is missing and the caller's default is returned with only
 * trailing spaces removed (NT). Enumerations (section or key NULL) go through unchanged. This W function is a
 * KernelEx addition on Windows 98 (Windows' own GetPrivateProfileStringW does nothing), so the gate gives kexnt's
 * version to Windows 9x programs as well (gate_ext.c g_always). */
typedef DWORD (WINAPI *T_GPPSW)(LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, DWORD, LPCWSTR);
typedef DWORD (WINAPI *T_GPPSA)(LPCSTR, LPCSTR, LPCSTR, LPSTR, DWORD, LPCSTR);
static char *w2a_dup(LPCWSTR w)
{
    int n; char *a;
    if (!w) return NULL;
    n = WideCharToMultiByte(CP_ACP, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 0 || !(a = (char *)HeapAlloc(GetProcessHeap(), 0, n))) return NULL;
    WideCharToMultiByte(CP_ACP, 0, w, -1, a, n, NULL, NULL);
    return a;
}
DWORD KEXAPI kex_GetPrivateProfileStringW(LPCWSTR app, LPCWSTR key, LPCWSTR def, LPWSTR buf, DWORD size, LPCWSTR file)
{
    static const char sentinel[] = "<KexNG:no-value>";   /* no white space: Windows 98 keeps it intact */
    static T_GPPSW prevw; static T_GPPSA ga;
    char *aapp = NULL, *akey = NULL, *afile = NULL, *tmp = NULL; DWORD asize, r, n, i, le; HANDLE heap = GetProcessHeap();
    FARPROC kex_prev_impl(const char *dll, const char *name);
    {   /* build 126: UTF-16 INI files as on NT (uini_ext.c) */
        DWORD KEXAPI kex_uini_GetPrivateProfileStringW(LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, DWORD, LPCWSTR);
        DWORD u = kex_uini_GetPrivateProfileStringW(app, key, def, buf, size, file);
        if (u != (DWORD)-2) return u;
    }
    if (!app || !key || !buf || !size) {    /* section / key lists: unchanged (UNICOWS, as KernelEx gave before) */
        if (!prevw) {
            HMODULE u = LoadLibraryA("UNICOWS.DLL");
            prevw = (T_GPPSW)(void *)(u ? GetProcAddress(u, "GetPrivateProfileStringW") : NULL);
            if (!prevw) prevw = (T_GPPSW)(void *)kex_prev_impl("KERNEL32.DLL", "GetPrivateProfileStringW");
        }
        if (!prevw) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
        return prevw(app, key, def, buf, size, file);
    }
    if (!ga) ga = (T_GPPSA)(void *)kex_sysproc("KERNEL32.DLL", "GetPrivateProfileStringA");
    if (!ga) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0; }
    asize = size * 2 + 64;                  /* room for double-byte characters and the sentinel */
    aapp = w2a_dup(app); akey = w2a_dup(key); afile = file ? w2a_dup(file) : NULL;
    tmp = (char *)HeapAlloc(heap, 0, asize);
    if (!aapp || !akey || (file && !afile) || !tmp) { r = 0; buf[0] = 0; SetLastError(ERROR_NOT_ENOUGH_MEMORY); goto out; }
    r = ga(aapp, akey, sentinel, tmp, asize, afile);
    le = GetLastError();
    if (r == sizeof(sentinel) - 1 && !lstrcmpA(tmp, sentinel)) {      /* missing: the caller's default, NT style */
        n = 0;
        if (def && !IsBadStringPtrW(def, 32767)) { n = (DWORD)lstrlenW(def); while (n && def[n - 1] == L' ') n--; }
        if (n > size - 1) n = size - 1;
        for (i = 0; i < n; i++) buf[i] = def[i];
        buf[n] = 0; r = n;
    } else {
        int w = MultiByteToWideChar(CP_ACP, 0, tmp, (int)r, buf, (int)size - 1);
        if (w <= 0 && r) {                  /* did not fit: convert into a temporary, keep what fits */
            int need = MultiByteToWideChar(CP_ACP, 0, tmp, (int)r, NULL, 0);
            WCHAR *t2 = need > 0 ? (WCHAR *)HeapAlloc(heap, 0, need * sizeof(WCHAR)) : NULL;
            w = 0;
            if (t2) { MultiByteToWideChar(CP_ACP, 0, tmp, (int)r, t2, need); w = need < (int)size - 1 ? need : (int)size - 1;
                      for (i = 0; i < (DWORD)w; i++) buf[i] = t2[i]; HeapFree(heap, 0, t2); }
        }
        buf[w > 0 ? w : 0] = 0; r = w > 0 ? (DWORD)w : 0;
    }
    SetLastError(le);
out:
    if (aapp) HeapFree(heap, 0, aapp);
    if (akey) HeapFree(heap, 0, akey);
    if (afile) HeapFree(heap, 0, afile);
    if (tmp) HeapFree(heap, 0, tmp);
    return r;
}

/* ---- RtlGetVersion for configurations without a KernelEx-NG version profile (build 126) ----
 * Measured (VC++ 2015-2022 setup, WiX Burn 3.14, run as Windows XP - KernelEx's own WINXP configuration): after
 * GetModuleHandle("ntdll") worked (kexnt.c), "Error 0x8007007f: Failed to locate RtlGetVersion" -> VersionNT not set
 * -> the setup failed. RtlGetVersion exists since Windows 2000. The version profiles (kexver.c) answer it themselves;
 * this one serves the other configurations with what GetVersionExW reports for this program. */
typedef BOOL (WINAPI *T_GVXW)(OSVERSIONINFOW *);
LONG KEXAPI kex_RtlGetVersion(OSVERSIONINFOW *v)
{
    static T_GVXW gv; FARPROC kex_prev_impl(const char *dll, const char *name);
    if (!v || IsBadWritePtr(v, sizeof(OSVERSIONINFOW))) return (LONG)0xC000000DL;                  /* STATUS_INVALID_PARAMETER */
    if (v->dwOSVersionInfoSize != sizeof(OSVERSIONINFOW) && v->dwOSVersionInfoSize != sizeof(OSVERSIONINFOEXW)) return (LONG)0xC000000DL;
    /* the GetVersionExW this program's configuration gives (KernelEx resolves GetProcAddress per configuration);
     * kex_prev_impl gave Windows 98's own (measured: 4.10 while the program saw 5.1) */
    if (!gv) {   /* through the API-set shell in SYSTEM: KernelEx resolves a SYSTEM module's KERNEL32 link with this
                  * process's configuration (kexnt itself, outside SYSTEM, gets Windows 98's own) */
        HMODULE s = LoadLibraryA("api-ms-win-core-sysinfo-l1-1-0.dll");
        if (s) gv = (T_GVXW)(void *)GetProcAddress(s, "GetVersionExW");
    }
    if (!gv) gv = (T_GVXW)(void *)GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "GetVersionExW");
    if (!gv) gv = (T_GVXW)(void *)kex_prev_impl("KERNEL32.DLL", "GetVersionExW");
    if (!gv || !gv(v)) {                    /* Windows 98's own GetVersionExW does nothing: the A version */
        static BOOL (WINAPI *ga)(OSVERSIONINFOA *); OSVERSIONINFOA a; int i;
        if (!ga) *(FARPROC *)&ga = GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "GetVersionExA");
        a.dwOSVersionInfoSize = sizeof(a);
        if (!ga || !ga(&a)) return (LONG)0xC0000001L;                                              /* STATUS_UNSUCCESSFUL */
        v->dwMajorVersion = a.dwMajorVersion; v->dwMinorVersion = a.dwMinorVersion; v->dwBuildNumber = a.dwBuildNumber;
        v->dwPlatformId = a.dwPlatformId;
        for (i = 0; i < 127 && a.szCSDVersion[i]; i++) v->szCSDVersion[i] = (WCHAR)(BYTE)a.szCSDVersion[i];
        v->szCSDVersion[i] = 0;
    }
    return 0;
}
