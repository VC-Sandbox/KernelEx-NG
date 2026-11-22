/* nttoken_ext.c - NTDLL token functions and NtQuerySection for Windows 98 (2026-11-02).
 *
 * KernelEx 4.5.2's kexbases has ADVAPI32 OpenProcessToken / GetTokenInformation stubs (placeholder handle
 * 0xCAFE, see sec_ext.c) but no NTDLL Nt*Token entry points: programs that import them statically do not
 * start ("linked to missing export NTDLL.DLL:NtOpenProcessToken" - the Visual C++ 2010 redistributable's
 * setup, 2026-11-02). These are the documented native equivalents on top of the same placeholders:
 *   NtOpenProcessToken(Ex)       -> ADVAPI32 OpenProcessToken
 *   NtOpenThreadToken(Ex)        -> STATUS_NO_TOKEN (a thread that is not impersonating, as on NT)
 *   NtQueryInformationToken      -> ADVAPI32 GetTokenInformation, plus the Vista+ classes a full-rights
 *                                   Win98 user answers: elevation type default, elevated, high integrity,
 *                                   session 0, primary token, not an AppContainer
 *   NtAdjustPrivilegesToken / NtSetInformationToken -> success (Win98 has no privileges to deny)
 *   NtDuplicateToken             -> the placeholder again
 *   NtQuerySection               -> SectionBasicInformation: SEC_COMMIT, size of a mapped view.
 *     Chrome 159 looks it up with GetProcAddress (base/memory/platform_shared_memory_region_win.cc) and got
 *     a bogus pointer (7) from the 4.5.2 tables, then jumped there.
 * All Zw* aliases come from kexnt_alias.def. Behaviour from the documentation only. */
#include <windows.h>

#define KEXAPI WINAPI
typedef LONG NTSTATUS;
#define ST_OK                 ((NTSTATUS)0x00000000L)
#define ST_INFO_LENGTH        ((NTSTATUS)0xC0000004L)
#define ST_INVALID_INFO_CLASS ((NTSTATUS)0xC0000003L)
#define ST_INVALID_HANDLE     ((NTSTATUS)0xC0000008L)
#define ST_INVALID_PARAM      ((NTSTATUS)0xC000000DL)
#define ST_ACCESS_VIOLATION   ((NTSTATUS)0xC0000005L)
#define ST_BUFFER_TOO_SMALL   ((NTSTATUS)0xC0000023L)
#define ST_NO_TOKEN           ((NTSTATUS)0xC000007CL)
#define ST_NOT_IMAGE          ((NTSTATUS)0xC0000049L)
#define KEX_TOKEN_PLACEHOLDER ((HANDLE)(ULONG_PTR)0xCAFE)

FARPROC kex_prev_impl(const char *dll, const char *name);   /* gdiguard_ext.c */
BOOL WINAPI kex_GetTokenInformation(HANDLE, DWORD, LPVOID, DWORD, PDWORD);   /* secsid_ext.c */

static NTSTATUS from_error(DWORD e)
{
    switch (e) {
    case ERROR_INSUFFICIENT_BUFFER: return ST_BUFFER_TOO_SMALL;
    case ERROR_INVALID_HANDLE:      return ST_INVALID_HANDLE;
    case ERROR_NOACCESS:            return ST_ACCESS_VIOLATION;
    case ERROR_NOT_ENOUGH_MEMORY:   return ST_INVALID_PARAM;
    case ERROR_CALL_NOT_IMPLEMENTED:
    case ERROR_INVALID_PARAMETER:   return ST_INVALID_INFO_CLASS;
    default:                        return ST_INVALID_PARAM;
    }
}

NTSTATUS KEXAPI kex_NtOpenProcessTokenEx(HANDLE process, ACCESS_MASK access, ULONG attrs, PHANDLE token)
{
    typedef BOOL (WINAPI *T_OPT)(HANDLE, DWORD, PHANDLE);
    static T_OPT opt;
    (void)attrs;
    if (!token || IsBadWritePtr(token, sizeof(*token))) return ST_ACCESS_VIOLATION;
    if (!opt) opt = (T_OPT)(void *)kex_prev_impl("ADVAPI32.DLL", "OpenProcessToken");
    if (opt && opt(process, access, token)) return ST_OK;
    *token = KEX_TOKEN_PLACEHOLDER;                       /* no KernelEx stub: same placeholder */
    return ST_OK;
}
NTSTATUS KEXAPI kex_NtOpenProcessToken(HANDLE process, ACCESS_MASK access, PHANDLE token)
{ return kex_NtOpenProcessTokenEx(process, access, 0, token); }

NTSTATUS KEXAPI kex_NtOpenThreadTokenEx(HANDLE thread, ACCESS_MASK access, BOOLEAN self, ULONG attrs, PHANDLE token)
{
    (void)thread; (void)access; (void)self; (void)attrs;
    if (token && !IsBadWritePtr(token, sizeof(*token))) *token = NULL;
    return ST_NO_TOKEN;
}
NTSTATUS KEXAPI kex_NtOpenThreadToken(HANDLE thread, ACCESS_MASK access, BOOLEAN self, PHANDLE token)
{ return kex_NtOpenThreadTokenEx(thread, access, self, 0, token); }

static NTSTATUS put(PVOID buf, ULONG len, PULONG ret, const void *src, ULONG n)
{
    if (ret) *ret = n;
    if (len < n) return ST_BUFFER_TOO_SMALL;
    if (!buf || IsBadWritePtr(buf, n)) return ST_ACCESS_VIOLATION;
    memcpy(buf, src, n);
    return ST_OK;
}

NTSTATUS KEXAPI kex_NtQueryInformationToken(HANDLE token, ULONG cls, PVOID buf, ULONG len, PULONG ret)
{
    DWORD v, got = 0;
    if (!token) return ST_INVALID_HANDLE;
    switch (cls) {
    case 8:  v = 1; return put(buf, len, ret, &v, 4);     /* TokenType: TokenPrimary */
    case 12: v = 0; return put(buf, len, ret, &v, 4);     /* TokenSessionId */
    case 18: v = 1; return put(buf, len, ret, &v, 4);     /* TokenElevationType: TokenElevationTypeDefault */
    case 20: v = 1; return put(buf, len, ret, &v, 4);     /* TokenElevation: elevated */
    case 29: v = 0; return put(buf, len, ret, &v, 4);     /* TokenIsAppContainer */
    case 25: {                                            /* TokenIntegrityLevel: S-1-16-12288 (high) */
        BYTE b[8 + 12];
        DWORD *p = (DWORD *)b;
        p[0] = 0; p[1] = 0x60;                            /* SID_AND_ATTRIBUTES: Sid set below, SE_GROUP_INTEGRITY(_ENABLED) */
        b[8] = 1; b[9] = 1; memset(b + 10, 0, 5); b[15] = 16; /* revision 1, 1 sub-authority, authority 16 */
        *(DWORD *)(b + 16) = 0x3000;
        if (ret) *ret = sizeof(b);
        if (len < sizeof(b)) return ST_BUFFER_TOO_SMALL;
        if (!buf || IsBadWritePtr(buf, sizeof(b))) return ST_ACCESS_VIOLATION;
        memcpy(buf, b, sizeof(b));
        ((DWORD *)buf)[0] = (DWORD)(ULONG_PTR)((BYTE *)buf + 8);
        return ST_OK;
    }
    }
    if (kex_GetTokenInformation(token, cls, buf, len, &got)) { if (ret) *ret = got; return ST_OK; }
    if (ret) *ret = got;
    return from_error(GetLastError());
}

NTSTATUS KEXAPI kex_NtAdjustPrivilegesToken(HANDLE token, BOOLEAN disable_all, PVOID newst, ULONG len, PVOID prev, PULONG retlen)
{
    (void)token; (void)disable_all; (void)newst;
    if (prev && len >= 4 && !IsBadWritePtr(prev, 4)) *(DWORD *)prev = 0;   /* no previous privileges */
    if (retlen) *retlen = 4;
    return ST_OK;
}
NTSTATUS KEXAPI kex_NtSetInformationToken(HANDLE token, ULONG cls, PVOID buf, ULONG len)
{ (void)token; (void)cls; (void)buf; (void)len; return ST_OK; }
NTSTATUS KEXAPI kex_NtDuplicateToken(HANDLE token, ACCESS_MASK access, PVOID oa, BOOLEAN eff, ULONG type, PHANDLE out)
{
    (void)token; (void)access; (void)oa; (void)eff; (void)type;
    if (!out || IsBadWritePtr(out, sizeof(*out))) return ST_ACCESS_VIOLATION;
    *out = KEX_TOKEN_PLACEHOLDER;
    return ST_OK;
}

/* SECTION_BASIC_INFORMATION { PVOID BaseAddress; ULONG AllocationAttributes; LARGE_INTEGER MaximumSize; } */
NTSTATUS KEXAPI kex_NtQuerySection(HANDLE section, ULONG cls, PVOID buf, SIZE_T len, PSIZE_T ret)
{
    DWORD b[4]; void *view; MEMORY_BASIC_INFORMATION mbi;
    if (!section) return ST_INVALID_HANDLE;
    if (cls == 1) return ST_NOT_IMAGE;                    /* SectionImageInformation: Win98 has no image sections */
    if (cls != 0) return ST_INVALID_INFO_CLASS;
    if (ret) *ret = sizeof(b);
    if (len < sizeof(b)) return ST_INFO_LENGTH;
    if (!buf || IsBadWritePtr(buf, sizeof(b))) return ST_ACCESS_VIOLATION;
    b[0] = 0; b[1] = SEC_COMMIT; b[2] = 0; b[3] = 0;
    view = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    if (!view) view = MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, 0);
    if (!view && GetLastError() == ERROR_INVALID_HANDLE) return ST_INVALID_HANDLE;
    if (view) {
        if (VirtualQuery(view, &mbi, sizeof(mbi))) b[2] = (DWORD)mbi.RegionSize;
        UnmapViewOfFile(view);
    }
    memcpy(buf, b, sizeof(b));
    return ST_OK;
}

/* ---- ADVAPI32 impersonation (build 132) ----
 * .NET 4's configuration system (System.Configuration.BaseConfigurationRecord.InitConfigFromFile) drops any
 * impersonation while it reads machine.config and restores it with WindowsImpersonationContext.Undo() -> RevertToSelf /
 * SetThreadToken. Windows 98's ADVAPI32 has only stubs that fail with ERROR_CALL_NOT_IMPLEMENTED ("This function is only
 * valid in Win32 mode", measured: SecurityException -> ConfigurationErrorsException "Configuration system failed to
 * initialize" for every WebClient / WinForms program). A Windows 98 thread never impersonates - it always runs as the
 * one local user - so these answer as NT does for a thread that is not impersonating: reverting and "impersonating"
 * succeed (nothing changes), and OpenThreadToken reports ERROR_NO_TOKEN (as NtOpenThreadToken above). */
BOOL KEXAPI kex_RevertToSelf(void) { SetLastError(ERROR_SUCCESS); return TRUE; }
BOOL KEXAPI kex_SetThreadToken(PHANDLE thread, HANDLE token) { (void)thread; (void)token; SetLastError(ERROR_SUCCESS); return TRUE; }
BOOL KEXAPI kex_ImpersonateSelf(DWORD level) { (void)level; SetLastError(ERROR_SUCCESS); return TRUE; }
BOOL KEXAPI kex_ImpersonateLoggedOnUser(HANDLE token) { (void)token; SetLastError(ERROR_SUCCESS); return TRUE; }
BOOL KEXAPI kex_OpenThreadToken(HANDLE thread, DWORD access, BOOL as_self, PHANDLE token)
{
    (void)thread; (void)access; (void)as_self;
    if (token) *token = NULL;
    SetLastError(ERROR_NO_TOKEN); return FALSE;
}
