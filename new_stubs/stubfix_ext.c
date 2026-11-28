/* stubfix_ext.c - Chromium imports that KernelEx 4.5.2 exports only as always-failing stubs (2026-11-02).
 * Found by cross-checking chrome.dll/chrome.exe/chrome_elf.dll imports with docs/kex_inventory.json ("_stub").
 *   GetComputerNameExA/W  - NetBIOS / DNS host name = the Windows 98 computer name, no DNS domain
 *   ReplaceFileA/W        - optional backup copy, then the replacement file takes the replaced file's name
 *                           (Chrome saves its settings this way, base::ReplaceFile / ImportantFileWriter)
 *   ConvertStringSecurityDescriptorToSecurityDescriptorA/W
 *                         - Windows 98 ignores security descriptors; any valid SDDL string gives a valid
 *                           self-relative descriptor with a NULL DACL (full access), as 9x behaves anyway
 *   CryptAcquireContextW, CryptSignHashW
 *                         - Windows 98's CryptoAPI has the ANSI functions; these convert the strings
 * Behaviour from the documentation only. */
#include "kexnt_common.h"

static BOOL to_a(LPCWSTR w, char *a, int n)
{
    if (!w) { a[0] = 0; return TRUE; }
    return WideCharToMultiByte(CP_ACP, 0, w, -1, a, n, NULL, NULL) > 0;
}

/* ---------------------------------------------------------------- GetComputerNameEx */
BOOL KEXAPI kex_GetComputerNameExA(int format, LPSTR buf, LPDWORD size)
{
    char name[MAX_COMPUTERNAME_LENGTH + 1]; DWORD n = sizeof(name), l;
    if (!size || format < 0 || format > 7) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (format == 2 || format == 6) name[0] = 0;              /* (Physical)DnsDomain: not in a domain */
    else if (!GetComputerNameA(name, &n)) return FALSE;
    if (format == 1 || format == 3 || format == 5 || format == 7)   /* DNS forms are lower case */
        { char *p; for (p = name; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32; }
    l = lstrlenA(name);
    if (!buf || *size < l + 1) { *size = l + 1; SetLastError(ERROR_MORE_DATA); return FALSE; }
    memcpy(buf, name, l + 1); *size = l;
    return TRUE;
}
BOOL KEXAPI kex_GetComputerNameExW(int format, LPWSTR buf, LPDWORD size)
{
    char name[MAX_COMPUTERNAME_LENGTH + 1]; DWORD n = sizeof(name), l;
    if (!size) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!kex_GetComputerNameExA(format, name, &n)) {
        if (GetLastError() == ERROR_MORE_DATA) *size = n;    /* never happens with our buffer; kept for safety */
        return FALSE;
    }
    l = MultiByteToWideChar(CP_ACP, 0, name, -1, NULL, 0);    /* includes the terminator */
    if (!buf || *size < l) { *size = l; SetLastError(ERROR_MORE_DATA); return FALSE; }
    MultiByteToWideChar(CP_ACP, 0, name, -1, buf, *size);
    *size = l - 1;
    return TRUE;
}

/* ---------------------------------------------------------------- ReplaceFile */
#define ERROR_UNABLE_TO_MOVE_REPLACEMENT_K   1176
#define ERROR_UNABLE_TO_REMOVE_REPLACED_K    1175
static BOOL replace_a(LPCSTR replaced, LPCSTR repl, LPCSTR backup)
{
    if (!replaced || !repl || !replaced[0] || !repl[0]) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (GetFileAttributesA(replaced) == 0xFFFFFFFF) { SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }
    if (GetFileAttributesA(repl) == 0xFFFFFFFF) { SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }
    if (backup && backup[0] && !CopyFileA(replaced, backup, FALSE)) return FALSE;
    SetFileAttributesA(replaced, FILE_ATTRIBUTE_NORMAL);
    if (!DeleteFileA(replaced)) { SetLastError(ERROR_UNABLE_TO_REMOVE_REPLACED_K); return FALSE; }
    if (!MoveFileA(repl, replaced)) {
        if (backup && backup[0]) CopyFileA(backup, replaced, FALSE);   /* put the old content back */
        SetLastError(ERROR_UNABLE_TO_MOVE_REPLACEMENT_K);
        return FALSE;
    }
    return TRUE;
}
BOOL KEXAPI kex_ReplaceFileA(LPCSTR replaced, LPCSTR repl, LPCSTR backup, DWORD flags, LPVOID ex, LPVOID res)
{ (void)flags; (void)ex; (void)res; return replace_a(replaced, repl, backup); }
BOOL KEXAPI kex_ReplaceFileW(LPCWSTR replaced, LPCWSTR repl, LPCWSTR backup, DWORD flags, LPVOID ex, LPVOID res)
{
    char a[MAX_PATH], b[MAX_PATH], c[MAX_PATH];
    (void)flags; (void)ex; (void)res;
    if (!replaced || !repl || !to_a(replaced, a, MAX_PATH) || !to_a(repl, b, MAX_PATH) || !to_a(backup, c, MAX_PATH)) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    return replace_a(a, b, backup ? c : NULL);
}

/* ---------------------------------------------------------------- SDDL -> security descriptor */
static BOOL sddl_sd(int ok, ULONG rev, PSECURITY_DESCRIPTOR *out, PULONG len)
{
    BYTE *sd;
    if (!ok || !out) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (rev != 1) { SetLastError(ERROR_UNKNOWN_REVISION); return FALSE; }
    if (!(sd = (BYTE *)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, 20))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    sd[0] = 1;                                   /* SECURITY_DESCRIPTOR_RELATIVE: revision 1 */
    *(WORD *)(sd + 2) = 0x8004;                  /* SE_SELF_RELATIVE | SE_DACL_PRESENT, DACL offset 0 = NULL DACL */
    *out = sd;
    if (len) *len = 20;
    return TRUE;
}
BOOL KEXAPI kex_ConvertStringSecurityDescriptorToSecurityDescriptorA(LPCSTR s, ULONG rev, PSECURITY_DESCRIPTOR *out, PULONG len)
{ return sddl_sd(s != NULL, rev, out, len); }
BOOL KEXAPI kex_ConvertStringSecurityDescriptorToSecurityDescriptorW(LPCWSTR s, ULONG rev, PSECURITY_DESCRIPTOR *out, PULONG len)
{ return sddl_sd(s != NULL, rev, out, len); }

/* ---------------------------------------------------------------- CryptoAPI wide-string entry points */
typedef BOOL (WINAPI *T_CACA)(ULONG_PTR *, LPCSTR, LPCSTR, DWORD, DWORD);
BOOL KEXAPI kex_CryptAcquireContextA(ULONG_PTR *prov, LPCSTR container, LPCSTR provider, DWORD type, DWORD flags);
BOOL KEXAPI kex_CryptAcquireContextW(ULONG_PTR *prov, LPCWSTR container, LPCWSTR provider, DWORD type, DWORD flags)
{
    static T_CACA f;
    char c[260], p[260];
    if (!f) f = (T_CACA)(void *)kex_sysproc("ADVAPI32.DLL", "CryptAcquireContextA");
    if (!f) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    if (!to_a(container, c, sizeof(c)) || !to_a(provider, p, sizeof(p))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return kex_CryptAcquireContextA(prov, container ? c : NULL, provider ? p : NULL, type, flags);
}
/* build 125: CRYPT_SILENT (0x40, "never show UI") is newer than Windows 98's CryptoAPI, which rejects it with
 * NTE_BAD_FLAGS (CACQ.EXE: VERIFYCONTEXT -> ok, VERIFYCONTEXT|SILENT -> 80090009). WiX Burn hashes every cached
 * package that way ("Error 0x80090009: Failed to calculate hash", VC++ 2013 setup). Windows 98's providers show no UI,
 * so the flag is simply dropped. */
BOOL KEXAPI kex_CryptAcquireContextA(ULONG_PTR *prov, LPCSTR container, LPCSTR provider, DWORD type, DWORD flags)
{
    static T_CACA f; BOOL r;
    if (!f) f = (T_CACA)(void *)kex_sysproc("ADVAPI32.DLL", "CryptAcquireContextA");
    if (!f) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    r = f(prov, container, provider, type, flags & ~0x40UL);
    /* build 138: PROV_RSA_AES (24) is an XP SP3 provider type; Windows 98 defines types 1, 3 and 13 only (probe
     * cryptprov.c: 24 -> NTE_PROV_TYPE_NOT_DEF, the AES provider by name -> NTE_KEYSET_NOT_DEF). .NET 2.0 SP2 asks for it
     * on "XP or later" for its static handle (SHA1CryptoServiceProvider, RSA, Remoting identities), so all of those
     * failed with 0x80090017. The Enhanced RSA provider (type 1) offers the same RSA/SHA-1/MD5/3DES; AES keys stay
     * unavailable through CryptoAPI. */
    if (!r && type == 24 && (GetLastError() == 0x80090017UL || GetLastError() == 0x80090019UL)) {
        r = f(prov, container, "Microsoft Enhanced Cryptographic Provider v1.0", 1, flags & ~0x40UL);
        if (!r) r = f(prov, container, NULL, 1, flags & ~0x40UL);
    }
    if (!r) {   /* build 132: which provider a program wanted (the .NET 4 strong-name check) */
        static LONG n; DWORD e = GetLastError();
        if (InterlockedIncrement(&n) <= 30) {
            void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d); void kex_crashlog_text(const char *s);
            char t[300];
            kex_crashnote("CryptAcquireContext FAILED (type, flags, error, caller)", type, flags, e, (DWORD)(ULONG_PTR)__builtin_return_address(0));
            lstrcpyA(t, "    provider: "); lstrcpynA(t + 14, provider ? provider : "(default)", 260); kex_crashlog_text(t);
        }
        SetLastError(e);
    }
    return r;
}
/* build 132: CryptVerifySignatureW is a stub on Windows 98 (probe rsaver.c: the A function verifies a 1024-bit
 * RSA / SHA-1 signature, the W one fails with 0x78 = ERROR_CALL_NOT_IMPLEMENTED). The .NET 4 runtime's strong-name
 * check calls the W one, so every signed assembly failed (StrongNameSignatureVerificationEx -> 0x8013141A, the .NET
 * 4.0 setup's InstallAssembly: "strong name signature could not be verified"). The description is unused by the
 * Microsoft providers (NULL is documented); it is converted and passed on. */
typedef BOOL (WINAPI *T_CVSA)(ULONG_PTR, const BYTE *, DWORD, ULONG_PTR, LPCSTR, DWORD);
BOOL KEXAPI kex_CryptVerifySignatureW(ULONG_PTR hash, const BYTE *sig, DWORD len, ULONG_PTR key, LPCWSTR desc, DWORD flags)
{
    static T_CVSA f; char d[260];
    if (!f) f = (T_CVSA)(void *)kex_sysproc("ADVAPI32.DLL", "CryptVerifySignatureA");
    if (!f) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    if (!to_a(desc, d, sizeof(d))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return f(hash, sig, len, key, desc ? d : NULL, flags);
}
/* CryptEnumProvidersW / CryptGetDefaultProviderW: the A functions, names widened (same probe family, same stub) */
typedef BOOL (WINAPI *T_CEPA)(DWORD, DWORD *, DWORD, DWORD *, LPSTR, DWORD *);
BOOL KEXAPI kex_CryptEnumProvidersW(DWORD index, DWORD *res, DWORD flags, DWORD *type, LPWSTR name, DWORD *cb)
{
    static T_CEPA f; char a[260]; DWORD n = sizeof(a), need;
    if (!f) f = (T_CEPA)(void *)kex_sysproc("ADVAPI32.DLL", "CryptEnumProvidersA");
    if (!f) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    if (!cb) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!f(index, res, flags, type, a, &n)) return FALSE;
    need = (DWORD)MultiByteToWideChar(CP_ACP, 0, a, -1, NULL, 0) * sizeof(WCHAR);
    if (!name) { *cb = need; return TRUE; }
    if (*cb < need) { *cb = need; SetLastError(ERROR_MORE_DATA); return FALSE; }
    MultiByteToWideChar(CP_ACP, 0, a, -1, name, (int)(*cb / sizeof(WCHAR))); *cb = need;
    return TRUE;
}
typedef BOOL (WINAPI *T_CGDA)(DWORD, DWORD *, DWORD, LPSTR, DWORD *);
BOOL KEXAPI kex_CryptGetDefaultProviderW(DWORD type, DWORD *res, DWORD flags, LPWSTR name, DWORD *cb)
{
    static T_CGDA f; char a[260]; DWORD n = sizeof(a), need;
    if (!f) f = (T_CGDA)(void *)kex_sysproc("ADVAPI32.DLL", "CryptGetDefaultProviderA");
    if (!f) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    if (!cb) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!f(type, res, flags, a, &n)) return FALSE;
    need = (DWORD)MultiByteToWideChar(CP_ACP, 0, a, -1, NULL, 0) * sizeof(WCHAR);
    if (!name) { *cb = need; return TRUE; }
    if (*cb < need) { *cb = need; SetLastError(ERROR_MORE_DATA); return FALSE; }
    MultiByteToWideChar(CP_ACP, 0, a, -1, name, (int)(*cb / sizeof(WCHAR))); *cb = need;
    return TRUE;
}
typedef BOOL (WINAPI *T_CSHA)(ULONG_PTR, DWORD, LPCSTR, DWORD, BYTE *, DWORD *);
BOOL KEXAPI kex_CryptSignHashW(ULONG_PTR hash, DWORD key, LPCWSTR desc, DWORD flags, BYTE *sig, DWORD *len)
{
    static T_CSHA f;
    char d[260];
    if (!f) f = (T_CSHA)(void *)kex_sysproc("ADVAPI32.DLL", "CryptSignHashA");
    if (!f) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    if (!to_a(desc, d, sizeof(d))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return f(hash, key, desc ? d : NULL, flags, sig, len);
}

/* ---------------------------------------------------------------- service names (build 138)
 * Windows 98 has no NT service manager; KernelEx's OpenSCManager returns a placeholder handle, and the per-service
 * calls below were Windows 98 stubs failing with ERROR_CALL_NOT_IMPLEMENTED. .NET's ServiceController turns that into
 * "Service was not found" with an unexpected inner error, which WCF's ServiceModelReg (IisHelper.CheckWasInstalled,
 * probe iishelper.cs) does not expect, so WCF never registered its machine.config sections and every WCF/WF program
 * failed with "Unrecognized configuration section system.serviceModel". With no services on the system, the answer an
 * NT service manager gives is ERROR_SERVICE_DOES_NOT_EXIST. */
#define KEX_NO_SERVICE() do { SetLastError(1060 /* ERROR_SERVICE_DOES_NOT_EXIST */); } while (0)
ULONG_PTR KEXAPI kex_OpenServiceA(ULONG_PTR scm, LPCSTR name, DWORD access) { KEX_NO_SERVICE(); return 0; }
ULONG_PTR KEXAPI kex_OpenServiceW(ULONG_PTR scm, LPCWSTR name, DWORD access) { KEX_NO_SERVICE(); return 0; }
BOOL KEXAPI kex_GetServiceKeyNameA(ULONG_PTR scm, LPCSTR disp, LPSTR key, DWORD *cch) { KEX_NO_SERVICE(); return FALSE; }
BOOL KEXAPI kex_GetServiceKeyNameW(ULONG_PTR scm, LPCWSTR disp, LPWSTR key, DWORD *cch) { KEX_NO_SERVICE(); return FALSE; }
BOOL KEXAPI kex_GetServiceDisplayNameA(ULONG_PTR scm, LPCSTR key, LPSTR disp, DWORD *cch) { KEX_NO_SERVICE(); return FALSE; }
BOOL KEXAPI kex_GetServiceDisplayNameW(ULONG_PTR scm, LPCWSTR key, LPWSTR disp, DWORD *cch) { KEX_NO_SERVICE(); return FALSE; }
/* CloseServiceHandle (build 138): closing KernelEx's placeholder service manager handle (0xCAFE, from OpenSCManager)
 * failed with Windows 98's ERROR_CALL_NOT_IMPLEMENTED stub, and WCF's ServiceManagerHandle.ReleaseHandle throws on
 * that (ServiceModelReg's InfoCard component, probe smrcomp.cs). That handle closes; no other service handle exists. */
BOOL KEXAPI kex_CloseServiceHandle(ULONG_PTR h)
{
    if (h == 0xCAFE) return TRUE;
    SetLastError(ERROR_INVALID_HANDLE); return FALSE;
}

/* ---------------------------------------------------------------- event log (build 138)
 * Windows 98 has no event log; its ADVAPI32 RegisterEventSourceW/ReportEventW are stubs. NT programs write their
 * diagnostics there - the .NET runtime puts the message of Environment.FailFast (WPF's Invariant.Assert) into it, and
 * that message was the only description of why a WPF program ended with 0x80131623. Events go into the program's
 * KEXCRASH log (source, type, id, strings) instead; the handle is a placeholder. */
#define KEX_EVENTLOG ((ULONG_PTR)0x45564C47UL)   /* "EVLG" */
ULONG_PTR KEXAPI kex_RegisterEventSourceW(LPCWSTR server, LPCWSTR source) { return KEX_EVENTLOG; }
ULONG_PTR KEXAPI kex_RegisterEventSourceA(LPCSTR server, LPCSTR source) { return KEX_EVENTLOG; }
BOOL KEXAPI kex_DeregisterEventSource(ULONG_PTR h) { if (h == KEX_EVENTLOG) return TRUE; SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
BOOL KEXAPI kex_ReportEventW(ULONG_PTR h, WORD type, WORD cat, DWORD id, PVOID sid, WORD n, DWORD size, LPCWSTR *s, PVOID data)
{
    void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d); void kex_crashlog_text(const char *t);
    char buf[1024]; WORD i;
    if (h != KEX_EVENTLOG) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    kex_crashnote("event log entry (type, category, id, strings)", type, cat, id, n);
    for (i = 0; i < n && s && i < 8; i++)
        if (s[i] && WideCharToMultiByte(CP_ACP, 0, s[i], -1, buf, sizeof(buf) - 1, NULL, NULL)) { buf[sizeof(buf) - 1] = 0; kex_crashlog_text(buf); }
    return TRUE;
}
BOOL KEXAPI kex_ReportEventA(ULONG_PTR h, WORD type, WORD cat, DWORD id, PVOID sid, WORD n, DWORD size, LPCSTR *s, PVOID data)
{
    void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d); void kex_crashlog_text(const char *t);
    WORD i;
    if (h != KEX_EVENTLOG) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    kex_crashnote("event log entry (type, category, id, strings)", type, cat, id, n);
    for (i = 0; i < n && s && i < 8; i++) if (s[i]) kex_crashlog_text(s[i]);
    return TRUE;
}
