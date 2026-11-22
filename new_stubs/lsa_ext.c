/*
 * lsa_ext.c - LSA policy queries for modern programs (build 132).
 *
 * Windows 98's ADVAPI32 has no LSA functions at all. The .NET Framework 3.5 SP1 setup's engine imports two of them
 * statically - measured with KEXIMP on its SITSETUP.DLL: "static MISSING ADVAPI32.dll!LsaFreeMemory,
 * LsaQueryInformationPolicy" - so the DLL could not load and setup stopped with "Unable to load sitsetup.dll".
 *
 * Here the policy object of a stand-alone NT workstation (no domain), consistent with secsid_ext.c:
 *   PolicyAccountDomainInformation (5): DomainName = the computer name, DomainSid = S-1-5-21-0-0-0
 *       (the account domain of the user SID S-1-5-21-0-0-0-1000 secsid_ext.c reports)
 *   PolicyPrimaryDomainInformation (3): Name = the Windows 98 workgroup, Sid = NULL (not in a domain)
 *   PolicyDnsDomainInformation (12):    Name = the workgroup, no DNS names, no GUID, Sid = NULL
 *   PolicyLsaServerRoleInformation (6): PolicyServerRolePrimary, as NT workstations report it
 * Other classes: STATUS_NOT_SUPPORTED (noted in the crash log). Every result is one LocalAlloc block, so
 * LsaFreeMemory is LocalFree.
 */
#include "kexnt_common.h"

void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

typedef LONG NTSTATUS_K;
typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } KLSA_STR;
#define ST_OK            0
#define ST_INVALID_PARAM ((NTSTATUS_K)0xC000000DL)
#define ST_NOT_SUPPORTED ((NTSTATUS_K)0xC00000BBL)
#define ST_NO_MEMORY     ((NTSTATUS_K)0xC0000017L)
#define LSA_POLICY_HANDLE ((HANDLE)(ULONG_PTR)0x4C534131UL)   /* "LSA1" - the one policy object */

NTSTATUS_K KEXAPI kex_LsaOpenPolicy(PVOID system, PVOID attr, ACCESS_MASK access, PHANDLE h)
{
    (void)system; (void)attr; (void)access;
    if (!h) return ST_INVALID_PARAM;
    *h = LSA_POLICY_HANDLE;
    return ST_OK;
}

NTSTATUS_K KEXAPI kex_LsaClose(HANDLE h) { (void)h; return ST_OK; }

NTSTATUS_K KEXAPI kex_LsaFreeMemory(PVOID p) { if (p) LocalFree(p); return ST_OK; }

ULONG KEXAPI kex_LsaNtStatusToWinError(NTSTATUS_K s)
{
    switch ((ULONG)s) {
    case 0: return ERROR_SUCCESS;
    case 0xC0000022UL: return ERROR_ACCESS_DENIED;
    case 0xC000000DUL: return ERROR_INVALID_PARAMETER;
    case 0xC00000BBUL: return ERROR_NOT_SUPPORTED;
    case 0xC0000017UL: return ERROR_NOT_ENOUGH_MEMORY;
    case 0xC0000034UL: return ERROR_FILE_NOT_FOUND;
    default: return ERROR_MR_MID_NOT_FOUND;
    }
}

static int ansi_to_w(const char *a, WCHAR *w, int cch)
{
    int n = MultiByteToWideChar(CP_ACP, 0, a, -1, w, cch);
    return n > 0 ? n - 1 : 0;
}

static void workgroup(char *o, DWORD cb)
{
    HKEY k; DWORD t, n = cb;
    lstrcpynA(o, "WORKGROUP", cb);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\VxD\\VNETSUP", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExA(k, "Workgroup", NULL, &t, (BYTE *)o, &n) != ERROR_SUCCESS || t != REG_SZ || !o[0]) lstrcpynA(o, "WORKGROUP", cb);
        RegCloseKey(k);
    }
}

/* name -> UNICODE_STRING whose buffer is at *pool (advanced) */
static void put_str(KLSA_STR *s, const WCHAR *w, int len, BYTE **pool)
{
    s->Length = (USHORT)(len * 2); s->MaximumLength = (USHORT)(len * 2 + 2);
    s->Buffer = (PWSTR)*pool;
    memcpy(*pool, w, len * 2 + 2);
    *pool += len * 2 + 2;
}

NTSTATUS_K KEXAPI kex_LsaQueryInformationPolicy(HANDLE h, int cls, PVOID *out)
{
    char a[MAX_COMPUTERNAME_LENGTH + 64]; WCHAR w[MAX_COMPUTERNAME_LENGTH + 64]; DWORD n = sizeof(a); int len; BYTE *blk, *pool;
    if (!out) return ST_INVALID_PARAM;
    *out = NULL;
    if (h != LSA_POLICY_HANDLE) return ST_INVALID_PARAM;
    switch (cls) {
    case 5: {                                                     /* PolicyAccountDomainInformation */
        struct { KLSA_STR name; PSID sid; } *r;
        static const BYTE domsid[] = { 1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };  /* S-1-5-21-0-0-0 */
        if (!GetComputerNameA(a, &n)) lstrcpyA(a, "COMPUTER");
        len = ansi_to_w(a, w, sizeof(w) / sizeof(w[0]));
        if (!(blk = (BYTE *)LocalAlloc(LPTR, sizeof(*r) + sizeof(domsid) + len * 2 + 2))) return ST_NO_MEMORY;
        r = (void *)blk; pool = blk + sizeof(*r);
        r->sid = (PSID)pool; memcpy(pool, domsid, sizeof(domsid)); pool += sizeof(domsid);
        put_str(&r->name, w, len, &pool);
        *out = r; return ST_OK;
    }
    case 3: case 12: {                                            /* PolicyPrimaryDomainInformation / PolicyDnsDomainInformation */
        struct { KLSA_STR name, dns, forest; GUID guid; PSID sid; } *r;   /* primary = the first two fields' layout */
        workgroup(a, sizeof(a));
        len = ansi_to_w(a, w, sizeof(w) / sizeof(w[0]));
        if (!(blk = (BYTE *)LocalAlloc(LPTR, sizeof(*r) + len * 2 + 2))) return ST_NO_MEMORY;
        r = (void *)blk; pool = blk + sizeof(*r);
        put_str(&r->name, w, len, &pool);
        /* POLICY_PRIMARY_DOMAIN_INFO is { Name, Sid }: Sid sits where dns.Length/.Buffer are - zero = NULL */
        *out = r; return ST_OK;
    }
    case 6: {                                                     /* PolicyLsaServerRoleInformation */
        DWORD *r = (DWORD *)LocalAlloc(LPTR, sizeof(DWORD));
        if (!r) return ST_NO_MEMORY;
        *r = 3;                                                   /* PolicyServerRolePrimary */
        *out = r; return ST_OK;
    }
    default: {
        static LONG k; if (InterlockedIncrement(&k) <= 10) kex_crashnote("LsaQueryInformationPolicy: class not provided (class, -, -, -)", (DWORD)cls, 0, 0, 0);
        return ST_NOT_SUPPORTED;
    }
    }
}
