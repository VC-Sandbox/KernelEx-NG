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

/* ---------------------------------------------------------------- LsaLookupSids (build 138)
 * .NET's WindowsIdentity.Name / SecurityIdentifier.Translate call ADVAPI32!LsaLookupSids (EntryPointNotFoundException
 * on Windows 98, probe dotnet/core20.cs "WindowsIdentity / token"). Names for the SIDs this system reports
 * (secsid_ext.c: user S-1-5-21-0-0-0-1000, primary group ...-513) and NT's well-known ones; anything else is unknown
 * (SidTypeUnknown, STATUS_SOME_NOT_MAPPED / STATUS_NONE_MAPPED as on NT). Both results are LocalAlloc blocks. */
typedef struct { BYTE rev, n, auth[6]; DWORD sub[15]; } KLSID;
typedef struct { KLSA_STR Name; PVOID Sid; } KTRUST;
typedef struct { ULONG Entries; KTRUST *Domains; } KREFDOMS;
typedef struct { int Use; KLSA_STR Name; LONG DomainIndex; } KXNAME;
static int lsa_auth(const KLSID *s) { return s->auth[0] | s->auth[1] | s->auth[2] | s->auth[3] | s->auth[4] ? -1 : s->auth[5]; }
/* domain: 0 = this computer (S-1-5-21-0-0-0), 1 = NT AUTHORITY (S-1-5), 2 = BUILTIN (S-1-5-32), -1 = none */
static const char *sid_name(const KLSID *s, int *dom, int *use, char *user)
{
    int a = lsa_auth(s);
    *dom = -1; *use = 5;                                               /* SidTypeWellKnownGroup */
    if (s->rev != 1) return NULL;
    if (a == 1 && s->n == 1 && s->sub[0] == 0) return "Everyone";
    if (a == 2 && s->n == 1 && s->sub[0] == 0) return "LOCAL";
    if (a == 3 && s->n == 1 && s->sub[0] == 0) return "CREATOR OWNER";
    if (a != 5) return NULL;
    if (s->n == 4 && s->sub[0] == 21 && !s->sub[1] && !s->sub[2] && !s->sub[3]) { *dom = 0; *use = 3; return ""; }   /* the domain */
    if (s->n == 5 && s->sub[0] == 21 && !s->sub[1] && !s->sub[2] && !s->sub[3]) {
        *dom = 0;
        if (s->sub[4] == 1000) { DWORD n = 64; *use = 1; if (!GetUserNameA(user, &n) || !user[0]) lstrcpyA(user, "User"); return user; }
        if (s->sub[4] == 513) { *use = 2; return "None"; }
        return NULL;
    }
    if (s->n == 1) {
        *dom = 1;
        switch (s->sub[0]) {
        case 2: return "NETWORK"; case 4: return "INTERACTIVE"; case 11: return "Authenticated Users";
        case 18: return "SYSTEM"; case 19: return "LOCAL SERVICE"; case 20: return "NETWORK SERVICE";
        }
        return NULL;
    }
    if (s->n == 2 && s->sub[0] == 32) {
        *dom = 2; *use = 4;                                            /* SidTypeAlias */
        switch (s->sub[1]) { case 544: return "Administrators"; case 545: return "Users"; case 546: return "Guests"; }
    }
    return NULL;
}
static DWORD ws_put(KLSA_STR *u, const char *s, WCHAR *at)
{
    int n = MultiByteToWideChar(CP_ACP, 0, s, -1, at, 64);
    if (n < 1) n = 1;
    u->Buffer = at; u->Length = (USHORT)((n - 1) * 2); u->MaximumLength = (USHORT)(n * 2);
    return (DWORD)n;
}
NTSTATUS_K KEXAPI kex_LsaLookupSids(HANDLE h, ULONG count, PVOID *sids, KREFDOMS **doms, KXNAME **names)
{
    char user[64], comp[MAX_COMPUTERNAME_LENGTH + 1]; DWORD cn = sizeof(comp); ULONG i, mapped = 0; int used[3] = { -1, -1, -1 }, nd = 0;
    KXNAME *nm; KREFDOMS *rd; WCHAR *ws; BYTE *sp;
    static const BYTE dsid[3][16] = { { 1, 4, 0,0,0,0,0,5, 21,0,0,0, 0,0,0,0 }, { 1, 0, 0,0,0,0,0,5 }, { 1, 1, 0,0,0,0,0,5, 32,0,0,0 } };
    if (!sids || !doms || !names || !count || count > 1000) return ST_INVALID_PARAM;
    *doms = NULL; *names = NULL;
    if (!GetComputerNameA(comp, &cn)) lstrcpyA(comp, "COMPUTER");
    if (!(nm = (KXNAME *)LocalAlloc(LPTR, count * (sizeof(KXNAME) + 64 * sizeof(WCHAR))))) return ST_NO_MEMORY;
    if (!(rd = (KREFDOMS *)LocalAlloc(LPTR, sizeof(KREFDOMS) + 3 * (sizeof(KTRUST) + 32 * sizeof(WCHAR) + 28 * sizeof(BYTE) / 1 + 32)))) { LocalFree(nm); return ST_NO_MEMORY; }
    ws = (WCHAR *)(nm + count);
    rd->Domains = (KTRUST *)(rd + 1);
    for (i = 0; i < count; i++) {
        int dom, use; const char *n = sids[i] ? sid_name((const KLSID *)sids[i], &dom, &use, user) : NULL;
        if (!n) { nm[i].Use = 8; nm[i].DomainIndex = -1; ws_put(&nm[i].Name, "", ws); ws += 64; continue; }
        mapped++; nm[i].Use = use; ws_put(&nm[i].Name, n, ws); ws += 64;
        if (dom < 0) { nm[i].DomainIndex = -1; continue; }
        if (used[dom] < 0) used[dom] = nd++;
        nm[i].DomainIndex = used[dom];
    }
    rd->Entries = (ULONG)nd;
    {   WCHAR *dw = (WCHAR *)(rd->Domains + 3); BYTE *ds; int d;
        sp = (BYTE *)(dw + 3 * 32);
        for (d = 0; d < 3; d++) {
            if (used[d] < 0) continue;
            ws_put(&rd->Domains[used[d]].Name, d == 0 ? comp : d == 1 ? "NT AUTHORITY" : "BUILTIN", dw + 32 * used[d]);
            ds = sp + 28 * used[d]; memcpy(ds, dsid[d], 16); rd->Domains[used[d]].Sid = ds;
        }
    }
    *names = nm; *doms = rd;
    return mapped == count ? ST_OK : mapped ? (NTSTATUS_K)0x00000107L : (NTSTATUS_K)0xC0000073L;
}

/* LsaGetLogonSessionData (SECUR32, build 138): .NET's WindowsIdentity.AuthenticationType reads the logon session of
 * the token (EntryPointNotFoundException on Windows 98). The one logon session of this system: an interactive NTLM
 * logon of the user secsid_ext.c reports (S-1-5-21-0-0-0-1000) on this computer. XP's
 * SECURITY_LOGON_SESSION_DATA layout (80 bytes), one LocalAlloc block freed by LsaFreeReturnBuffer. */
typedef struct {
    ULONG Size; DWORD LogonIdLo; LONG LogonIdHi; KLSA_STR UserName, LogonDomain, AuthenticationPackage;
    ULONG LogonType, Session; PVOID Sid; FILETIME LogonTime; KLSA_STR LogonServer, DnsDomainName, Upn;
} KLOGON;
NTSTATUS_K KEXAPI kex_LsaGetLogonSessionData(PVOID luid, KLOGON **out)
{
    char user[64], comp[MAX_COMPUTERNAME_LENGTH + 1]; DWORD n = sizeof(user), cn = sizeof(comp); KLOGON *d; WCHAR *w; BYTE *sid;
    static const BYTE usid[] = { 1, 5, 0,0,0,0,0,5, 21,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0xE8,3,0,0 };
    if (!out) return ST_INVALID_PARAM;
    if (!GetUserNameA(user, &n) || !user[0]) lstrcpyA(user, "User");
    if (!GetComputerNameA(comp, &cn)) lstrcpyA(comp, "COMPUTER");
    if (!(d = (KLOGON *)LocalAlloc(LPTR, sizeof(KLOGON) + 4 * 64 * sizeof(WCHAR) + sizeof(usid)))) return ST_NO_MEMORY;
    w = (WCHAR *)(d + 1); sid = (BYTE *)(w + 4 * 64);
    d->Size = sizeof(KLOGON); if (luid) { d->LogonIdLo = ((DWORD *)luid)[0]; d->LogonIdHi = ((LONG *)luid)[1]; }
    ws_put(&d->UserName, user, w); ws_put(&d->LogonDomain, comp, w + 64); ws_put(&d->AuthenticationPackage, "NTLM", w + 128);
    ws_put(&d->LogonServer, comp, w + 192);
    d->LogonType = 2; d->Session = 0; memcpy(sid, usid, sizeof(usid)); d->Sid = sid;   /* Interactive */
    GetSystemTimeAsFileTime(&d->LogonTime);
    *out = d; return ST_OK;
}
