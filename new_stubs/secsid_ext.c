/* secsid_ext.c - the current user's identity for Windows 98 (2026-11-02).
 *
 * Windows 98 has no accounts or tokens. KernelEx 4.5.2 hands out a placeholder token (0xCAFE, sec_ext.c), its
 * GetTokenInformation answers a few classes with odd SIDs (TokenUser = S-1-5-4), and ConvertSidToStringSidA/W /
 * ConvertStringSidToSidA/W are stubs that always fail. Chrome 159 builds its per-user registry suffix from
 * the user SID string (base::win::GetUserSidString) and stops when that fails
 * (NOTREACHED, chrome/installer/util/shell_util.cc:179).
 *
 * One consistent identity, the same SID ntreg_ext.c maps \Registry\User\<sid> to HKEY_CURRENT_USER for:
 *   user          S-1-5-21-0-0-0-1000           primary group S-1-5-21-0-0-0-513
 *   groups        Everyone, Administrators (owner), Users, Interactive, Authenticated Users, logon S-1-5-5-0-1000
 *   no privileges, primary token, session 0, elevated (default type), high integrity, no AppContainer.
 * GetTokenInformation answers every token handle this way (there is only one user). SID <-> string follows
 * the documented SDDL form, including the two-letter well-known aliases. */
#include <windows.h>

#define KEXAPI WINAPI

/* ---------------------------------------------------------------- SIDs */
typedef struct { BYTE rev, n, auth[6]; DWORD sub[15]; } KSID;
static DWORD sid_len(const KSID *s) { return 8 + 4 * s->n; }
static void mk(KSID *s, DWORD auth, int n, DWORD a, DWORD b, DWORD c, DWORD d, DWORD e)
{
    s->rev = 1; s->n = (BYTE)n; memset(s->auth, 0, 6); s->auth[5] = (BYTE)auth;
    s->sub[0] = a; s->sub[1] = b; s->sub[2] = c; s->sub[3] = d; s->sub[4] = e;
}
static BOOL sid_ok(const void *p)
{
    const KSID *s = (const KSID *)p;
    return p && !IsBadReadPtr(p, 8) && s->rev == 1 && s->n <= 15 && !IsBadReadPtr(p, 8 + 4 * s->n);
}

/* ---------------------------------------------------------------- GetTokenInformation */
#define NGROUPS 6
static void group_sid(int i, KSID *s)
{
    switch (i) {
    case 0: mk(s, 1, 1, 0, 0, 0, 0, 0); break;                 /* Everyone */
    case 1: mk(s, 5, 2, 32, 544, 0, 0, 0); break;              /* BUILTIN\Administrators */
    case 2: mk(s, 5, 2, 32, 545, 0, 0, 0); break;              /* BUILTIN\Users */
    case 3: mk(s, 5, 1, 4, 0, 0, 0, 0); break;                 /* INTERACTIVE */
    case 4: mk(s, 5, 1, 11, 0, 0, 0, 0); break;                /* Authenticated Users */
    default: mk(s, 5, 3, 5, 0, 1000, 0, 0); break;             /* logon session */
    }
}
static const DWORD group_attr[NGROUPS] = { 7, 0xF, 7, 7, 7, 0xC0000007 };

static BOOL out_need(DWORD need, DWORD len, PDWORD ret, void *buf)
{
    if (ret) *ret = need;
    if (len < need || !buf) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (IsBadWritePtr(buf, need)) { SetLastError(ERROR_NOACCESS); return FALSE; }
    return TRUE;
}
static BOOL put_dw(DWORD v, void *buf, DWORD len, PDWORD ret)
{ if (!out_need(4, len, ret, buf)) return FALSE; *(DWORD *)buf = v; return TRUE; }

/* one SID behind a header of hdr bytes whose first DWORD points to it (TOKEN_USER/OWNER/PRIMARY_GROUP/...) */
static BOOL put_sid_struct(const KSID *s, DWORD hdr, DWORD attr, void *buf, DWORD len, PDWORD ret)
{
    DWORD need = hdr + sid_len(s);
    if (!out_need(need, len, ret, buf)) return FALSE;
    memset(buf, 0, hdr);
    memcpy((BYTE *)buf + hdr, s, sid_len(s));
    ((DWORD *)buf)[0] = (DWORD)(ULONG_PTR)((BYTE *)buf + hdr);
    if (hdr >= 8) ((DWORD *)buf)[1] = attr;
    return TRUE;
}
/* TOKEN_GROUPS: count, then SID_AND_ATTRIBUTES[], then the SIDs */
static BOOL put_groups(int first, int count, void *buf, DWORD len, PDWORD ret)
{
    KSID s; DWORD need = 4 + 8 * count, off; int i;
    for (i = 0; i < count; i++) { group_sid(first + i, &s); need += sid_len(&s); }
    if (!out_need(need, len, ret, buf)) return FALSE;
    ((DWORD *)buf)[0] = count;
    off = 4 + 8 * count;
    for (i = 0; i < count; i++) {
        group_sid(first + i, &s);
        memcpy((BYTE *)buf + off, &s, sid_len(&s));
        ((DWORD *)buf)[1 + 2 * i] = (DWORD)(ULONG_PTR)((BYTE *)buf + off);
        ((DWORD *)buf)[2 + 2 * i] = group_attr[first + i];
        off += sid_len(&s);
    }
    return TRUE;
}

/* Build 131: GetKernelObjectSecurity / SetKernelObjectSecurity. Windows 98 has no security on objects, so every object
 * describes itself as NT would describe one nobody restricts: owner = the user, group = its primary group, DACL NULL
 * (everyone), and - asked for its LABEL (Vista+) - a SACL with one medium-integrity mandatory label (no write up).
 * Setting it is accepted. Chromium's sandbox children harden their token's label this way before they lower it
 * (restricted_token_utils.cc HardenTokenIntegrityLevelPolicy); Windows 98's own exports fail (120), the child quit
 * (SBOX_FATAL_MITIGATION). */
BOOL KEXAPI kex_GetKernelObjectSecurity(HANDLE h, DWORD info, PSECURITY_DESCRIPTOR out, DWORD len, LPDWORD need)
{
    BYTE b[256]; DWORD n = 20; KSID own, grp, il;
    if (!h) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    memset(b, 0, sizeof(b));
    b[0] = 1;                                                     /* Revision */
    *(WORD *)(b + 2) = 0x8000 | 0x0004;                          /* SE_SELF_RELATIVE | SE_DACL_PRESENT (NULL DACL) */
    mk(&own, 5, 5, 21, 0, 0, 0, 1000); mk(&grp, 5, 5, 21, 0, 0, 0, 513);
    if (info & OWNER_SECURITY_INFORMATION) { *(DWORD *)(b + 4) = n; memcpy(b + n, &own, sid_len(&own)); n += sid_len(&own); }
    if (info & GROUP_SECURITY_INFORMATION) { *(DWORD *)(b + 8) = n; memcpy(b + n, &grp, sid_len(&grp)); n += sid_len(&grp); }
    if (info & 0x10 /* LABEL_SECURITY_INFORMATION */) {
        DWORD acl = n, ace = n + 8, ln;
        mk(&il, 16, 1, 0x2000, 0, 0, 0, 0);                      /* S-1-16-8192 medium */
        ln = 8 + sid_len(&il);
        b[acl] = 2; *(WORD *)(b + acl + 2) = (WORD)(8 + ln); *(WORD *)(b + acl + 4) = 1;   /* ACL: rev 2, size, 1 ACE */
        b[ace] = 0x11; b[ace + 1] = 0; *(WORD *)(b + ace + 2) = (WORD)ln;                /* SYSTEM_MANDATORY_LABEL_ACE */
        *(DWORD *)(b + ace + 4) = 1;                                                     /* NO_WRITE_UP */
        memcpy(b + ace + 8, &il, sid_len(&il));
        *(DWORD *)(b + 12) = acl; *(WORD *)(b + 2) |= 0x0010;                            /* SE_SACL_PRESENT */
        n += 8 + ln;
    }
    if (need) *need = n;
    if (!out || len < n) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    memcpy(out, b, n);
    return TRUE;
}
BOOL KEXAPI kex_SetKernelObjectSecurity(HANDLE h, DWORD info, PSECURITY_DESCRIPTOR sd)
{
    (void)info;
    if (!h) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (!sd) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return TRUE;
}

/* Build 131: SetTokenInformation. Windows 98 has no tokens (kexnt's tokens are a placeholder) and no security on
 * objects, so the settings a program makes on its token change nothing on 98 - accepted, as NT accepts them for the
 * process's own token. Chromium's sandbox (Firefox 115's content processes) sets the default DACL and the integrity
 * level of the restricted token it starts children with; Windows 98's own export fails (120) and the broker gave up
 * (SBOX_ERROR_CANNOT_CREATE_RESTRICTED_TOKEN). */
BOOL KEXAPI kex_SetTokenInformation(HANDLE token, DWORD cls, LPVOID buf, DWORD len)
{
    if (!token) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (cls < 1 || cls > 48) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (len && (!buf || IsBadReadPtr(buf, len))) { SetLastError(ERROR_NOACCESS); return FALSE; }
    return TRUE;
}

BOOL KEXAPI kex_GetTokenInformation(HANDLE token, DWORD cls, LPVOID buf, DWORD len, PDWORD ret)
{
    KSID s;
    if (!token) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    switch (cls) {
    case 1:  mk(&s, 5, 5, 21, 0, 0, 0, 1000); return put_sid_struct(&s, 8, 0, buf, len, ret);    /* TokenUser */
    case 2:  return put_groups(0, NGROUPS, buf, len, ret);                                       /* TokenGroups */
    case 3:  return put_dw(0, buf, len, ret);                                                    /* TokenPrivileges: none */
    case 4:  mk(&s, 5, 5, 21, 0, 0, 0, 1000); return put_sid_struct(&s, 4, 0, buf, len, ret);    /* TokenOwner */
    case 5:  mk(&s, 5, 5, 21, 0, 0, 0, 513); return put_sid_struct(&s, 4, 0, buf, len, ret);     /* TokenPrimaryGroup */
    case 6:  return put_dw(0, buf, len, ret);                                                    /* TokenDefaultDacl: none */
    case 7:                                                                                      /* TokenSource */
        if (!out_need(16, len, ret, buf)) return FALSE;
        memcpy(buf, "User32  ", 8); memset((BYTE *)buf + 8, 0, 8); ((DWORD *)buf)[2] = 1000;
        return TRUE;
    case 8:  return put_dw(1, buf, len, ret);                                                    /* TokenType: primary */
    case 9:  return put_dw(2, buf, len, ret);                                                    /* ImpersonationLevel */
    case 10: {                                                                                   /* TokenStatistics */
        DWORD *d;
        if (!out_need(56, len, ret, buf)) return FALSE;
        d = (DWORD *)buf; memset(d, 0, 56);
        d[0] = 0x1001;                      /* TokenId */
        d[2] = 1000;                        /* AuthenticationId (logon session) */
        d[4] = 0xFFFFFFFF; d[5] = 0x7FFFFFFF;   /* ExpirationTime: never */
        d[6] = 1;                           /* TokenType */
        d[10] = NGROUPS;                    /* GroupCount */
        d[12] = 0x1002;                     /* ModifiedId */
        return TRUE;
    }
    case 11: return put_dw(0, buf, len, ret);                                                    /* TokenRestrictedSids */
    case 12: return put_dw(0, buf, len, ret);                                                    /* TokenSessionId */
    case 18: return put_dw(1, buf, len, ret);                                                    /* TokenElevationType */
    case 20: return put_dw(1, buf, len, ret);                                                    /* TokenElevation */
    case 21: return put_dw(0, buf, len, ret);                                                    /* TokenHasRestrictions */
    case 23: case 24: case 26: return put_dw(0, buf, len, ret);                                  /* virtualization, UIAccess */
    case 25: mk(&s, 16, 1, 0x3000, 0, 0, 0, 0); return put_sid_struct(&s, 8, 0x60, buf, len, ret); /* IntegrityLevel: high */
    case 27: return put_dw(1, buf, len, ret);                                                    /* MandatoryPolicy: NO_WRITE_UP */
    case 28: return put_groups(NGROUPS - 1, 1, buf, len, ret);                                   /* TokenLogonSid */
    case 29: return put_dw(0, buf, len, ret);                                                    /* TokenIsAppContainer */
    case 30: return put_dw(0, buf, len, ret);                                                    /* TokenCapabilities: none */
    case 31: return put_dw(0, buf, len, ret);                                                    /* TokenAppContainerSid: NULL */
    case 32: return put_dw(0, buf, len, ret);                                                    /* TokenAppContainerNumber */
    }
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
}

/* ---------------------------------------------------------------- SID <-> string */
static int put_u(char *p, DWORD v)
{
    char t[12]; int n = 0, i;
    do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    for (i = 0; i < n; i++) p[i] = t[n - 1 - i];
    return n;
}
static int sid_text(const KSID *s, char *o)            /* o: at least 8 + 11*16 + 16 bytes */
{
    static const char hx[] = "0123456789ABCDEF";
    int n = 0, i;
    o[n++] = 'S'; o[n++] = '-'; n += put_u(o + n, s->rev); o[n++] = '-';
    if (s->auth[0] || s->auth[1]) {
        o[n++] = '0'; o[n++] = 'x';
        for (i = 0; i < 6; i++) { o[n++] = hx[s->auth[i] >> 4]; o[n++] = hx[s->auth[i] & 15]; }
    } else
        n += put_u(o + n, ((DWORD)s->auth[2] << 24) | ((DWORD)s->auth[3] << 16) | ((DWORD)s->auth[4] << 8) | s->auth[5]);
    for (i = 0; i < s->n; i++) { o[n++] = '-'; n += put_u(o + n, s->sub[i]); }
    o[n] = 0;
    return n;
}
BOOL KEXAPI kex_ConvertSidToStringSidA(PSID sid, LPSTR *out)
{
    char t[256]; int n; LPSTR p;
    if (!out || !sid_ok(sid)) { SetLastError(ERROR_INVALID_SID); return FALSE; }
    n = sid_text((const KSID *)sid, t);
    if (!(p = (LPSTR)LocalAlloc(LMEM_FIXED, n + 1))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    memcpy(p, t, n + 1); *out = p;
    return TRUE;
}
BOOL KEXAPI kex_ConvertSidToStringSidW(PSID sid, LPWSTR *out)
{
    char t[256]; int n, i; LPWSTR p;
    if (!out || !sid_ok(sid)) { SetLastError(ERROR_INVALID_SID); return FALSE; }
    n = sid_text((const KSID *)sid, t);
    if (!(p = (LPWSTR)LocalAlloc(LMEM_FIXED, 2 * (n + 1)))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    for (i = 0; i <= n; i++) p[i] = (WCHAR)(unsigned char)t[i];
    *out = p;
    return TRUE;
}

static const struct { char a[3]; const char *s; } ALIAS[] = {
    { "WD", "S-1-1-0" }, { "CO", "S-1-3-0" }, { "CG", "S-1-3-1" }, { "OW", "S-1-3-4" },
    { "NU", "S-1-5-2" }, { "IU", "S-1-5-4" }, { "SU", "S-1-5-6" }, { "AN", "S-1-5-7" },
    { "ED", "S-1-5-9" }, { "PS", "S-1-5-10" }, { "AU", "S-1-5-11" }, { "RC", "S-1-5-12" },
    { "SY", "S-1-5-18" }, { "LS", "S-1-5-19" }, { "NS", "S-1-5-20" },
    { "BA", "S-1-5-32-544" }, { "BU", "S-1-5-32-545" }, { "BG", "S-1-5-32-546" }, { "PU", "S-1-5-32-547" },
    { "AO", "S-1-5-32-548" }, { "SO", "S-1-5-32-549" }, { "PO", "S-1-5-32-550" }, { "BO", "S-1-5-32-551" },
    { "RE", "S-1-5-32-552" }, { "RU", "S-1-5-32-554" }, { "RD", "S-1-5-32-555" }, { "NO", "S-1-5-32-556" },
    { "AC", "S-1-15-2-1" }, { "LW", "S-1-16-4096" }, { "ME", "S-1-16-8192" }, { "HI", "S-1-16-12288" },
    { "SI", "S-1-16-16384" },
};
static BOOL parse_sid(const char *t, KSID *s)
{
    unsigned long long v; int i;
    if (t[0] && t[1] && !t[2]) {
        for (i = 0; i < (int)(sizeof(ALIAS) / sizeof(ALIAS[0])); i++)
            if ((t[0] & ~32) == ALIAS[i].a[0] && (t[1] & ~32) == ALIAS[i].a[1]) { t = ALIAS[i].s; break; }
    }
    if ((t[0] != 'S' && t[0] != 's') || t[1] != '-') return FALSE;
    t += 2;
    for (v = 0; *t >= '0' && *t <= '9'; t++) v = v * 10 + (*t - '0');
    if (v != 1 || *t != '-') return FALSE;
    t++;
    v = 0;
    if (t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
        for (t += 2; ; t++) {
            int d = (*t >= '0' && *t <= '9') ? *t - '0' : (*t >= 'a' && *t <= 'f') ? *t - 'a' + 10 : (*t >= 'A' && *t <= 'F') ? *t - 'A' + 10 : -1;
            if (d < 0) break;
            v = v * 16 + d;
        }
    } else {
        if (*t < '0' || *t > '9') return FALSE;
        for (; *t >= '0' && *t <= '9'; t++) v = v * 10 + (*t - '0');
    }
    if (v >> 48) return FALSE;
    s->rev = 1; s->n = 0;
    for (i = 0; i < 6; i++) s->auth[i] = (BYTE)(v >> (8 * (5 - i)));
    while (*t == '-') {
        unsigned long long x = 0; t++;
        if (*t < '0' || *t > '9' || s->n >= 15) return FALSE;
        for (; *t >= '0' && *t <= '9'; t++) { x = x * 10 + (*t - '0'); if (x > 0xFFFFFFFFULL) return FALSE; }
        s->sub[s->n++] = (DWORD)x;
    }
    return *t == 0;
}
static BOOL string_to_sid(const char *t, PSID *out)
{
    KSID s; void *p;
    if (!t || !out) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!parse_sid(t, &s)) { SetLastError(ERROR_INVALID_SID); return FALSE; }
    if (!(p = LocalAlloc(LMEM_FIXED, sid_len(&s)))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    memcpy(p, &s, sid_len(&s)); *out = p;
    return TRUE;
}
BOOL KEXAPI kex_ConvertStringSidToSidA(LPCSTR str, PSID *out)
{
    char t[256]; int i;
    if (!str || IsBadStringPtrA(str, 256)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < 255 && str[i]; i++) t[i] = str[i];
    t[i] = 0;
    return string_to_sid(t, out);
}
BOOL KEXAPI kex_ConvertStringSidToSidW(LPCWSTR str, PSID *out)
{
    char t[256]; int i;
    if (!str || IsBadReadPtr(str, 2)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < 255 && str[i]; i++) { if (str[i] > 127) { SetLastError(ERROR_INVALID_SID); return FALSE; } t[i] = (char)str[i]; }
    t[i] = 0;
    return string_to_sid(t, out);
}
