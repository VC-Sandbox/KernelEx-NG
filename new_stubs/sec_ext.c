/*
 * sec_ext.c - minimal security-descriptor helpers for Windows 98 SE (KernelEx-NG).
 *
 * Win98's ADVAPI32 exports InitializeAcl and InitializeSecurityDescriptor as stubs that always fail.
 * KernelEx has working versions, but Chromium 159's chrome_elf.dll (delay-loaded ADVAPI32) still ended
 * up with a failing one, so its crash reporter could not build the empty-DACL security descriptor for
 * its shared memory (CHECK mapped_region_.IsValid()). These are routed under ADVAPI32 from kexnt, which
 * is last in every core.ini "contents=" line and therefore wins.
 * Layouts and rules follow the documented Win32 structures (ACL 8 bytes; absolute SECURITY_DESCRIPTOR
 * 20 bytes on x86: Revision, Sbz1, Control, Owner, Group, Sacl, Dacl). Win98 has no object security,
 * so these only describe security for callers that build and pass descriptors around.
 */
#include "kexnt_common.h"

typedef struct { BYTE AclRevision, Sbz1; WORD AclSize, AceCount, Sbz2; } KACL;
typedef struct { BYTE Revision, Sbz1; WORD Control; PVOID Owner, Group; KACL *Sacl, *Dacl; } KSD;

#define K_ACL_REVISION      2
#define K_ACL_REVISION_DS   4
#define K_SD_REVISION       1
#define K_SE_DACL_PRESENT   0x0004
#define K_SE_DACL_DEFAULTED 0x0008
#define K_SE_SELF_RELATIVE  0x8000

BOOL KEXAPI kex_InitializeAcl(KACL *acl, DWORD size, DWORD rev)
{
    if (!acl) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (rev != K_ACL_REVISION && rev != K_ACL_REVISION_DS) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (size < sizeof(KACL)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (size > 0xFFFF) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    acl->AclRevision = (BYTE)rev; acl->Sbz1 = 0;
    acl->AclSize = (WORD)(size & ~3UL);                           /* DWORD aligned, as NT does */
    acl->AceCount = 0; acl->Sbz2 = 0;
    return TRUE;
}

BOOL KEXAPI kex_IsValidAcl(KACL *acl)
{
    return acl && (acl->AclRevision == K_ACL_REVISION || acl->AclRevision == K_ACL_REVISION_DS)
        && acl->AclSize >= sizeof(KACL);
}

BOOL KEXAPI kex_InitializeSecurityDescriptor(KSD *sd, DWORD rev)
{
    if (!sd) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (rev != K_SD_REVISION) { SetLastError(ERROR_UNKNOWN_REVISION); return FALSE; }
    sd->Revision = K_SD_REVISION; sd->Sbz1 = 0; sd->Control = 0;
    sd->Owner = sd->Group = NULL; sd->Sacl = sd->Dacl = NULL;
    return TRUE;
}

BOOL KEXAPI kex_IsValidSecurityDescriptor(KSD *sd)
{
    if (!sd || sd->Revision != K_SD_REVISION) { SetLastError(ERROR_INVALID_SECURITY_DESCR); return FALSE; }
    return TRUE;
}

BOOL KEXAPI kex_SetSecurityDescriptorDacl(KSD *sd, BOOL present, KACL *dacl, BOOL defaulted)
{
    if (!sd) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (sd->Revision != K_SD_REVISION) { SetLastError(ERROR_UNKNOWN_REVISION); return FALSE; }
    if (sd->Control & K_SE_SELF_RELATIVE) { SetLastError(ERROR_INVALID_SECURITY_DESCR); return FALSE; }
    if (!present) { sd->Control &= ~K_SE_DACL_PRESENT; return TRUE; }
    sd->Control |= K_SE_DACL_PRESENT;
    sd->Dacl = dacl;
    if (defaulted) sd->Control |= K_SE_DACL_DEFAULTED; else sd->Control &= ~K_SE_DACL_DEFAULTED;
    return TRUE;
}

/* KernelEx's token stubs (OpenProcessToken / OpenThreadToken / DuplicateTokenEx in kexbases, 4.5.2 included)
 * hand out the placeholder handle 0xCAFE - Win98 has no tokens. Win98's CloseHandle rejects it, and
 * Chromium's ScopedHandle CHECKs the result (base/win/scoped_handle_verifier.cc:117, chrome.exe startup:
 * OpenProcessToken + DuplicateTokenEx). 0xCAFE is never a real 9x handle (those are multiples of 4),
 * so closing it simply succeeds; everything else goes to Win98. */
#define KEX_TOKEN_PLACEHOLDER ((HANDLE)(ULONG_PTR)0xCAFE)
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
BOOL KEXAPI kex_CloseHandle(HANDLE h)
{
    void kex_dir_close(HANDLE h);
    void kex_section_forget(HANDLE h);
    void kex_iocp_close(HANDLE h);
    if (h == KEX_TOKEN_PLACEHOLDER) return TRUE;
    /* build 131: CloseHandle(NULL) (Firefox 115's mozglue closes a handle it never created) - Windows answers it
     * (ERROR_INVALID_HANDLE, as NT); kexnt's tables use 0 for empty slots, so the bookkeeping below must not see it
     * (kex_dir_close took every empty slot for a pending ReadDirectoryChangesW and dereferenced NULL: page fault) */
    if (!h) return CloseHandle(h);
    { void kex_fview_close(HANDLE h); kex_fview_close(h); }   /* fview_ext.c: writable-file flag, private file views */
    { void kex_lockfile_close(HANDLE h); kex_lockfile_close(h); }   /* lockfile_ext.c: its shared-lock bytes */
    kex_section_forget(h);                              /* shm_ext.c: forget a section handle's access */
    { void kex_imgsec_forget(HANDLE h); kex_imgsec_forget(h); }   /* imgsec_ext.c: an image section */
    kex_dir_close(h);                                   /* dirhandle_ext.c: forget a directory handle (aborts its watches) */
    kex_iocp_close(h);                                  /* iocp_ext.c: a completion port or an associated handle (after the above) */
    { void kex_job_close(HANDLE h); kex_job_close(h); } /* job_ext.c: last handle of a kill-on-close job ends its processes */
    {   /* build 82: who closes Chromium's pipe ends (tab channels were found "gone" while the browser lived) */
        BOOL kex_pipe_end_info(HANDLE h, char *out, int cb, int *server); char nm[48]; int srv;
        if (kex_pipe_end_info(h, nm, sizeof(nm), &srv)) {
            static LONG k; char t[200]; DWORD *fp = (DWORD *)__builtin_frame_address(0);
            if (InterlockedIncrement(&k) <= 60) {
                lstrcpyA(t, srv ? "pipe end closed: SERVER end (handle, caller, caller's caller, this process) " : "pipe end closed: client end (handle, caller, caller's caller, this process) ");
                lstrcatA(t, nm);
                kex_crashnote(t, (DWORD)(ULONG_PTR)h, fp[1], !IsBadReadPtr((void *)fp[0], 8) ? ((DWORD *)fp[0])[1] : 0, GetCurrentProcessId());
                {   /* build 91: a CHILD process closing a server end (build 90: right before it, the tab died) - full chain */
                    static LONG kc; void kex_crashlog_callers(const char *what, DWORD ebp, int max);
                    if (srv && nm[0] && InterlockedIncrement(&kc) <= 12) kex_crashlog_callers("  (server end closed) callers:", (DWORD)(ULONG_PTR)fp, 28);
                }
            }
        }
    }
    {   BOOL kex_pipe_close_begin(HANDLE h, int *slot, int *side, DWORD *gen); void kex_pipe_close_end(int slot, int side, DWORD gen);
        int ps = -1, pside = 0; DWORD pgen = 0; BOOL ispipe = kex_pipe_close_begin(h, &ps, &pside, &pgen);   /* build 121 */
        BOOL r = CloseHandle(h); DWORD le = GetLastError();
        void kex_fpath_closed(HANDLE h); if (r) kex_fpath_closed(h);   /* fpath_ext.c: delete-on-close (build 50) */
        if (r && ispipe) kex_pipe_close_end(ps, pside, pgen);          /* pipe_ext.c: last handle -> slot forgets the event */
        SetLastError(le); return r; }
}

/* ---------------------------------------------------------------- SetEntriesInAcl / SetNamedSecurityInfo (build 125)
 * Windows 98's ADVAPI32 exports both as stubs returning ERROR_CALL_NOT_IMPLEMENTED (120). WiX Burn (VC++ 2013-2022
 * setups) secures its package cache folder with them and stops on the error (VC13Q.LOG: "Error 0x80070078: Failed to
 * create ACL to secure cache path"). SetEntriesInAcl builds a real ACL (documented ACCESS_ALLOWED/DENIED_ACE layout:
 * type, flags, size, mask, SID) that the caller frees with LocalFree. Windows 98 has no object security, so
 * SetNamedSecurityInfo only checks that a file object exists and reports success. */
typedef struct { void *multi; DWORD mop; DWORD form; DWORD type; void *name; } KTRUSTEE;
typedef struct { DWORD perm; DWORD mode; DWORD inherit; KTRUSTEE t; } KEA;
static const BYTE k_everyone[12] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };   /* S-1-1-0 */
static const BYTE *ea_sid(const KEA *e, DWORD *len)
{
    const BYTE *s = (e->t.form == 0 /* TRUSTEE_IS_SID */ && e->t.name) ? (const BYTE *)e->t.name : k_everyone;
    if (IsBadReadPtr(s, 8) || s[0] != 1 || s[1] > 15) s = k_everyone;   /* names/objects: Windows 98 has one user */
    *len = 8 + 4 * s[1];
    return s;
}
static DWORD set_entries(ULONG n, const KEA *ea, KACL *old, KACL **out)
{
    DWORD size = sizeof(KACL), i, sl, oldbytes = 0; BYTE *p; KACL *acl;
    if (!out) return ERROR_INVALID_PARAMETER;
    *out = NULL;
    if (n && !ea) return ERROR_INVALID_PARAMETER;
    for (i = 0; i < n; i++) { if (ea[i].mode == 1 || ea[i].mode == 2 || ea[i].mode == 3) { ea_sid(&ea[i], &sl); size += 8 + sl; } }
    if (old && kex_IsValidAcl(old) && old->AceCount) {
        BYTE *a = (BYTE *)(old + 1); WORD k;
        for (k = 0; k < old->AceCount && (DWORD)(a - (BYTE *)old) + 4 <= old->AclSize; k++) a += *(WORD *)(a + 2);
        oldbytes = (DWORD)(a - (BYTE *)(old + 1));
    }
    size += oldbytes; size = (size + 3) & ~3UL;
    if (size > 0xFFFC) return ERROR_INVALID_PARAMETER;
    if (!(acl = (KACL *)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, size))) return ERROR_NOT_ENOUGH_MEMORY;
    acl->AclRevision = K_ACL_REVISION; acl->AclSize = (WORD)size;
    p = (BYTE *)(acl + 1);
    {   int pass;                     /* deny entries first, as NT orders them */
        for (pass = 0; pass < 2; pass++)
            for (i = 0; i < n; i++) {
                const BYTE *s; WORD asz;
                if (pass == 0 ? ea[i].mode != 3 : (ea[i].mode != 1 && ea[i].mode != 2)) continue;
                s = ea_sid(&ea[i], &sl); asz = (WORD)(8 + sl);
                p[0] = pass == 0 ? 1 /* ACCESS_DENIED */ : 0 /* ACCESS_ALLOWED */;
                p[1] = (BYTE)(ea[i].inherit & 0x1F); *(WORD *)(p + 2) = asz; *(DWORD *)(p + 4) = ea[i].perm;
                CopyMemory(p + 8, s, sl); p += asz; acl->AceCount++;
            }
    }
    if (oldbytes) { CopyMemory(p, old + 1, oldbytes); acl->AceCount = (WORD)(acl->AceCount + old->AceCount); }
    *out = acl;
    return ERROR_SUCCESS;
}
DWORD KEXAPI kex_SetEntriesInAclW(ULONG n, void *ea, KACL *old, KACL **out) { return set_entries(n, (const KEA *)ea, old, out); }
DWORD KEXAPI kex_SetEntriesInAclA(ULONG n, void *ea, KACL *old, KACL **out) { return set_entries(n, (const KEA *)ea, old, out); }
DWORD KEXAPI kex_SetNamedSecurityInfoA(char *name, DWORD type, DWORD info, PVOID owner, PVOID group, PVOID dacl, PVOID sacl)
{
    (void)info; (void)owner; (void)group; (void)dacl; (void)sacl;
    if (!name) return ERROR_INVALID_PARAMETER;
    if (type == 1 /* SE_FILE_OBJECT */ && GetFileAttributesA(name) == INVALID_FILE_ATTRIBUTES) return GetLastError();
    return ERROR_SUCCESS;
}
DWORD KEXAPI kex_SetNamedSecurityInfoW(WCHAR *name, DWORD type, DWORD info, PVOID owner, PVOID group, PVOID dacl, PVOID sacl)
{
    char a[MAX_PATH * 2];
    if (!name) return ERROR_INVALID_PARAMETER;
    if (!WideCharToMultiByte(CP_ACP, 0, name, -1, a, sizeof(a), NULL, NULL)) return ERROR_FILENAME_EXCED_RANGE;
    return kex_SetNamedSecurityInfoA(a, type, info, owner, group, dacl, sacl);
}
