/* procspawn_ext.c - child processes the way Chromium launches them (2026-11-02, build 10).
 *
 * Chromium's base::LaunchProcess (launch_win.cc) for every child (GPU, network service, renderer):
 *   1. SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) for each handle the child needs
 *      (the Mojo channel end, shared memory regions) and PCHECKs the result. Windows 98 has the export but
 *      always fails with ERROR_CALL_NOT_IMPLEMENTED (0x78) - launch_win.cc:345 "This function is only
 *      valid in Win32 mode".
 *   2. STARTUPINFOEXW (cb 72) + EXTENDED_STARTUPINFO_PRESENT + PROC_THREAD_ATTRIBUTE_HANDLE_LIST, and
 *      CreateProcessW(bInheritHandles = TRUE). The handle VALUES go to the child on its command line
 *      (--mojo-platform-channel-handle=N, --field-trial-handle=...), so they must be the same numbers there.
 *
 * Windows 98 keeps the inherit bit in the process handle table entry itself (HANDLE_TABLE_ENTRY.flags bit 31,
 * HF_INHERIT in common/kstructs.h, the bit CreateProcess looks at when it copies a parent's inheritable
 * entries to the SAME slots of the child's table). So SetHandleInformation sets/clears that bit in place
 * and the handle keeps its value - exactly NT's behaviour. HANDLE_FLAG_PROTECT_FROM_CLOSE is remembered and
 * reported by GetHandleInformation (9x has no such bit; CloseHandle still closes).
 *
 * CreateProcessA/W: flags Windows 98 does not know are removed before the call (EXTENDED_STARTUPINFO_PRESENT,
 * CREATE_BREAKAWAY_FROM_JOB, CREATE_PRESERVE_CODE_AUTHZ_LEVEL, INHERIT_PARENT_AFFINITY, CREATE_PROTECTED_PROCESS,
 * CREATE_SECURE_PROCESS, ...); a STARTUPINFOEX is passed on as a plain STARTUPINFO (its attribute list has no
 * 9x meaning: a HANDLE_LIST only narrows what is inherited, and 9x passes every inheritable handle). A
 * CREATE_UNICODE_ENVIRONMENT block is converted to the ANSI block Windows 98 expects (KernelEx 4.5 drops the
 * flag but passes the UTF-16 block on unchanged, which the child reads as a one-letter environment).
 * Behaviour from the documentation; table layout from KernelEx's own kstructs.h / kexcoresdk.cpp. */
#include "kexnt_common.h"

FARPROC kex_prev_impl(const char *dll, const char *name);                      /* gdiguard_ext.c */
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);           /* crashlog_ext.c */

#define HF_INHERIT 0x80000000UL
#ifndef HANDLE_FLAG_INHERIT
#define HANDLE_FLAG_INHERIT 1
#define HANDLE_FLAG_PROTECT_FROM_CLOSE 2
#endif
#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

/* ---------------------------------------------------------------- the 9x handle table */
typedef struct { DWORD flags; void *obj; } HTE;
typedef struct { DWORD count; HTE e[1]; } HTAB;

static HTE *entry(HANDLE h)
{
    BYTE *pdb; HTAB *t; DWORD i = (DWORD)(ULONG_PTR)h;
    if (!kex_is_win9x() || !i || (i & 3) || i >= 0x80000000UL) return NULL;   /* pseudo / global handles */
    __asm__ volatile("movl %%fs:0x30, %0" : "=r"(pdb));
    if (!pdb || IsBadReadPtr(pdb + 0x44, 4)) return NULL;
    t = *(HTAB **)(pdb + 0x44);                                               /* PDB98.pHandleTable */
    i /= 4;
    if (!t || IsBadReadPtr(t, 4) || i > t->count || IsBadWritePtr(&t->e[i], sizeof(HTE))) return NULL;
    if (!t->e[i].obj || IsBadReadPtr(t->e[i].obj, 4)) return NULL;
    return &t->e[i];
}

#define NPROT 64
static HANDLE g_prot[NPROT];
static LONG   g_prot_lock;
static void prot_set(HANDLE h, BOOL on)
{
    int i, free_slot = -1;
    kex_spin_acquire((volatile LONG *)&g_prot_lock);
    for (i = 0; i < NPROT; i++) {
        if (g_prot[i] == h) { if (!on) g_prot[i] = 0; free_slot = -2; break; }
        if (!g_prot[i] && free_slot == -1) free_slot = i;
    }
    if (on && free_slot >= 0) g_prot[free_slot] = h;
    g_prot_lock = 0;
}
static BOOL prot_get(HANDLE h)
{
    int i;
    for (i = 0; i < NPROT; i++) if (g_prot[i] == h) return TRUE;
    return FALSE;
}

BOOL KEXAPI kex_SetHandleInformation(HANDLE h, DWORD mask, DWORD flags)
{
    typedef BOOL (WINAPI *T)(HANDLE, DWORD, DWORD);
    HTE *e;
    if (!kex_is_win9x()) {
        T f = (T)(void *)kex_sysproc("KERNEL32.DLL", "SetHandleInformation");
        return f ? f(h, mask, flags) : FALSE;
    }
    if (!(e = entry(h))) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (mask & HANDLE_FLAG_INHERIT) {
        if (flags & HANDLE_FLAG_INHERIT) e->flags |= HF_INHERIT;
        else e->flags &= ~HF_INHERIT;
    }
    if (mask & HANDLE_FLAG_PROTECT_FROM_CLOSE) prot_set(h, (flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0);
    return TRUE;
}

BOOL KEXAPI kex_GetHandleInformation(HANDLE h, LPDWORD flags)
{
    typedef BOOL (WINAPI *T)(HANDLE, LPDWORD);
    HTE *e;
    if (!kex_is_win9x()) {
        T f = (T)(void *)kex_sysproc("KERNEL32.DLL", "GetHandleInformation");
        return f ? f(h, flags) : FALSE;
    }
    if (!flags) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!(e = entry(h))) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    *flags = ((e->flags & HF_INHERIT) ? HANDLE_FLAG_INHERIT : 0) | (prot_get(h) ? HANDLE_FLAG_PROTECT_FROM_CLOSE : 0);
    return TRUE;
}

/* ---------------------------------------------------------------- CreateProcess */
/* What Windows 98's CreateProcess understands (plus CREATE_UNICODE_ENVIRONMENT, handled here). */
#define K9X_FLAGS (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | DETACHED_PROCESS | \
                   CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS | IDLE_PRIORITY_CLASS | HIGH_PRIORITY_CLASS | \
                   REALTIME_PRIORITY_CLASS | CREATE_NEW_PROCESS_GROUP | CREATE_SEPARATE_WOW_VDM | \
                   CREATE_SHARED_WOW_VDM | CREATE_DEFAULT_ERROR_MODE | CREATE_NO_WINDOW)
/* BELOW/ABOVE_NORMAL_PRIORITY_CLASS (0x4000 / 0x8000) are NT-only: dropped, the child runs at normal priority.
 * CREATE_NO_WINDOW is kept: KernelEx's CreateProcessA turns it into SW_HIDE. */

static DWORD fix_flags(DWORD f)
{
    DWORD r = f & (K9X_FLAGS | CREATE_UNICODE_ENVIRONMENT);
    r &= ~CREATE_UNICODE_ENVIRONMENT;                                     /* the block is ANSI by now */
    if ((r | CREATE_UNICODE_ENVIRONMENT) != (f | CREATE_UNICODE_ENVIRONMENT)) kex_trace("CreateProcess: flags Windows 98 does not know removed", f, r, 0, 0);
    return r;
}

/* UTF-16 environment block -> ANSI block (HeapAlloc'd), NULL when not needed / on failure. */
static char *env_to_ansi(const WCHAR *w)
{
    const WCHAR *p = w; int n, len; char *a;
    if (!w) return NULL;
    while (*p) p += lstrlenW(p) + 1;
    len = (int)(p - w) + 1;                                               /* including the final NUL */
    n = WideCharToMultiByte(CP_ACP, 0, w, len, NULL, 0, NULL, NULL);
    if (n <= 0 || !(a = (char *)HeapAlloc(GetProcessHeap(), 0, n + 1))) return NULL;
    WideCharToMultiByte(CP_ACP, 0, w, len, a, n, NULL, NULL);
    a[n] = 0;
    return a;
}

typedef BOOL (WINAPI *T_CPW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                             LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *T_CPA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                             LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

/* build 83: PROC_THREAD_ATTRIBUTE_HANDLE_LIST honoured. Windows 98 copies EVERY inheritable handle of the parent
 * into a child; NT copies only the listed ones. Build 82's log showed tab processes holding (and closing) the
 * browser's own pipe ends - copies they were never given - and every Chrome helper inheriting all pipe ends,
 * sections and events the browser had marked inheritable for earlier launches (pipe instances kept alive,
 * "other end gone" decided by whoever closed last, K32 objects piling up until CreateEvent failed: browser FATAL
 * platform_channel.cc:112 "Not enough storage" at 21:38:42). Now: for the duration of the CreateProcess call
 * every inheritable handle NOT in the list has its HF_INHERIT bit cleared in this process's handle table, and
 * set again afterwards. One launch at a time (critical section), so two launches cannot undo each other. */
#define PTA_HANDLE_LIST 0x00020002
PVOID kex_ProcThreadAttributeFind(LPPROC_THREAD_ATTRIBUTE_LIST list, DWORD_PTR attr, SIZE_T *size);   /* sysinfo_ext.c */
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
static CRITICAL_SECTION g_launch_cs; static volatile LONG g_launch_init;
#define NHIDE 2048
static DWORD g_hidden[NHIDE];
static int narrow_inherit(const HANDLE *keep, int nkeep)
{
    BYTE *pdb; HTAB *t; DWORD i; int n = 0, k;
    __asm__ volatile("movl %%fs:0x30, %0" : "=r"(pdb));
    if (!pdb || IsBadReadPtr(pdb + 0x44, 4)) return 0;
    t = *(HTAB **)(pdb + 0x44);
    if (!t || IsBadReadPtr(t, 4) || IsBadWritePtr(&t->e[0], (t->count + 1) * sizeof(HTE))) return 0;
    for (i = 1; i <= t->count && n < NHIDE; i++) {
        HANDLE h = (HANDLE)(ULONG_PTR)(i * 4);
        if (!t->e[i].obj || !(t->e[i].flags & HF_INHERIT)) continue;
        for (k = 0; k < nkeep; k++) if (keep[k] == h) break;
        if (k < nkeep) continue;
        t->e[i].flags &= ~HF_INHERIT; g_hidden[n++] = i;
    }
    return n;
}
static void restore_inherit(int n)
{
    BYTE *pdb; HTAB *t; int k;
    __asm__ volatile("movl %%fs:0x30, %0" : "=r"(pdb));
    if (!pdb || IsBadReadPtr(pdb + 0x44, 4)) return;
    t = *(HTAB **)(pdb + 0x44);
    if (!t) return;
    for (k = 0; k < n; k++) if (g_hidden[k] <= t->count && t->e[g_hidden[k]].obj) t->e[g_hidden[k]].flags |= HF_INHERIT;
}

/* build 131: the EXE a CreateProcess call names (application name, else the command line's first word) */
static void exe_of(const char *app, const char *cmd, char *out, int cb)
{
    const char *q; int n = 0;
    out[0] = 0;
    if (app && app[0]) { lstrcpynA(out, app, cb); return; }
    if (!cmd) return;
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    if (*cmd == '"') { for (q = cmd + 1; *q && *q != '"' && n < cb - 1; q++) out[n++] = *q; }
    else for (q = cmd; *q && *q != ' ' && *q != '\t' && n < cb - 1; q++) out[n++] = *q;
    out[n] = 0;
}
void kex_fpeb_note_child(DWORD pid, HANDLE ph, const char *exe);   /* chrome_ext.c */
static void note_child_w(LPCWSTR app, LPCWSTR cmd, LPPROCESS_INFORMATION pi)
{
    char a[MAX_PATH], c[MAX_PATH * 2], e[MAX_PATH];
    a[0] = c[0] = 0;
    if (app) WideCharToMultiByte(CP_ACP, 0, app, -1, a, sizeof(a), NULL, NULL);
    if (cmd) WideCharToMultiByte(CP_ACP, 0, cmd, -1, c, sizeof(c), NULL, NULL);
    a[sizeof(a) - 1] = c[sizeof(c) - 1] = 0;
    exe_of(a, c, e, sizeof(e));
    kex_fpeb_note_child(pi->dwProcessId, pi->hProcess, e);
}

BOOL KEXAPI kex_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                               BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si,
                               LPPROCESS_INFORMATION pi)
{
    static T_CPW cp;
    STARTUPINFOW s; char *aenv = NULL; BOOL r; DWORD e;
    const HANDLE *keep = NULL; int nkeep = 0, hidden = 0; BOOL narrowed = FALSE;
    if (!cp) cp = (T_CPW)(void *)kex_prev_impl("KERNEL32.DLL", "CreateProcessW");
    if (!cp) { SetLastError(ERROR_PROC_NOT_FOUND); return FALSE; }
    if (!kex_is_win9x()) return cp(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
    if (!si) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(&s, 0, sizeof(s));
    memcpy(&s, si, si->cb && si->cb < sizeof(s) ? si->cb : sizeof(s));
    s.cb = sizeof(s);
    if (s.lpDesktop && !s.lpDesktop[0]) s.lpDesktop = NULL;
    if ((flags & CREATE_UNICODE_ENVIRONMENT) && env) {
        if (!(aenv = env_to_ansi((const WCHAR *)env))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        env = aenv;
    }
    if (inherit && (flags & EXTENDED_STARTUPINFO_PRESENT) && si->cb >= sizeof(STARTUPINFOW) + sizeof(void *)) {
        LPPROC_THREAD_ATTRIBUTE_LIST al = *(LPPROC_THREAD_ATTRIBUTE_LIST *)((BYTE *)si + sizeof(STARTUPINFOW));
        SIZE_T sz = 0;
        keep = (const HANDLE *)kex_ProcThreadAttributeFind(al, PTA_HANDLE_LIST, &sz);
        if (keep) { nkeep = (int)(sz / sizeof(HANDLE)); narrowed = TRUE; }
    }
    flags = fix_flags(flags);
    if (narrowed) {
        if (InterlockedCompareExchange(&g_launch_init, 1, 0) == 0) {          /* 0 -> 1: this thread initialises */
            InitializeCriticalSection(&g_launch_cs); InterlockedExchange(&g_launch_init, 2);
        }
        while (g_launch_init != 2) Sleep(1);
        EnterCriticalSection(&g_launch_cs);
        hidden = narrow_inherit(keep, nkeep);
    }
    r = cp(app, cmd, pa, ta, inherit, flags, env, dir, &s, pi);
    e = GetLastError();
    if (narrowed) {
        static LONG k;
        restore_inherit(hidden);
        LeaveCriticalSection(&g_launch_cs);
        if (InterlockedIncrement(&k) <= 10)
            kex_crashnote("CreateProcess with a handle list: handles passed, other inheritable handles held back (passed, held back, ok, child)",
                          (DWORD)nkeep, (DWORD)hidden, (DWORD)r, r && pi ? pi->dwProcessId : 0);
    }
    kex_trace("CreateProcessW", r, r ? 0 : e, inherit, r && pi ? pi->dwProcessId : 0);
    if (r && pi) { DWORD kex_pid_nt(DWORD); note_child_w(app, cmd, pi); pi->dwProcessId = kex_pid_nt(pi->dwProcessId); SetLastError(e); }   /* build 131: PEB record; NT-style id */
    if (!r) {   /* build 131: which program could not start (error 31 = an import it needs is missing) */
        static LONG kf; char t[300] = "CreateProcess FAILED (error, -, -, -): ";
        if (InterlockedIncrement(&kf) <= 20) {
            int n = lstrlenA(t);
            WideCharToMultiByte(CP_ACP, 0, app ? app : (cmd ? cmd : L"?"), -1, t + n, (int)sizeof(t) - n - 1, NULL, NULL);
            t[sizeof(t) - 1] = 0;
            kex_crashnote(t, e, 0, 0, 0);
            if (e == 31 && kf == 1) {   /* keep a copy of the program for the import check (setups delete it at once) */
                char src[MAX_PATH], dst[MAX_PATH], *q = t + n, *z; DWORD k = 0;
                if (*q == '"') { q++; for (z = q; *z && *z != '"'; z++) ; *z = 0; }
                else if (!app) { for (z = q; *z && *z != ' '; z++) ; *z = 0; }
                lstrcpynA(src, q, MAX_PATH);
                k = GetTempPathA(MAX_PATH - 20, dst);
                if (k && k < MAX_PATH - 20) { lstrcatA(dst, "KEXFAIL31.EXE"); if (CopyFileA(src, dst, FALSE)) kex_crashnote("  copy kept as %TEMP%\\KEXFAIL31.EXE", 0, 0, 0, 0); }
            }
        }
    }
    if (aenv) HeapFree(GetProcessHeap(), 0, aenv);
    SetLastError(e);
    return r;
}

/* Build 131: CreateProcessAsUser. Windows 98 runs every program with the same rights and has no tokens (kexnt's are a
 * placeholder), so a program started "as a user" is started like any other - Chromium's sandbox (Firefox 115's content
 * processes) creates every child with CreateProcessAsUserW and its restricted token; Windows 98's export fails (120,
 * SBOX_ERROR_CREATE_PROCESS). */
BOOL KEXAPI kex_CreateProcessAsUserW(HANDLE tok, LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                     BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si,
                                     LPPROCESS_INFORMATION pi)
{
    (void)tok;
    return kex_CreateProcessW(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
}
BOOL KEXAPI kex_CreateProcessAsUserA(HANDLE tok, LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                     BOOL inherit, DWORD flags, LPVOID env, LPCSTR dir, LPSTARTUPINFOA si,
                                     LPPROCESS_INFORMATION pi);

BOOL KEXAPI kex_CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                               BOOL inherit, DWORD flags, LPVOID env, LPCSTR dir, LPSTARTUPINFOA si,
                               LPPROCESS_INFORMATION pi)
{
    static T_CPA cp;
    STARTUPINFOA s; char *aenv = NULL; BOOL r; DWORD e;
    if (!cp) cp = (T_CPA)(void *)kex_prev_impl("KERNEL32.DLL", "CreateProcessA");
    if (!cp) { SetLastError(ERROR_PROC_NOT_FOUND); return FALSE; }
    if (!kex_is_win9x()) return cp(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
    if (!si) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(&s, 0, sizeof(s));
    memcpy(&s, si, si->cb && si->cb < sizeof(s) ? si->cb : sizeof(s));
    s.cb = sizeof(s);
    if (s.lpDesktop && !s.lpDesktop[0]) s.lpDesktop = NULL;
    if ((flags & CREATE_UNICODE_ENVIRONMENT) && env) {
        if (!(aenv = env_to_ansi((const WCHAR *)env))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        env = aenv;
    }
    flags = fix_flags(flags);
    r = cp(app, cmd, pa, ta, inherit, flags, env, dir, &s, pi);
    e = GetLastError();
    if (r && pi) { DWORD kex_pid_nt(DWORD); char x[MAX_PATH]; exe_of(app, cmd, x, sizeof(x)); kex_fpeb_note_child(pi->dwProcessId, pi->hProcess, x); pi->dwProcessId = kex_pid_nt(pi->dwProcessId); }   /* build 131 */
    if (aenv) HeapFree(GetProcessHeap(), 0, aenv);
    SetLastError(e);
    return r;
}

/* ---------------------------------------------------------------- handle facts for NtQueryObject & co. (build 14)
 * K32 object type (first byte of the object: WIN98_K32OBJ_*), the access mask Windows 98 keeps in the handle table
 * entry (without HF_INHERIT) and whether the handle is inheritable. FALSE for invalid / pseudo / global handles. */
BOOL kex_handle_facts(HANDLE h, BYTE *type, DWORD *access, BOOL *inherit)
{
    HTE *e = entry(h);
    BYTE *o;
    if (!e) return FALSE;
    o = (BYTE *)e->obj;
    if (IsBadReadPtr(o, 1)) return FALSE;
    if (type) *type = o[0];
    if (access) *access = e->flags & ~HF_INHERIT;
    if (inherit) *inherit = (e->flags & HF_INHERIT) != 0;
    return TRUE;
}

BOOL KEXAPI kex_CreateProcessAsUserA(HANDLE tok, LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                     BOOL inherit, DWORD flags, LPVOID env, LPCSTR dir, LPSTARTUPINFOA si,
                                     LPPROCESS_INFORMATION pi)
{
    (void)tok;                                       /* build 131: see kex_CreateProcessAsUserW */
    return kex_CreateProcessA(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
}
