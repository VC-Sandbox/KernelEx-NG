/*
 * pid_ext.c - KernelEx-NG build 131: process ids as NT shows them.
 *
 * A Windows 98 process id is an obfuscated pointer (process database ^ a per-boot value) and always has its top bit
 * set (0xFFFxxxxx). NT's never do: they are small positive numbers, and programs rely on it. Firefox 115 passes its
 * process id to every child process on the command line as an unsigned number and the child reads it back with
 * strtol (toolkit/xre/nsEmbedFunctions.cpp) - 4294401411 saturated to 0x7FFFFFFF, the child's endpoint for the parent
 * carried that id, and the parent's Endpoint::Bind release-asserted (mMyPid == GetCurrentProcId()).
 *
 * To a modern program (the gates send Windows 98 programs to the previous implementation) kexnt shows every process id
 * with its top bit cleared, everywhere a process id comes out (kex_pid_nt), and turns any id a program hands in back
 * (kex_pid_real: the top bit set again - an id already in Windows 98's form passes unchanged). Inside kexnt, ids stay
 * real. 0 stays 0.
 */
#include "kexnt_common.h"
#include <tlhelp32.h>

FARPROC kex_prev_impl(const char *dll, const char *name);
DWORD kex_process_id(HANDLE process);                                    /* chrome_ext.c */

DWORD kex_pid_nt(DWORD real) { return real & 0x7FFFFFFFUL; }
DWORD kex_pid_real(DWORD id) { return (id && id != 0xFFFFFFFFUL) ? (id | 0x80000000UL) : id; }

#define PREV(T, v, name) static T v; if (!v) v = (T)(void *)kex_prev_impl("KERNEL32.DLL", name)

DWORD KEXAPI kex_GetCurrentProcessId(void) { return kex_pid_nt(GetCurrentProcessId()); }
DWORD KEXAPI kex_GetProcessId(HANDLE h)
{
    DWORD r = kex_process_id(h);
    if (!r) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
    return kex_pid_nt(r);
}
HANDLE KEXAPI kex_CreateToolhelp32Snapshot(DWORD flags, DWORD pid)
{
    typedef HANDLE (WINAPI *T)(DWORD, DWORD); PREV(T, p, "CreateToolhelp32Snapshot");
    return p ? p(flags, kex_pid_real(pid)) : INVALID_HANDLE_VALUE;
}
/* PROCESSENTRY32(W): +8 th32ProcessID, +24 th32ParentProcessID; MODULEENTRY32(W): +8 th32ProcessID;
 * THREADENTRY32: +12 th32OwnerProcessID */
#define UNMAPAT(e, off) (*(DWORD *)((BYTE *)(e) + (off)) = kex_pid_real(*(DWORD *)((BYTE *)(e) + (off))))
#define MAPAT(e, off) (*(DWORD *)((BYTE *)(e) + (off)) = kex_pid_nt(*(DWORD *)((BYTE *)(e) + (off))))
typedef BOOL (WINAPI *T_TH)(HANDLE, LPVOID);
static BOOL th_call(const char *name, T_TH *cache, HANDLE s, LPVOID e, int kind)
{
    BOOL r;
    if (!*cache) *cache = (T_TH)(void *)kex_prev_impl("KERNEL32.DLL", name);
    if (!*cache) { SetLastError(ERROR_PROC_NOT_FOUND); return FALSE; }
    if (e && !IsBadWritePtr(e, 28)) {   /* a ...Next call: Windows 98 finds its place from the ids in the entry - real ones again */
        if (kind == 0) { UNMAPAT(e, 8); UNMAPAT(e, 24); } else if (kind == 1) UNMAPAT(e, 8); else UNMAPAT(e, 12);
    }
    r = (*cache)(s, e);
    if (r && e) { if (kind == 0) { MAPAT(e, 8); MAPAT(e, 24); } else if (kind == 1) MAPAT(e, 8); else MAPAT(e, 12); }
    return r;
}
static T_TH c_p1, c_pn, c_p1w, c_pnw, c_mn, c_mnw, c_t1, c_tn;
BOOL KEXAPI kex_Process32First(HANDLE s, LPVOID e)  { return th_call("Process32First", &c_p1, s, e, 0); }
BOOL KEXAPI kex_Process32Next(HANDLE s, LPVOID e)   { return th_call("Process32Next", &c_pn, s, e, 0); }
BOOL KEXAPI kex_Process32FirstW(HANDLE s, LPVOID e) { return th_call("Process32FirstW", &c_p1w, s, e, 0); }
BOOL KEXAPI kex_Process32NextW(HANDLE s, LPVOID e)  { return th_call("Process32NextW", &c_pnw, s, e, 0); }
/* build 132: the EXE first in a module list, as on NT. NT's loader list starts with the program's own image, and
 * programs take the first MODULEENTRY32 as "the process's EXE". Windows 98 lists modules in another order (PMODS on the
 * .NET 3.5 setup's bootstrapper: OLE32.DLL first, DOTNETFX35SETUP.EXE second). The .NET 3.5 setup's component
 * installer (gencomp.dll: Process32FirstW for its parent, then Module32FirstW) took the folder of that first module as
 * its package folder: "Cannot access file: C:\WINDOWS\SYSTEM\tools\clwireg.exe", then tried to download every
 * component. Windows 98's Module32Next finds its place from the entry passed in, so the order cannot be changed call by
 * call: Module32First reads the whole list once (Windows 98's own functions), moves the module whose path is the
 * process's EXE path to the front, and First/Next hand out that list for this snapshot handle. */
#define NSNAP 8
typedef struct { HANDLE snap; MODULEENTRY32 *m; int n, pos; } MSNAP;
static MSNAP g_ms[NSNAP]; static volatile LONG g_ms_lock; static int g_ms_next;
static BOOL exe_path(DWORD pid, char *out)
{
    typedef HANDLE (WINAPI *T_CS)(DWORD, DWORD); typedef BOOL (WINAPI *T_P)(HANDLE, LPPROCESSENTRY32);
    PREV(T_CS, cs, "CreateToolhelp32Snapshot"); PREV(T_P, p1, "Process32First"); PREV(T_P, pn, "Process32Next");
    PROCESSENTRY32 pe; HANDLE h; BOOL ok = FALSE, r;
    if (!cs || !p1 || !pn || (h = cs(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE) return FALSE;
    pe.dwSize = sizeof(pe);
    for (r = p1(h, &pe); r; r = pn(h, &pe)) if (pe.th32ProcessID == pid) { lstrcpynA(out, pe.szExeFile, MAX_PATH); ok = TRUE; break; }
    CloseHandle(h);
    return ok;
}
static MSNAP *ms_build(HANDLE s)
{
    typedef BOOL (WINAPI *T_M)(HANDLE, LPMODULEENTRY32); PREV(T_M, m1, "Module32First"); PREV(T_M, mn, "Module32Next");
    MODULEENTRY32 e, *list = NULL, t; int n = 0, cap = 0, i; char exe[MAX_PATH]; BOOL r; MSNAP *ms;
    if (!m1 || !mn) return NULL;
    e.dwSize = sizeof(e);
    for (r = m1(s, &e); r; r = mn(s, &e)) {
        if (n == cap) {
            MODULEENTRY32 *nl = (MODULEENTRY32 *)HeapAlloc(GetProcessHeap(), 0, (cap ? cap * 2 : 64) * sizeof(*nl));
            if (!nl) break;
            if (list) { memcpy(nl, list, n * sizeof(*nl)); HeapFree(GetProcessHeap(), 0, list); }
            list = nl; cap = cap ? cap * 2 : 64;
        }
        list[n++] = e;
    }
    if (!n) { if (list) HeapFree(GetProcessHeap(), 0, list); return NULL; }
    if (exe_path(list[0].th32ProcessID, exe))
        for (i = 1; i < n; i++)
            if (!lstrcmpiA(list[i].szExePath, exe)) { t = list[i]; memmove(list + 1, list, i * sizeof(*list)); list[0] = t; break; }
    kex_spin_acquire(&g_ms_lock);
    for (i = 0; i < NSNAP; i++) if (g_ms[i].snap == s) break;
    if (i == NSNAP) { i = g_ms_next; g_ms_next = (g_ms_next + 1) % NSNAP; }
    ms = &g_ms[i];
    if (ms->m) HeapFree(GetProcessHeap(), 0, ms->m);
    ms->snap = s; ms->m = list; ms->n = n; ms->pos = 0;
    InterlockedExchange(&g_ms_lock, 0);
    return ms;
}
/* entry k of this snapshot's list into e (A or W); FALSE + ERROR_NO_MORE_FILES at the end */
static BOOL ms_get(HANDLE s, LPVOID e, int wide, int first)
{
    MSNAP *ms = NULL; MODULEENTRY32 m; int i, k;
    if (!e || IsBadWritePtr(e, wide ? sizeof(MODULEENTRY32W) : sizeof(MODULEENTRY32))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (first) ms = ms_build(s);
    else { kex_spin_acquire(&g_ms_lock); for (i = 0; i < NSNAP; i++) if (g_ms[i].snap == s && g_ms[i].m) { ms = &g_ms[i]; break; } InterlockedExchange(&g_ms_lock, 0); }
    if (!ms) {                                     /* no list (empty snapshot, or Next without First): Windows 98's answer */
        if (first) { SetLastError(ERROR_NO_MORE_FILES); return FALSE; }
        return wide ? th_call("Module32NextW", &c_mnw, s, e, 1) : th_call("Module32Next", &c_mn, s, e, 1);
    }
    k = first ? 0 : ms->pos + 1;
    if (k >= ms->n) { SetLastError(ERROR_NO_MORE_FILES); return FALSE; }
    ms->pos = k; m = ms->m[k];
    m.th32ProcessID = kex_pid_nt(m.th32ProcessID);
    if (!wide) { DWORD sz = ((MODULEENTRY32 *)e)->dwSize; m.dwSize = sz; memcpy(e, &m, sizeof(m)); }
    else {
        MODULEENTRY32W *w = (MODULEENTRY32W *)e;
        w->th32ModuleID = m.th32ModuleID; w->th32ProcessID = m.th32ProcessID; w->GlblcntUsage = m.GlblcntUsage;
        w->ProccntUsage = m.ProccntUsage; w->modBaseAddr = m.modBaseAddr; w->modBaseSize = m.modBaseSize; w->hModule = m.hModule;
        if (!MultiByteToWideChar(CP_ACP, 0, m.szModule, -1, w->szModule, MAX_MODULE_NAME32 + 1)) w->szModule[0] = 0;
        if (!MultiByteToWideChar(CP_ACP, 0, m.szExePath, -1, w->szExePath, MAX_PATH)) w->szExePath[0] = 0;
    }
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}
BOOL KEXAPI kex_Module32First(HANDLE s, LPVOID e)   { return ms_get(s, e, 0, 1); }
BOOL KEXAPI kex_Module32Next(HANDLE s, LPVOID e)    { return ms_get(s, e, 0, 0); }
BOOL KEXAPI kex_Module32FirstW(HANDLE s, LPVOID e)  { return ms_get(s, e, 1, 1); }
BOOL KEXAPI kex_Module32NextW(HANDLE s, LPVOID e)   { return ms_get(s, e, 1, 0); }
BOOL KEXAPI kex_Thread32First(HANDLE s, LPVOID e)   { return th_call("Thread32First", &c_t1, s, e, 2); }
BOOL KEXAPI kex_Thread32Next(HANDLE s, LPVOID e)    { return th_call("Thread32Next", &c_tn, s, e, 2); }
BOOL KEXAPI kex_ProcessIdToSessionId(DWORD pid, DWORD *sid)
{
    typedef BOOL (WINAPI *T)(DWORD, DWORD *); PREV(T, p, "ProcessIdToSessionId");
    if (p) return p(kex_pid_real(pid), sid);
    if (!sid) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    { HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, kex_pid_real(pid));
      if (!h) return FALSE;
      CloseHandle(h); *sid = 0; return TRUE; }                           /* one session on 98 */
}
BOOL KEXAPI kex_DebugActiveProcess(DWORD pid)
{
    typedef BOOL (WINAPI *T)(DWORD); PREV(T, p, "DebugActiveProcess");
    return p ? p(kex_pid_real(pid)) : FALSE;
}
BOOL KEXAPI kex_DebugActiveProcessStop(DWORD pid)
{
    typedef BOOL (WINAPI *T)(DWORD); PREV(T, p, "DebugActiveProcessStop");
    if (!p) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return p(kex_pid_real(pid));
}
