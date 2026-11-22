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
static T_TH c_p1, c_pn, c_p1w, c_pnw, c_m1, c_mn, c_m1w, c_mnw, c_t1, c_tn;
BOOL KEXAPI kex_Process32First(HANDLE s, LPVOID e)  { return th_call("Process32First", &c_p1, s, e, 0); }
BOOL KEXAPI kex_Process32Next(HANDLE s, LPVOID e)   { return th_call("Process32Next", &c_pn, s, e, 0); }
BOOL KEXAPI kex_Process32FirstW(HANDLE s, LPVOID e) { return th_call("Process32FirstW", &c_p1w, s, e, 0); }
BOOL KEXAPI kex_Process32NextW(HANDLE s, LPVOID e)  { return th_call("Process32NextW", &c_pnw, s, e, 0); }
BOOL KEXAPI kex_Module32First(HANDLE s, LPVOID e)   { return th_call("Module32First", &c_m1, s, e, 1); }
BOOL KEXAPI kex_Module32Next(HANDLE s, LPVOID e)    { return th_call("Module32Next", &c_mn, s, e, 1); }
BOOL KEXAPI kex_Module32FirstW(HANDLE s, LPVOID e)  { return th_call("Module32FirstW", &c_m1w, s, e, 1); }
BOOL KEXAPI kex_Module32NextW(HANDLE s, LPVOID e)   { return th_call("Module32NextW", &c_mnw, s, e, 1); }
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
