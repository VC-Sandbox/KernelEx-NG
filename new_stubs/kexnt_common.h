/* kexnt_common.h - shared definitions for KernelEx-NG Phase 1 stubs (MinGW i686, Win98 SE target). */
#ifndef KEXNT_COMMON_H
#define KEXNT_COMMON_H
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00   /* we export NT10 prototypes; we never call them on the host */

#endif
#include <windows.h>

typedef LONG NTSTATUS;
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_NOT_IMPLEMENTED       ((NTSTATUS)0xC0000002L)
#define STATUS_INVALID_INFO_CLASS    ((NTSTATUS)0xC0000003L)
#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)
#define STATUS_ACCESS_VIOLATION_K    ((NTSTATUS)0xC0000005L)
#define STATUS_INVALID_HANDLE_K      ((NTSTATUS)0xC0000008L)
#undef  STATUS_INVALID_PARAMETER   /* winnt.h defines it as DWORD; we want signed NTSTATUS */
#define STATUS_INVALID_PARAMETER     ((NTSTATUS)0xC000000DL)
#define STATUS_NO_MEMORY_K           ((NTSTATUS)0xC0000017L)
#define STATUS_BUFFER_TOO_SMALL      ((NTSTATUS)0xC0000023L)
#define STATUS_NOT_SUPPORTED         ((NTSTATUS)0xC00000BBL)
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

#define KEXAPI WINAPI
#define KEX_EXPORT __declspec(dllexport)

/* Running on the Win9x kernel? NOT GetVersion(): KernelEx version profiles (kexver) make it report NT,
 * which silently disabled every 9x code path in Windows-10-profile processes (GetThreadId returned 0).
 * Win9x maps KERNEL32 in the shared arena (0xBFF70000 on 98 SE); NT never loads it at or above 2 GB. */
static __inline BOOL kex_is_win9x(void) { return (ULONG_PTR)GetModuleHandleA("KERNEL32.DLL") >= 0x80000000UL; }

/* Resolve an export from the REAL system DLL (bypassing our own overrides). */
static __inline FARPROC kex_sysproc(const char *dll, const char *name)
{
    HMODULE h = GetModuleHandleA(dll);
    if (!h) h = LoadLibraryA(dll);
    return h ? GetProcAddress(h, name) : NULL;
}

/* Spin lock acquire for Win9x (2026-11-10 build 21). Win98 runs one CPU, and Sleep(0) only yields to threads of
 * the same or higher priority: a high-priority thread spinning with Sleep(0) on a lock held by a preempted
 * lower-priority thread never lets it run (priority inversion -> the process crawls or hangs). After a few
 * Sleep(0) rounds (200), Sleep(1) lets every ready thread run. */
static __inline void kex_spin_acquire(volatile LONG *l)
{
    int n = 0;
    while (InterlockedExchange((LONG *)l, 1)) { if (++n < 200) Sleep(0); else Sleep(1); }
}
/* Build 131: the same, but gives up after about ms milliseconds (returns FALSE). For locks of the diagnostic paths
 * (KEXTRACE, the VxD-call trace): their owner can be a thread that Windows 98 terminated in ExitProcess, or one that the
 * profiler's sampler or a debugger suspended, while it held the lock. A bare spin then waited forever - the full kextest
 * froze Windows at [DirectWrite], and every process that loaded DWrite.dll could not finish exiting (Trace=1 only). */
static __inline BOOL kex_spin_try(volatile LONG *l, DWORD ms)
{
    int n = 0; DWORD t0 = GetTickCount();
    while (InterlockedExchange((LONG *)l, 1)) {
        if (++n < 200) Sleep(0); else Sleep(1);
        if (n >= 200 && GetTickCount() - t0 >= ms) return FALSE;
    }
    return TRUE;
}
#endif
