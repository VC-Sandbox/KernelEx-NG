/*
 * ntcs_ext.c - critical sections with the NT layout for .NET programs (build 132).
 *
 * The .NET 4 runtime does not only call EnterCriticalSection: before trying a lock it reads the structure itself.
 * clr.dll CrstBase::Enter (symbols: public clr.pdb, OMAP-mapped):
 *     cmp dword [ebx+4], -1      ; RTL_CRITICAL_SECTION.LockCount - NT: -1 = free
 *     jne spin                   ; held -> spin with pause, __SwitchToThread(0,0), 10 rounds, then block
 *     call UnsafeEETryEnterCriticalSection   (TryEnterCriticalSection)
 * A Windows 98 critical section keeps a pointer to its kernel object at offset 4 - never -1 - so every lock
 * acquisition in the runtime spun its whole budget before blocking: .NET programs ran, but took minutes to start
 * (measured: MIN.EXE about 2 minutes; KEXHANG thread dumps: main thread always in CrstBase::Enter ->
 * __SwitchToThread, the other runtime threads idle).
 *
 * In a .NET process (gate_ext.c) InitializeCriticalSection(*) here builds an NT-layout critical section with the
 * documented Windows XP algorithm: DebugInfo, LockCount (-1 free; +1 per owner/waiter), RecursionCount,
 * OwningThread, LockSemaphore (auto-reset event, created at initialization), SpinCount. Leave hands the lock to one
 * waiter (SetEvent) as XP does. Such sections carry a marker in DebugInfo; Enter/TryEnter/Leave/Delete use the NT
 * path only for sections with that marker, and pass every other one (Windows 98 layout: made by a system DLL or
 * outside a .NET process) to the previous implementation unchanged. Other programs never get the NT layout.
 */
#include "kexnt_common.h"

FARPROC kex_prev_impl(const char *dll, const char *name);   /* gdiguard_ext.c */
int kex_gate_is_clr(void);                                    /* gate_ext.c */

typedef struct {
    PVOID DebugInfo; volatile LONG LockCount; LONG RecursionCount; DWORD OwningThread; HANDLE LockSemaphore; ULONG_PTR SpinCount;
} NTCS;
static BYTE g_ntcs_marker[32];                                /* DebugInfo of every NT-layout section */
#define IS_NT(c) ((c) && ((NTCS *)(c))->DebugInfo == (PVOID)g_ntcs_marker)

typedef void (WINAPI *T_CS)(LPCRITICAL_SECTION);
typedef BOOL (WINAPI *T_TCS)(LPCRITICAL_SECTION);
static void prev_void(const char *name, LPCRITICAL_SECTION cs)
{
    T_CS f = (T_CS)(void *)kex_prev_impl("KERNEL32.DLL", name);
    if (f) f(cs);
}

VOID KEXAPI kex_InitializeCriticalSection(LPCRITICAL_SECTION cs)
{
    NTCS *c = (NTCS *)cs;
    if (!kex_gate_is_clr()) { prev_void("InitializeCriticalSection", cs); return; }
    c->LockCount = -1; c->RecursionCount = 0; c->OwningThread = 0; c->SpinCount = 0;
    c->LockSemaphore = CreateEventA(NULL, FALSE, FALSE, NULL);
    c->DebugInfo = (PVOID)g_ntcs_marker;
}

VOID KEXAPI kex_EnterCriticalSection(LPCRITICAL_SECTION cs)
{
    NTCS *c = (NTCS *)cs; DWORD tid;
    if (!IS_NT(c)) { prev_void("EnterCriticalSection", cs); return; }
    tid = GetCurrentThreadId();
    if (InterlockedIncrement(&c->LockCount) == 0) { c->OwningThread = tid; c->RecursionCount = 1; return; }
    if (c->OwningThread == tid) { c->RecursionCount++; return; }
    WaitForSingleObject(c->LockSemaphore, INFINITE);          /* Leave handed the lock to us */
    c->OwningThread = tid; c->RecursionCount = 1;
}

BOOL KEXAPI kex_TryEnterCriticalSection(LPCRITICAL_SECTION cs)
{
    NTCS *c = (NTCS *)cs; DWORD tid;
    if (!IS_NT(c)) { T_TCS f = (T_TCS)(void *)kex_prev_impl("KERNEL32.DLL", "TryEnterCriticalSection"); return f ? f(cs) : FALSE; }
    tid = GetCurrentThreadId();
    if (InterlockedCompareExchange(&c->LockCount, 0, -1) == -1) { c->OwningThread = tid; c->RecursionCount = 1; return TRUE; }
    if (c->OwningThread == tid) { InterlockedIncrement(&c->LockCount); c->RecursionCount++; return TRUE; }
    return FALSE;
}

VOID KEXAPI kex_LeaveCriticalSection(LPCRITICAL_SECTION cs)
{
    NTCS *c = (NTCS *)cs;
    if (!IS_NT(c)) { prev_void("LeaveCriticalSection", cs); return; }
    if (--c->RecursionCount > 0) { InterlockedDecrement(&c->LockCount); return; }
    c->OwningThread = 0;
    if (InterlockedDecrement(&c->LockCount) >= 0) SetEvent(c->LockSemaphore);   /* a waiter: hand over */
}

VOID KEXAPI kex_DeleteCriticalSection(LPCRITICAL_SECTION cs)
{
    NTCS *c = (NTCS *)cs;
    if (!IS_NT(c)) { prev_void("DeleteCriticalSection", cs); return; }
    if (c->LockSemaphore) CloseHandle(c->LockSemaphore);
    c->LockSemaphore = NULL; c->DebugInfo = NULL; c->LockCount = -1;
}
