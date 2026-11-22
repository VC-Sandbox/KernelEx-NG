/* sync_ext.h - SRW locks, condition variables, InitOnce, WaitOnAddress for Windows 98 SE. */
#ifndef SYNC_EXT_H
#define SYNC_EXT_H
#include "kexnt_common.h"

BOOL    KEXAPI kex_WaitOnAddress(volatile VOID *Address, PVOID CompareAddress, SIZE_T AddressSize, DWORD dwMilliseconds);
VOID    KEXAPI kex_WakeByAddressSingle(PVOID Address);
VOID    KEXAPI kex_WakeByAddressAll(PVOID Address);

VOID    KEXAPI kex_InitializeSRWLock(PSRWLOCK l);
VOID    KEXAPI kex_AcquireSRWLockExclusive(PSRWLOCK l);
VOID    KEXAPI kex_AcquireSRWLockShared(PSRWLOCK l);
VOID    KEXAPI kex_ReleaseSRWLockExclusive(PSRWLOCK l);
VOID    KEXAPI kex_ReleaseSRWLockShared(PSRWLOCK l);
BOOLEAN KEXAPI kex_TryAcquireSRWLockExclusive(PSRWLOCK l);
BOOLEAN KEXAPI kex_TryAcquireSRWLockShared(PSRWLOCK l);

VOID    KEXAPI kex_InitializeConditionVariable(PCONDITION_VARIABLE c);
BOOL    KEXAPI kex_SleepConditionVariableSRW(PCONDITION_VARIABLE c, PSRWLOCK l, DWORD ms, ULONG flags);
BOOL    KEXAPI kex_SleepConditionVariableCS(PCONDITION_VARIABLE c, PCRITICAL_SECTION cs, DWORD ms);
VOID    KEXAPI kex_WakeConditionVariable(PCONDITION_VARIABLE c);
VOID    KEXAPI kex_WakeAllConditionVariable(PCONDITION_VARIABLE c);

VOID    KEXAPI kex_InitOnceInitialize(PINIT_ONCE o);
BOOL    KEXAPI kex_InitOnceBeginInitialize(LPINIT_ONCE o, DWORD flags, PBOOL pending, LPVOID *ctx);
BOOL    KEXAPI kex_InitOnceComplete(LPINIT_ONCE o, DWORD flags, LPVOID ctx);
BOOL    KEXAPI kex_InitOnceExecuteOnce(PINIT_ONCE o, PINIT_ONCE_FN fn, PVOID param, LPVOID *ctx);

BOOL kex_sync_init(void);
void kex_sync_thread_detach(void);
#endif
