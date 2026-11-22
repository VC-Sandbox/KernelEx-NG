/* kernel32_ext.h - NT6+/NT10 kernel32 APIs emulated on Windows 98 SE. */
#ifndef KERNEL32_EXT_H
#define KERNEL32_EXT_H
#include "kexnt_common.h"

ULONGLONG KEXAPI kex_GetTickCount64(void);
BOOL      KEXAPI kex_IsWow64Process(HANDLE hProcess, PBOOL Wow64Process);
BOOL      KEXAPI kex_IsWow64Process2(HANDLE hProcess, USHORT *pProcessMachine, USHORT *pNativeMachine);
BOOL      KEXAPI kex_InitializeCriticalSectionEx(LPCRITICAL_SECTION cs, DWORD spin, DWORD flags);
BOOL      KEXAPI kex_InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION cs, DWORD spin);
DWORD     KEXAPI kex_SetCriticalSectionSpinCount(LPCRITICAL_SECTION cs, DWORD spin);
BOOL      KEXAPI kex_SetThreadStackGuarantee(PULONG StackSizeInBytes);
SIZE_T    KEXAPI kex_GetLargePageMinimum(void);
VOID      KEXAPI kex_FlushProcessWriteBuffers(void);
VOID      KEXAPI kex_GetSystemTimePreciseAsFileTime(LPFILETIME ft);
BOOL      KEXAPI kex_QueryUnbiasedInterruptTime(PULONGLONG UnbiasedTime);
BOOL      kex_k32ext_init(void);   /* call from DLL_PROCESS_ATTACH */
#endif
