/* ntdll_ext.h - NT-level emulation for Windows 98 SE (KernelEx-NG Phase 1). */
#ifndef NTDLL_EXT_H
#define NTDLL_EXT_H
#include "kexnt_common.h"

NTSTATUS KEXAPI kex_NtQuerySystemInformation(ULONG cls, PVOID buf, ULONG len, PULONG retlen);
NTSTATUS KEXAPI kex_NtSetInformationThread(HANDLE h, ULONG cls, PVOID info, ULONG len);
NTSTATUS KEXAPI kex_NtCreateThreadEx(PHANDLE out, ACCESS_MASK access, PVOID objattr, HANDLE process,
                                     PVOID start, PVOID arg, ULONG flags, SIZE_T zerobits,
                                     SIZE_T stack, SIZE_T maxstack, PVOID attrlist);
LPVOID KEXAPI kex_ConvertThreadToFiber(LPVOID param);
LPVOID KEXAPI kex_ConvertThreadToFiberEx(LPVOID param, DWORD flags);
BOOL   KEXAPI kex_ConvertFiberToThread(void);
LPVOID KEXAPI kex_CreateFiber(SIZE_T stack, LPFIBER_START_ROUTINE fn, LPVOID param);
LPVOID KEXAPI kex_CreateFiberEx(SIZE_T commit, SIZE_T reserve, DWORD flags, LPFIBER_START_ROUTINE fn, LPVOID param);
VOID   KEXAPI kex_SwitchToFiber(LPVOID fiber);
VOID   KEXAPI kex_DeleteFiber(LPVOID fiber);
BOOL   KEXAPI kex_IsThreadAFiber(void);
LPVOID KEXAPI kex_GetCurrentFiber(void);
VOID   KEXAPI kex_RtlCaptureContext(PCONTEXT ctx);
PVOID  KEXAPI kex_RtlLookupFunctionEntry(ULONG64 pc, PULONG64 imagebase, PVOID history);
BOOL   kex_ntext_init(void);
#endif
