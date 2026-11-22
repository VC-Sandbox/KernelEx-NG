/* fls_ext.h - Fiber Local Storage emulation for Windows 98 SE. */
#ifndef FLS_EXT_H
#define FLS_EXT_H
#include "kexnt_common.h"

DWORD KEXAPI kex_FlsAlloc(PFLS_CALLBACK_FUNCTION cb);
BOOL  KEXAPI kex_FlsFree(DWORD i);
PVOID KEXAPI kex_FlsGetValue(DWORD i);
BOOL  KEXAPI kex_FlsSetValue(DWORD i, PVOID v);

BOOL kex_fls_init(void);
void kex_fls_thread_detach(void);
#endif
