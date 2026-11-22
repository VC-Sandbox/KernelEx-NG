/* sysinfo_ext.h - processor topology, psapi K32*, process/thread info for Windows 98 SE.
 * Exported functions are bound by name in kexnt.def; only cross-module helpers are declared here. */
#ifndef SYSINFO_EXT_H
#define SYSINFO_EXT_H
#include "kernel32_ext.h"
#include <psapi.h>

DWORD kex_GetDefaultDllDirectories(void);   /* for the Phase 2 loader */
PVOID kex_ProcThreadAttributeFind(LPPROC_THREAD_ATTRIBUTE_LIST list, DWORD_PTR attr, SIZE_T *size);
#endif
