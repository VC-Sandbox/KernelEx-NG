/* ntldr_ext.c - NTDLL loader / memory / section / file functions Windows 98's NTDLL lacks (build 131).
 *
 * Found with GPA.EXE over Supermium 150's own XP wrappers (pwrp_k32.dll, p_ntd.dll imported statically by its
 * chrome.exe / chrome_elf.dll): in Windows XP mode every import was there except these nine NTDLL functions and two
 * PSAPI ones, and Windows 98 answered CreateProcess with error 31 (a static import missing).
 * Each one does what NT documents, on top of the Win32 calls Windows 98 has (or kexnt's own versions of them).
 */
#include "kexnt_common.h"

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } KUSTR;
typedef struct { USHORT Length, MaximumLength; PCHAR Buffer; } KASTR;
typedef struct { union { NTSTATUS Status; PVOID Pointer; }; ULONG_PTR Information; } KIOSB2;

#define STATUS_DLL_NOT_FOUND_K        ((NTSTATUS)0xC0000135L)
#define STATUS_ENTRYPOINT_NOT_FOUND_K ((NTSTATUS)0xC0000139L)
#define STATUS_ORDINAL_NOT_FOUND_K    ((NTSTATUS)0xC0000138L)
#define STATUS_CONFLICTING_ADDRESSES_K ((NTSTATUS)0xC0000018L)
#define STATUS_SECTION_NOT_IMAGE_K    ((NTSTATUS)0xC0000049L)
#define STATUS_NOT_MAPPED_VIEW_K      ((NTSTATUS)0xC0000019L)

void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
HMODULE KEXAPI kex_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags);
LPVOID KEXAPI kex_VirtualAlloc(LPVOID a, SIZE_T n, DWORD type, DWORD prot);
BOOL KEXAPI kex_VirtualFree(LPVOID a, SIZE_T n, DWORD type);
LPVOID KEXAPI kex_MapViewOfFileEx(HANDLE h, DWORD access, DWORD hi, DWORD lo, SIZE_T n, LPVOID base);
BOOL KEXAPI kex_UnmapViewOfFile(LPCVOID a);
BOOL KEXAPI kex_GetFileInformationByHandleEx(HANDLE h, int cls, LPVOID buf, DWORD size);
FARPROC knowndll_real_gpa(void);
FARPROC WINAPI knowndll_gpa_extra(HMODULE h, LPCSTR name);

static NTSTATUS st_from_win32(DWORD e)
{
    switch (e) {
    case ERROR_NOT_ENOUGH_MEMORY: case ERROR_OUTOFMEMORY: return STATUS_NO_MEMORY_K;
    case ERROR_INVALID_HANDLE: return STATUS_INVALID_HANDLE_K;
    case ERROR_INVALID_ADDRESS: return STATUS_CONFLICTING_ADDRESSES_K;
    case ERROR_MOD_NOT_FOUND: case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND: return STATUS_DLL_NOT_FOUND_K;
    case ERROR_PROC_NOT_FOUND: return STATUS_ENTRYPOINT_NOT_FOUND_K;
    case ERROR_INVALID_PARAMETER: return STATUS_INVALID_PARAMETER;
    case ERROR_ACCESS_DENIED: return (NTSTATUS)0xC0000022L;
    default: return (NTSTATUS)0xC0000001L;          /* STATUS_UNSUCCESSFUL */
    }
}

/* ---- LdrLoadDll / LdrGetProcedureAddress -------------------------------------------------------------- */
NTSTATUS KEXAPI kex_LdrLoadDll(PCWSTR path, PULONG chars, const KUSTR *name, PVOID *base)
{
    WCHAR buf[MAX_PATH + 1]; int n; HMODULE h;
    if (!name || !name->Buffer || !base) return STATUS_INVALID_PARAMETER;
    n = name->Length / 2; if (n > MAX_PATH) return (NTSTATUS)0xC0000106L;      /* STATUS_NAME_TOO_LONG */
    memcpy(buf, name->Buffer, n * 2); buf[n] = 0;
    h = kex_LoadLibraryExW(buf, NULL, (chars && (*chars & 2)) ? LOAD_LIBRARY_AS_DATAFILE : 0);   /* 2 = IMAGE_FILE_EXECUTABLE_IMAGE: no */
    if (!h) { *base = NULL; return st_from_win32(GetLastError()); }
    *base = h;
    return STATUS_SUCCESS;
}

/* GetProcAddress as THIS PROCESS's KernelEx configuration answers it. KernelEx picks the configuration from the
 * return address GetProcAddress sees (core/thunks.cpp ExportFromNameDynamic_thunk). kexnt itself lives outside
 * SYSTEM and would get Windows 98's own exports; a module in SYSTEM gets the process's configuration (build 126,
 * RtlGetVersion). So the call is made with its return address on a RET byte of a SYSTEM module of ours (the
 * API-set shell for the loader), which returns at once to us: nothing is changed in any module. */
static BYTE *g_sys_ret;
static BYTE *sys_ret_byte(void)
{
    BYTE *b; IMAGE_NT_HEADERS32 *nt; IMAGE_SECTION_HEADER *s; int i; DWORD k;
    if (g_sys_ret) return g_sys_ret;
    b = (BYTE *)LoadLibraryA("api-ms-win-core-libraryloader-l1-1-0.dll");
    if (!b) return NULL;
    nt = (IMAGE_NT_HEADERS32 *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    s = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, s++)
        if (s->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            for (k = 0; k < s->Misc.VirtualSize; k++)
                if (b[s->VirtualAddress + k] == 0xC3) { g_sys_ret = b + s->VirtualAddress + k; return g_sys_ret; }
    return NULL;
}
BYTE *sys_ret_byte_c(void);
FARPROC kex_gpa_as_process(HMODULE h, LPCSTR name);
__asm__(
    ".text\n"
    ".globl _kex_gpa_as_process\n"
    "_kex_gpa_as_process:\n"                 /* cdecl (h, name) */
    "    pushl %ebx\n"
    "    call _sys_ret_byte_c\n"
    "    movl %eax, %ebx\n"
    "    call _knowndll_real_gpa\n"
    "    testl %eax, %eax\n"
    "    jz 9f\n"
    "    testl %ebx, %ebx\n"
    "    jz 8f\n"
    "    pushl $1f\n"                        /* where the RET byte sends us */
    "    pushl 16(%esp)\n"                   /* name */
    "    pushl 16(%esp)\n"                   /* h */
    "    pushl %ebx\n"                       /* GetProcAddress returns onto the RET byte */
    "    jmp *%eax\n"
    "1:  popl %ebx\n"
    "    ret\n"
    "8:  pushl 12(%esp)\n"                   /* no shell: plain call (Windows 98's answer) */
    "    pushl 12(%esp)\n"
    "    call *%eax\n"
    "9:  popl %ebx\n"
    "    ret\n"
);
BYTE *sys_ret_byte_c(void) { return sys_ret_byte(); }

NTSTATUS KEXAPI kex_LdrGetProcedureAddress(HMODULE h, const KASTR *name, ULONG ord, PVOID *addr)
{
    char nb[256]; LPCSTR q; FARPROC p;
    if (!addr) return STATUS_INVALID_PARAMETER;
    *addr = NULL;
    if (name && name->Buffer) {
        int n = name->Length < sizeof(nb) - 1 ? name->Length : sizeof(nb) - 1;
        memcpy(nb, name->Buffer, n); nb[n] = 0; q = nb;
        if ((p = knowndll_gpa_extra(h, q)) != NULL) { *addr = (PVOID)p; return STATUS_SUCCESS; }
    } else q = (LPCSTR)(ULONG_PTR)(ord & 0xFFFF);
    p = kex_gpa_as_process(h, q);
    if (!p) return (name && name->Buffer) ? STATUS_ENTRYPOINT_NOT_FOUND_K : STATUS_ORDINAL_NOT_FOUND_K;
    *addr = (PVOID)p;
    return STATUS_SUCCESS;
}

/* ---- memory ------------------------------------------------------------------------------------------- */
NTSTATUS KEXAPI kex_NtAllocateVirtualMemory(HANDLE proc, PVOID *base, ULONG_PTR zero, PSIZE_T size, ULONG type, ULONG prot)
{
    LPVOID r;
    if (!base || !size) return STATUS_INVALID_PARAMETER;
    if (proc != GetCurrentProcess() && proc != (HANDLE)(LONG_PTR)-1) return STATUS_NOT_IMPLEMENTED;  /* 98: no VirtualAllocEx */
    r = kex_VirtualAlloc(*base, *size, type, prot);
    if (!r) return st_from_win32(GetLastError());
    {   MEMORY_BASIC_INFORMATION m;     /* NT rounds the region out and reports it */
        if (!*base) *base = r;
        else *base = (PVOID)((ULONG_PTR)*base & ~0xFFFUL);
        if (VirtualQuery(r, &m, sizeof(m)) && (type & MEM_RESERVE)) *size = m.RegionSize;
        else *size = (*size + 0xFFF) & ~0xFFFUL; }
    return STATUS_SUCCESS;
}

/* ---- sections ----------------------------------------------------------------------------------------- */
NTSTATUS KEXAPI kex_NtMapViewOfSection(HANDLE sec, HANDLE proc, PVOID *base, ULONG_PTR zero, SIZE_T commit,
                                       PLARGE_INTEGER off, PSIZE_T vsize, ULONG inherit, ULONG type, ULONG prot)
{
    DWORD acc, lo = 0, hi = 0; LPVOID r; SIZE_T n;
    if (!base || !vsize) return STATUS_INVALID_PARAMETER;
    if (proc != GetCurrentProcess() && proc != (HANDLE)(LONG_PTR)-1) return STATUS_NOT_IMPLEMENTED;
    switch (prot & 0xFF) {
    case PAGE_READONLY: case PAGE_EXECUTE_READ: case PAGE_EXECUTE: acc = FILE_MAP_READ; break;
    case PAGE_WRITECOPY: case PAGE_EXECUTE_WRITECOPY: acc = FILE_MAP_COPY; break;
    default: acc = FILE_MAP_WRITE; break;
    }
    if (off) { lo = off->LowPart & ~0xFFFFUL; hi = (DWORD)off->HighPart; }   /* NT rounds the offset down to 64 KB */
    n = *vsize;
    if (off && n) n += off->LowPart & 0xFFFF;
    r = kex_MapViewOfFileEx(sec, acc, hi, lo, n, *base);
    if (!r) return st_from_win32(GetLastError());
    if (off) off->LowPart = lo;
    if (!n) {   MEMORY_BASIC_INFORMATION m; LPBYTE p = r; n = 0;     /* whole section: report the view's size */
        while (VirtualQuery(p + n, &m, sizeof(m)) && m.AllocationBase == (PVOID)(ULONG_PTR)((ULONG_PTR)r) && m.RegionSize) n += m.RegionSize;
        if (!n && VirtualQuery(r, &m, sizeof(m))) n = m.RegionSize; }
    *base = r; *vsize = (n + 0xFFF) & ~0xFFFUL;
    return STATUS_SUCCESS;
}
NTSTATUS KEXAPI kex_NtUnmapViewOfSection(HANDLE proc, PVOID base)
{
    if (proc != GetCurrentProcess() && proc != (HANDLE)(LONG_PTR)-1) return STATUS_NOT_IMPLEMENTED;
    return kex_UnmapViewOfFile(base) ? STATUS_SUCCESS : STATUS_NOT_MAPPED_VIEW_K;
}

/* ---- NtQueryInformationFile: the classes GetFileInformationByHandle can answer ------------------------- */
NTSTATUS KEXAPI kex_NtQueryInformationFile(HANDLE h, KIOSB2 *iosb, PVOID buf, ULONG len, ULONG cls)
{
    int wcls; ULONG need;
    if (!iosb || !buf) return STATUS_INVALID_PARAMETER;
    switch (cls) {
    case 4:  wcls = 0; need = 40; break;            /* FileBasicInformation (padded to 8) */
    case 5:  wcls = 1; need = 24; break;            /* FileStandardInformation */
    case 35: wcls = 9; need = 8;  break;            /* FileAttributeTagInformation */
    case 14: {                                      /* FilePositionInformation */
        LONG hi = 0; DWORD lo;
        if (len < 8) return STATUS_INFO_LENGTH_MISMATCH;
        lo = SetFilePointer(h, 0, &hi, FILE_CURRENT);
        if (lo == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) return st_from_win32(GetLastError());
        ((DWORD *)buf)[0] = lo; ((DWORD *)buf)[1] = (DWORD)hi;
        iosb->Status = STATUS_SUCCESS; iosb->Information = 8; return STATUS_SUCCESS;
    }
    case 16: if (len < 4) return STATUS_INFO_LENGTH_MISMATCH;   /* FileModeInformation: synchronous */
        *(DWORD *)buf = 0x20; iosb->Status = STATUS_SUCCESS; iosb->Information = 4; return STATUS_SUCCESS;
    case 9:  wcls = 2; need = 6; break;             /* FileNameInformation (pipes only, as GetFileInformationByHandleEx) */
    default: return STATUS_INVALID_INFO_CLASS;
    }
    if (len < need) return STATUS_INFO_LENGTH_MISMATCH;
    if (!kex_GetFileInformationByHandleEx(h, wcls, buf, len)) {
        DWORD e = GetLastError();
        return e == ERROR_NOT_SUPPORTED ? STATUS_NOT_SUPPORTED : st_from_win32(e);
    }
    iosb->Status = STATUS_SUCCESS;
    iosb->Information = cls == 9 ? 4 + ((DWORD *)buf)[0] : need;
    return STATUS_SUCCESS;
}

/* ---- Rtl helpers ------------------------------------------------------------------------------------------ */
VOID KEXAPI kex_RtlMoveMemory(PVOID d, const VOID *s, SIZE_T n) { memmove(d, s, n); }

PVOID KEXAPI kex_RtlPcToFileHeader(PVOID pc, PVOID *base)
{
    MEMORY_BASIC_INFORMATION m; BYTE *b;
    if (!base) return NULL;
    *base = NULL;
    if (!VirtualQuery(pc, &m, sizeof(m)) || m.State != MEM_COMMIT || !m.AllocationBase) return NULL;
    b = (BYTE *)m.AllocationBase;
    if (IsBadReadPtr(b, 0x40) || ((IMAGE_DOS_HEADER *)b)->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    if (IsBadReadPtr(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew, 4) || *(DWORD *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew) != IMAGE_NT_SIGNATURE) return NULL;
    *base = b;
    return b;
}

/* RtlGetCallersAddress: the return address of the function that called the caller, and that function's caller's.
 * NT walks the EBP chain the same way (x86). */
VOID KEXAPI kex_RtlGetCallersAddress(PVOID *callers, PVOID *callers_caller)
{
    DWORD *f = (DWORD *)__builtin_frame_address(0), *f1, *f2;
    PVOID a = NULL, b = NULL;
    f1 = (DWORD *)f[0];                                 /* frame of our caller */
    if (f1 > f && !IsBadReadPtr(f1, 8)) {
        a = (PVOID)f1[1];                               /* where our caller returns */
        f2 = (DWORD *)f1[0];
        if (f2 > f1 && !IsBadReadPtr(f2, 8)) b = (PVOID)f2[1];
    }
    if (callers) *callers = a;
    if (callers_caller) *callers_caller = b;
}

/* ---- more NTDLL names Supermium's pwrp_k32.dll looks up (strings in the DLL), build 131 ------------------ */
SIZE_T KEXAPI kex_RtlCompareMemory(const VOID *a, const VOID *b, SIZE_T n)
{
    const BYTE *p = a, *q = b; SIZE_T i = 0;
    while (i < n && p[i] == q[i]) i++;
    return i;                                              /* bytes that match, from the start */
}
VOID KEXAPI kex_RtlFillMemory(PVOID d, SIZE_T n, BYTE v) { memset(d, v, n); }
VOID KEXAPI kex_RtlZeroMemory(PVOID d, SIZE_T n) { memset(d, 0, n); }
/* RtlRaiseException(EXCEPTION_RECORD*): raise it as RaiseException would, with the record's parameters */
VOID KEXAPI kex_RtlRaiseException(PEXCEPTION_RECORD r)
{
    if (!r) return;
    RaiseException(r->ExceptionCode, r->ExceptionFlags & EXCEPTION_NONCONTINUABLE,
                   r->NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS ? EXCEPTION_MAXIMUM_PARAMETERS : r->NumberParameters,
                   r->ExceptionInformation);
}
/* VerSetConditionMask (NTDLL; KERNEL32 forwards to it on NT): 3 bits per type, type bit = 1 << (index) */
ULONGLONG KEXAPI kex_VerSetConditionMask(ULONGLONG mask, DWORD type, BYTE cond)
{
    int idx;
    if (!type) return mask;
    cond &= 7;
    if (type & VER_PRODUCT_TYPE) idx = 7; else if (type & VER_SUITENAME) idx = 6; else if (type & VER_PLATFORMID) idx = 3;
    else if (type & VER_BUILDNUMBER) idx = 2; else if (type & VER_MAJORVERSION) idx = 1; else if (type & VER_MINORVERSION) idx = 0;
    else if (type & VER_SERVICEPACKMAJOR) idx = 5; else if (type & VER_SERVICEPACKMINOR) idx = 4; else return mask;
    return mask | ((ULONGLONG)cond << (idx * 3));
}
/* ApiSetQueryApiSetPresence(name, &present): an API set is "present" when its DLL can be found (KEXSETUP installs the
 * api-ms-win-* shells into SYSTEM). */
NTSTATUS KEXAPI kex_ApiSetQueryApiSetPresence(const KUSTR *name, BOOLEAN *present)
{
    char a[MAX_PATH]; int n, k; char path[MAX_PATH + 16]; UINT s;
    if (!name || !present || !name->Buffer) return STATUS_INVALID_PARAMETER;
    n = name->Length / 2; if (n > MAX_PATH - 5) n = MAX_PATH - 5;
    for (k = 0; k < n; k++) a[k] = (char)name->Buffer[k];
    a[n] = 0;
    if (n < 4 || lstrcmpiA(a + n - 4, ".dll")) lstrcatA(a, ".dll");
    s = GetSystemDirectoryA(path, MAX_PATH);
    if (!s || s >= MAX_PATH) { *present = FALSE; return STATUS_SUCCESS; }
    if (path[s - 1] != '\\') lstrcatA(path, "\\");
    lstrcatA(path, a);
    *present = GetFileAttributesA(path) != 0xFFFFFFFF;
    return STATUS_SUCCESS;
}
