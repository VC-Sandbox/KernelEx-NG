/*
 * ntdll_ext.c - KernelEx-NG Phase 1 NT-level emulation on Windows 98 SE.
 * Struct layouts follow the documented / ReactOS x86 layouts. Win98 data sources:
 * GetSystemInfo, GlobalMemoryStatus, Toolhelp32, HKEY_DYN_DATA\PerfStats (CPU usage).
 */
#include "ntdll_ext.h"
#include <tlhelp32.h>
#include <string.h>

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } KUSTR;

typedef struct {                       /* SystemBasicInformation (0) / Emulation (62), 44 bytes */
    ULONG Reserved, TimerResolution, PageSize, NumberOfPhysicalPages,
          LowestPhysicalPageNumber, HighestPhysicalPageNumber, AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress, MaximumUserModeAddress, ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} K_SYS_BASIC;
typedef struct { USHORT Arch, Level, Revision, MaxProcs; ULONG FeatureBits; } K_SYS_PROC;   /* 1 */
typedef struct { LARGE_INTEGER BootTime, CurrentTime, TimeZoneBias; ULONG TimeZoneId, Reserved;
                 ULONGLONG BootTimeBias, SleepTimeBias; } K_SYS_TOD;                         /* 3 */
typedef struct { LARGE_INTEGER Idle, Kernel, User, Dpc, Interrupt; ULONG InterruptCount; } K_SYS_PPI; /* 8 */
typedef struct {                
                /* SYSTEM_PROCESS_INFORMATION (5), x86 = 0xB8 bytes */
    ULONG NextEntryOffset, NumberOfThreads; LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime, UserTime, KernelTime; KUSTR ImageName; LONG BasePriority;
    HANDLE UniqueProcessId, InheritedFromUniqueProcessId; ULONG HandleCount, SessionId;
    ULONG_PTR PageDirectoryBase; SIZE_T VmCounters[11]; SIZE_T PrivatePageCount;
    LARGE_INTEGER IoCounters[6];
} K_SYS_PROCESS;
typedef struct {                /* SYSTEM_THREAD_INFORMATION, x86 = 0x40 bytes */
    LARGE_INTEGER KernelTime, UserTime, CreateTime; ULONG WaitTime; PVOID StartAddress;
    HANDLE UniqueProcess, UniqueThread; LONG Priority, BasePriority; ULONG ContextSwitches, State, WaitReason;
} K_SYS_THREAD;

#define NEED(sz) do { if (retlen) *retlen = (ULONG)(sz); if (len < (ULONG)(sz)) return STATUS_INFO_LENGTH_MISMATCH; } while (0)

/* CPU usage % from the Win9x performance registry (KERNEL\CPUUsage). */
static DWORD cpu_usage_percent(void)
{
    HKEY k; DWORD v = 0, sz = sizeof(v);
    if (RegOpenKeyExA(HKEY_DYN_DATA, "PerfStats\\StatData", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        RegQueryValueExA(k, "KERNEL\\CPUUsage", NULL, NULL, (BYTE *)&v, &sz);
        RegCloseKey(k);
    }
    return v > 100 ? 100 : v;
}

static void start_perfstats(void)   /* must be "started" once before StatData is live */
{
    HKEY k; DWORD v, sz = sizeof(v);
    if (RegOpenKeyExA(HKEY_DYN_DATA, "PerfStats\\StartStat", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        RegQueryValueExA(k, "KERNEL\\CPUUsage", NULL, NULL, (BYTE *)&v, &sz);
        RegCloseKey(k);
    }
}

/* Integrate CPU% over time into synthetic idle/user times (100 ns units). */
static CRITICAL_SECTION g_cpu_cs; static ULONGLONG g_cpu_last, g_idle, g_busy;
static void cpu_times(ULONGLONG *idle, ULONGLONG *busy)
{
    ULONGLONG now = (ULONGLONG)GetTickCount() * 10000ULL, d;
    EnterCriticalSection(&g_cpu_cs);
    d = g_cpu_last ? now - g_cpu_last : now;
    if (now < g_cpu_last) d = 0;
    { DWORD pct = cpu_usage_percent(); g_busy += d * pct / 100; g_idle += d - d * pct / 100; }
    g_cpu_last = now; *idle = g_idle; *busy = g_busy;
    LeaveCriticalSection(&g_cpu_cs);
}

static void fill_basic(K_SYS_BASIC *b)
{
    SYSTEM_INFO si; MEMORYSTATUS ms;
    GetSystemInfo(&si); ms.dwLength = sizeof(ms); GlobalMemoryStatus(&ms);
    memset(b, 0, sizeof(*b));
    b->TimerResolution = 549254;        /* 54.9 ms PIT tick on 9x */
    b->PageSize = si.dwPageSize;
    b->NumberOfPhysicalPages = (ULONG)(ms.dwTotalPhys / si.dwPageSize);
    b->LowestPhysicalPageNumber = 1;
    b->HighestPhysicalPageNumber = b->NumberOfPhysicalPages;
    b->AllocationGranularity = si.dwAllocationGranularity;
    b->MinimumUserModeAddress = (ULONG_PTR)si.lpMinimumApplicationAddress;
    b->MaximumUserModeAddress = (ULONG_PTR)si.lpMaximumApplicationAddress;
    b->ActiveProcessorsAffinityMask = 1;
    b->NumberOfProcessors = 1;          /* 9x kernel is uniprocessor */
}

static NTSTATUS query_processes(PVOID buf, ULONG len, PULONG retlen)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    PROCESSENTRY32 pe; THREADENTRY32 te; ULONG need = 0, off = 0; BYTE *p = (BYTE *)buf;
    K_SYS_PROCESS *prev = NULL; int
 pass;
    if (snap == INVALID_HANDLE_VALUE) return STATUS_NO_MEMORY_K;
    /* pass 0 = measure, pass 1 = fill */
    for (pass = 0; pass < 2; pass++) {
        off = 0; prev = NULL;
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) do {
            ULONG nthreads = 0, namelen, recsz; K_SYS_PROCESS *rec;
            const char *base = strrchr(pe.szExeFile, '\\'); base = base ? base + 1 : pe.szExeFile;
            te.dwSize = sizeof(te);
            if (Thread32First(snap, &te)) do { if (te.th32OwnerProcessID == pe.th32ProcessID) nthreads++; }
                while (Thread32Next(snap, &te));
            namelen = (ULONG)strlen(base);
            recsz = (sizeof(K_SYS_PROCESS) + nthreads * sizeof(K_SYS_THREAD) + (namelen + 1) * 2 + 7) & ~7UL;
            if (pass == 1) {
                K_SYS_THREAD *th; WCHAR *nm; ULONG i = 0;
                rec = (K_SYS_PROCESS *)(p + off); memset(rec, 0, recsz);
                th = (K_SYS_THREAD *)(rec + 1);
                nm = (WCHAR *)(th + nthreads);
                MultiByteToWideChar(CP_ACP, 0, base, -1, nm, namelen + 1);
                rec->NumberOfThreads = nthreads;
                rec->ImageName.Buffer = nm; rec->ImageName.Length = (USHORT)(namelen * 2);
                rec->ImageName.MaximumLength = (USHORT)(namelen * 2 + 2);
                rec->BasePriority = pe.pcPriClassBase;
                {   DWORD kex_pid_nt(DWORD real);                      /* build 131: NT-style ids (pid_ext.c) */
                    rec->UniqueProcessId = (HANDLE)(ULONG_PTR)kex_pid_nt(pe.th32ProcessID);
                    rec->InheritedFromUniqueProcessId = (HANDLE)(ULONG_PTR)kex_pid_nt(pe.th32ParentProcessID); }
                te.dwSize = sizeof(te);
                if (Thread32First(snap, &te)) do {
                    if (te.th32OwnerProcessID == pe.th32ProcessID && i < nthreads) {
                        th[i].UniqueProcess = rec->UniqueProcessId;
                        th[i].UniqueThread = (HANDLE)(ULONG_PTR)te.th32ThreadID;
                        th[i].Priority = te.tpBasePri + te.tpDeltaPri; th[i].BasePriority = te.tpBasePri;
                        th[i].State = 5; /* Waiting */ i++;
                    }
                } while (Thread32Next(snap, &te));
                if (prev) prev->NextEntryOffset = (ULONG)((BYTE *)rec - (BYTE *)prev);
                prev = rec;
            }
            off += recsz;
        } while (Process32Next(snap, &pe));
        if (pass == 0) {
            need = off;
            if (retlen) *retlen = need;
            if (len < need) { CloseHandle(snap); return STATUS_INFO_LENGTH_MISMATCH; }
        }
    }
    CloseHandle(snap);
    return STATUS_SUCCESS;
}

NTSTATUS KEXAPI kex_NtQuerySystemInformation(ULONG cls, PVOID buf, ULONG len, PULONG retlen)
{
    if (len && (!buf || IsBadWritePtr(buf, len))) return STATUS_ACCESS_VIOLATION_K;
    switch (cls) {
    case 0: case 62: /* SystemBasicInformation / SystemEmulationBasicInformation */
        NEED(sizeof(K_SYS_BASIC)); fill_basic((K_SYS_BASIC *)buf); return STATUS_SUCCESS;
    case 1: { /* SystemProcessorInformation */
        SYSTEM_INFO si; K_SYS_PROC *pi = (K_SYS_PROC *)buf;
        NEED(sizeof(K_SYS_PROC)); GetSystemInfo(&si);
        pi->Arch = PROCESSOR_ARCHITECTURE_INTEL; pi->Level = si.wProcessorLevel;
        pi->Revision = si.wProcessorRevision; pi->MaxProcs = 1; pi->FeatureBits = 0;
        return STATUS_SUCCESS; }
    case 3: { /* SystemTimeOfDayInformation */
        K_SYS_TOD *t = (K_SYS_TOD *)buf; FILETIME ft; TIME_ZONE_INFORMATION tz; DWORD id;
        NEED(sizeof(K_SYS_TOD)); memset(t, 0, sizeof(*t));
        GetSystemTimeAsFileTime(&ft);
        t->CurrentTime.LowPart = ft.dwLowDateTime; t->CurrentTime.HighPart = (LONG)ft.dwHighDateTime;
        t->BootTime.QuadPart = t->CurrentTime.QuadPart - (LONGLONG)GetTickCount() * 10000;
        id = GetTimeZoneInformation(&tz);
        t->TimeZoneBias.QuadPart = (LONGLONG)(tz.Bias + (id == TIME_ZONE_ID_DAYLIGHT ? tz.DaylightBias : 0)) * 600000000LL;
        t->TimeZoneId = id;
        return STATUS_SUCCESS; }
    case 5: /* SystemProcessInformation */
        return query_processes(buf, len, retlen);
    case 8: { /* SystemProcessorPerformanceInformation (1 CPU) */
        K_SYS_PPI *pp = (K_SYS_PPI *)buf; ULONGLONG idle, busy;
        NEED(sizeof(K_SYS_PPI)); memset(pp, 0, sizeof(*pp)); cpu_times(&idle, &busy);
        pp->Idle.QuadPart = (LONGLONG)idle;
        pp->Kernel.QuadPart = (LONGLONG)(idle + busy / 4);   /* NT: KernelTime includes idle */
        pp->User.QuadPart = (LONGLONG)(busy - busy / 4);
        return STATUS_SUCCESS; }
    case 16: case 64: /* System(Extended)HandleInformation: report zero handles */
        NEED(cls == 16 ? 4 : 8); memset(buf, 0, cls == 16 ? 4 : 8); return STATUS_SUCCESS;
    case 35: /* SystemKernelDebuggerInformation: {Enabled=FALSE, NotPresent=TRUE} */
        NEED(2); ((BYTE *)buf)[0] = 0; ((BYTE *)buf)[1] = 1; return STATUS_SUCCESS;
    case 50: /* SystemRangeStartInformation */
        NEED(sizeof(ULONG_PTR)); *(ULONG_PTR *)buf = 0x80000000UL; return STATUS_SUCCESS;
    case 83: /* SystemProcessorIdleCycleTimeInformation */
        NEED(8); { ULONGLONG i, b; cpu_times(&i, &b); *(ULONGLONG *)buf = i; } return STATUS_SUCCESS;
    case 103: /* SystemCodeIntegrityInformation {Length, Options} -> CODEINTEGRITY_OPTION_ENABLED */
        NEED(8); ((ULONG *)buf)[0] = 8; ((ULONG *)buf)[1] = 1; return STATUS_SUCCESS;
    default:
        if (retlen) *retlen = 0;
        return STATUS_INVALID_INFO_CLASS;
    }
}

/* ======================= NtSetInformationThread ======================= */
NTSTATUS KEXAPI kex_NtSetInformationThread(HANDLE h, ULONG cls, PVOID info, ULONG len)
{
    switch (cls) {
    case 2: case 3: /* ThreadPriority / ThreadBasePriority (LONG) */
        if (len != sizeof(LONG) || !info) return STATUS_INFO_LENGTH_MISMATCH;
        return SetThreadPriority(h, *(LONG *)info) ? STATUS_SUCCESS : STATUS_INVALID_HANDLE_K;
    case 4: /* ThreadAffinityMask: only CPU 0 exists */
        if (len != sizeof(ULONG_PTR) || !info) return STATUS_INFO_LENGTH_MISMATCH;
        return (*(ULONG_PTR *)info & 1) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
    case 5: /* ThreadImpersonationToken: only "revert" (NULL) is meaningful without tokens */
        if (len != sizeof(HANDLE) || !info) return STATUS_INFO_LENGTH_MISMATCH;
        return *(HANDLE *)info == NULL ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
    case 13: case 14: case 22: case 33: case 38: /* ideal CPU, prio boost, page/IO prio, name */
        return STATUS_SUCCESS;
    case 17: /* ThreadHideFromDebugger: len must be 0 */
        return len == 0 ? STATUS_SUCCESS : STATUS_INFO_LENGTH_MISMATCH;
    default:
        return STATUS_INVALID_INFO_CLASS;
    }
}

/* ======================= NtCreateThreadEx ======================= */
typedef struct { ULONG_PTR Attribute; SIZE_T Size; PVOID Value; PSIZE_T ReturnLength; } K_PS_ATTR;
typedef struct { SIZE_T TotalLength; K_PS_ATTR Attributes[1]; } K_PS_ATTR_LIST;

NTSTATUS KEXAPI kex_NtCreateThreadEx(PHANDLE out, ACCESS_MASK access, PVOID objattr, HANDLE process,
                                     PVOID start, PVOID arg, ULONG flags, SIZE_T zerobits,
                                     SIZE_T stack, SIZE_T maxstack, PVOID attrlist)
{
    DWORD tid = 0; HANDLE h;
    (void)access; (void)objattr; (void)zerobits;
    if (!out || !start) return STATUS_INVALID_PARAMETER;
    if (process != GetCurrentProcess() && process != (HANDLE)-1)
        return STATUS_NOT_SUPPORTED;          /* cross-process threads: Phase 3 via VxD */
    h = CreateThread(NULL, maxstack ? maxstack : stack, (LPTHREAD_START_ROUTINE)start, arg,
                     (flags & 1) ? CREATE_SUSPENDED : 0, &tid);   /* flag 1 = CREATE_SUSPENDED */
    if (!h) return STATUS_NO_MEMORY_K;
    if (attrlist) {                             /* PS_ATTRIBUTE_CLIENT_ID = 0x10003 */
        K_PS_ATTR_LIST *l = (K_PS_ATTR_LIST *)attrlist;
        SIZE_T i, n = (l->TotalLength - sizeof(SIZE_T)) / sizeof(K_PS_ATTR);
        for (i = 0; i < n; i++)
            if (l->Attributes[i].Attribute == 0x10003 && l->Attributes[i].Size >= 2 * sizeof(HANDLE)) {
                HANDLE *cid = (HANDLE *)l->Attributes[i].Value;
                cid[0] = (HANDLE)(ULONG_PTR)GetCurrentProcessId(); cid[1] = (HANDLE)(ULONG_PTR)tid;
            }
    }
    *out = h;
    return STATUS_SUCCESS;
}


/* ======================= Fibers =======================
 * Win98 kernel32 exports native CreateFiber/SwitchToFiber/DeleteFiber/ConvertThreadToFiber;
 * we forward to them. Win98 keeps the current fiber at fs:[0x10] (see ARCHITECTURE.md review), but the
 * fiber is tracked in a private TLS slot so IsThreadAFiber/GetCurrentFiber/ConvertFiberToThread work. */
typedef LPVOID (WINAPI *pfnConv)(LPVOID);
typedef LPVOID (WINAPI *pfnCreate)(SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
typedef VOID   (WINAPI *pfnFib)(LPVOID);
static pfnConv  p_Convert; static pfnCreate p_Create; static pfnFib p_Switch, p_Delete;
static DWORD g_fiber_tls = TLS_OUT_OF_INDEXES;

LPVOID KEXAPI kex_ConvertThreadToFiberEx(LPVOID param, DWORD flags)
{
    LPVOID f;
    (void)flags;   /* FIBER_FLAG_FLOAT_SWITCH: 9x always saves FPU state via TDB EmulatorSelector */
    if (kex_IsThreadAFiber()) { SetLastError(ERROR_ALREADY_FIBER); return NULL; }
    if (!p_Convert) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    f = p_Convert(param);
    if (f) TlsSetValue(g_fiber_tls, f);
    return f;
}
LPVOID KEXAPI kex_ConvertThreadToFiber(LPVOID param) { return kex_ConvertThreadToFiberEx(param, 0); }

BOOL KEXAPI kex_ConvertFiberToThread(void)
{
    if (!kex_IsThreadAFiber()) { SetLastError(ERROR_ALREADY_THREAD); return FALSE; }
    /* The native 9x thread-fiber block is small and owned by kernel32; we cannot free it
     * safely without RE of its layout, so it is intentionally leaked (bounded: once per call). */
    TlsSetValue(g_fiber_tls, NULL);
    return TRUE;
}

LPVOID KEXAPI kex_CreateFiberEx(SIZE_T commit, SIZE_T reserve, DWORD flags, LPFIBER_START_ROUTINE fn, LPVOID param)
{
    (void)flags;
    if (!p_Create) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return NULL; }
    return p_Create(reserve ? reserve : commit, fn, param);
}
LPVOID KEXAPI kex_CreateFiber(SIZE_T stack, LPFIBER_START_ROUTINE fn, LPVOID param)
{
    return kex_CreateFiberEx(stack, 0, 0, fn, param);
}

VOID KEXAPI kex_SwitchToFiber(LPVOID fiber)
{
    if (!fiber || !p_Switch) return;
    TlsSetValue(g_fiber_tls, fiber);   /* set before switching: the new fiber runs on this thread */
    p_Switch(fiber);
}

VOID KEXAPI kex_DeleteFiber(LPVOID fiber)
{
    if (!fiber || !p_Delete) return;
    if (fiber == kex_GetCurrentFiber()) {   /* NT semantics: deleting the running fiber exits the thread */
        TlsSetValue(g_fiber_tls, NULL);
        ExitThread(1);
    }
    p_Delete(fiber);
}

BOOL   KEXAPI kex_IsThreadAFiber(void)   { return g_fiber_tls != TLS_OUT_OF_INDEXES && TlsGetValue(g_fiber_tls) != NULL; }
LPVOID KEXAPI kex_GetCurrentFiber(void)  { return g_fiber_tls == TLS_OUT_OF_INDEXES ? NULL : TlsGetValue(g_fiber_tls); }

/* ======================= RtlCaptureContext (x86) =======================
 * Captures the caller's context: Eip = return address, Esp = caller's esp after
 * this stdcall returns (esp+8), Ebp = caller's ebp. ContextFlags = CONTEXT_FULL (0x10007). */
__asm__(
    ".text\n\t.globl _kex_RtlCaptureContext@4\n"
    "_kex_RtlCaptureContext@4:\n\t"
    "pushl %ebx\n\t"
    "movl 8(%esp), %ebx\n\t"          /* ebx = PCONTEXT */
    "movl %eax, 0xB0(%ebx)\n\t"
    "movl (%esp), %eax\n\t"  "movl %eax, 0xA4(%ebx)\n\t"   /* original ebx */
    "movl %ecx, 0xAC(%ebx)\n\t" "movl %edx, 0xA8(%ebx)\n\t"
    "movl %esi, 0xA0(%ebx)\n\t" "movl %edi, 0x9C(%ebx)\n\t"
    "movl %ebp, 0xB4(%ebx)\n\t"
    "movl 4(%esp), %eax\n\t" "movl %eax, 0xB8(%ebx)\n\t"   /* Eip = return address */
    "leal 12(%esp), %eax\n\t" "movl %eax, 0xC4(%ebx)\n\t"  /* Esp after ret 4 */
    "xorl %eax, %eax\n\t"
    "movw %cs, %ax\n\t" "movl %eax, 0xBC(%ebx)\n\t"
    "movw %ds, %ax\n\t" "movl %eax, 0x98(%ebx)\n\t"
    "movw %es, %ax\n\t" "movl %eax, 0x94(%ebx)\n\t"
    "movw %fs, %ax\n\t" "movl %eax, 0x90(%ebx)\n\t"
    "movw %gs, %ax\n\t" "movl %eax, 0x8C(%ebx)\n\t"
    "movw %ss, %ax\n\t" "movl %eax, 0xC8(%ebx)\n\t"
    "pushfl\n\t" "popl 0xC0(%ebx)\n\t"
    "movl $0x10007, (%ebx)\n\t"
    "movl 0xB0(%ebx), %eax\n\t"
    "popl %ebx\n\t"
    "ret $4\n");

/* x86 has no table-based unwind data: every function is "leaf" from this API's view. */
PVOID KEXAPI kex_RtlLookupFunctionEntry(ULONG64 pc, PULONG64 imagebase, PVOID history)
{
    (void)pc; (void)history;
    if (imagebase) *imagebase = 0;
    return NULL;
}

BOOL kex_ntext_init(void)
{
    HMODULE k = GetModuleHandleA("KERNEL32.DLL");
    InitializeCriticalSection(&g_cpu_cs);
    start_perfstats();
    g_fiber_tls = TlsAlloc();
    p_Convert = (pfnConv)GetProcAddress(k, "ConvertThreadToFiber");
    p_Create  = (pfnCreate)GetProcAddress(k, "CreateFiber");
    p_Switch  = (pfnFib)GetProcAddress(k, "SwitchToFiber");
    p_Delete  = (pfnFib)GetProcAddress(k, "DeleteFiber");
    return g_fiber_tls != TLS_OUT_OF_INDEXES;
}
