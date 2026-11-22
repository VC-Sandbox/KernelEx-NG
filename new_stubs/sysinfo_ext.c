/*
 * sysinfo_ext.c - KernelEx-NG Phase 2: processor topology, product info, psapi (K32*),
 * process/thread information classes and assorted NT6+ kernel32 APIs for Windows 98 SE.
 *
 * Rules (same as kernel32_ext.c):
 *   - real data where Win98 can provide it (CPUID, toolhelp, VirtualQuery, GlobalMemoryStatus)
 *   - hints/no-op controls (memory priority, power throttling, prefetch) succeed silently
 *   - anything whose success would make the caller assume behaviour we do not provide
 *     (mitigations, DEP, skip-completion-port, cycle counters) FAILS with
 *     ERROR_NOT_SUPPORTED so the caller takes its fallback path.
 * Win98 schedules on exactly one CPU, so topology reports 1 core / 1 package / 1 node / 1 group.
 * Only kernel32 exports present in the Win98 SE CD kernel32.dll are imported ("make verify").
 */
#include "sysinfo_ext.h"
#include <tlhelp32.h>
#include <string.h>

/* ================================ CPUID / caches ================================ */
typedef struct { BYTE level, assoc; WORD line; DWORD size; PROCESSOR_CACHE_TYPE type; } kex_cache;
static kex_cache g_cache[8];
static int       g_ncache = -1;

static BOOL have_cpuid(void)
{
    DWORD a, b;
    __asm__ __volatile__("pushfl; pushfl; popl %0; movl %0,%1; xorl $0x200000,%0;"
                         "pushl %0; popfl; pushfl; popl %0; popfl"
                         : "=&r"(a), "=&r"(b) :: "cc");
    return ((a ^ b) & 0x200000) != 0;
}

static void cpuid(DWORD leaf, DWORD sub, DWORD r[4])
{
    __asm__ __volatile__("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(leaf), "c"(sub));
}

static void add_cache(int level, int assoc, int line, DWORD size, PROCESSOR_CACHE_TYPE t)
{
    if (g_ncache >= 8 || !size) return;
    g_cache[g_ncache].level = (BYTE)level; g_cache[g_ncache].assoc = (BYTE)assoc;
    g_cache[g_ncache].line = (WORD)line;   g_cache[g_ncache].size = size;
    g_cache[g_ncache].type = t;            g_ncache++;
}

static int amd_assoc(DWORD code)
{
    static const BYTE map[16] = { 0, 1, 2, 0, 4, 0, 8, 0, 16, 0, 32, 48, 64, 96, 128, 0xFF };
    return map[code & 15];
}

/* Intel leaf 4 / AMD leaf 0x8000001D: one subleaf per cache, same register layout. */
static void deterministic_caches(DWORD leaf)
{
    DWORD r[4], sub;
    for (sub = 0; sub < 8; sub++) {
        DWORD t, ways, parts, line, sets;
        cpuid(leaf, sub, r);
        t = r[0] & 0x1F;
        if (!t) break;
        ways = ((r[1] >> 22) & 0x3FF) + 1; parts = ((r[1] >> 12) & 0x3FF) + 1;
        line = (r[1] & 0xFFF) + 1;         sets = r[2] + 1;
        add_cache((r[0] >> 5) & 7, (r[0] & 0x200) ? 0xFF : (int)ways, (int)line, ways * parts * line * sets,
                  t == 1 ? CacheData : t == 2 ? CacheInstruction : CacheUnified);
    }
}

static void detect_caches(void)
{
    DWORD r[4], maxl, maxe;
    char vendor[13];
    if (g_ncache >= 0) return;
    g_ncache = 0;
    if (!have_cpuid()) return;                         /* 486 without CPUID: no cache info */
    cpuid(0, 0, r); maxl = r[0];
    memcpy(vendor, &r[1], 4); memcpy(vendor + 4, &r[3], 4); memcpy(vendor + 8, &r[2], 4); vendor[12] = 0;

    if (!strcmp(vendor, "GenuineIntel") && maxl >= 4) {       /* deterministic cache parameters */
        deterministic_caches(4);
        if (g_ncache) return;
    }
    cpuid(0x80000000, 0, r); maxe = r[0];
    /* AMD Zen/Bulldozer+: leaf 0x8000001D has the Intel-leaf-4 layout (needs TOPOEXT, 0x80000001 ECX bit 22).
       Zen reports L3 associativity as code 9 ("see 0x8000001D") in leaf 0x80000006, so prefer this. */
    if (maxe >= 0x8000001D && maxe < 0x8000FFFF) {
        cpuid(0x80000001, 0, r);
        if (r[2] & (1u << 22)) { deterministic_caches(0x8000001D); if (g_ncache) return; }
    }
    if (maxe >= 0x80000005 && maxe < 0x8000FFFF) {
        cpuid(0x80000005, 0, r);                       /* AMD L1 (zero on Intel) */
        add_cache(1, (r[2] >> 16) & 0xFF, r[2] & 0xFF, (r[2] >> 24) * 1024, CacheData);
        add_cache(1, (r[3] >> 16) & 0xFF, r[3] & 0xFF, (r[3] >> 24) * 1024, CacheInstruction);
    }
    if (maxe >= 0x80000006 && maxe < 0x8000FFFF) {
        cpuid(0x80000006, 0, r);
        add_cache(2, amd_assoc(r[2] >> 12), r[2] & 0xFF, (r[2] >> 16) * 1024, CacheUnified);
        add_cache(3, amd_assoc(r[3] >> 12), r[3] & 0xFF, (r[3] >> 18) * 512 * 1024, CacheUnified);
    }
}

/* ============================ Logical processor info ============================ */
BOOL KEXAPI kex_GetLogicalProcessorInformation(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buf, PDWORD len)
{
    DWORD need, n = 0;
    int i;
    if (!len) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    detect_caches();
    need = (DWORD)(3 + g_ncache) * sizeof(*buf);
    if (!buf || *len < need) { *len = need; SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    memset(buf, 0, need);
    buf[n].ProcessorMask = 1; buf[n].Relationship = RelationProcessorCore;    n++;
    buf[n].ProcessorMask = 1; buf[n].Relationship = RelationProcessorPackage; n++;
    buf[n].ProcessorMask = 1; buf[n].Relationship = RelationNumaNode;         n++;
    for (i = 0; i < g_ncache; i++, n++) {
        buf[n].ProcessorMask = 1; buf[n].Relationship = RelationCache;
        buf[n].Cache.Level = g_cache[i].level; buf[n].Cache.Associativity = g_cache[i].assoc;
        buf[n].Cache.LineSize = g_cache[i].line; buf[n].Cache.Size = g_cache[i].size;
        buf[n].Cache.Type = g_cache[i].type;
    }
    *len = need;
    return TRUE;
}

#define EX_HDR      FIELD_OFFSET(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor)
#define EX_PROC_SZ  (EX_HDR + sizeof(PROCESSOR_RELATIONSHIP))
#define EX_NUMA_SZ  (EX_HDR + sizeof(NUMA_NODE_RELATIONSHIP))
#define EX_CACHE_SZ (EX_HDR + sizeof(CACHE_RELATIONSHIP))
#define EX_GROUP_SZ (EX_HDR + sizeof(GROUP_RELATIONSHIP))

static DWORD ex_record(BYTE *p, LOGICAL_PROCESSOR_RELATIONSHIP rel, int cache_idx)
{
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX e = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)p;
    DWORD sz = rel == RelationNumaNode ? EX_NUMA_SZ : rel == RelationCache ? EX_CACHE_SZ :
               rel == RelationGroup ? EX_GROUP_SZ : EX_PROC_SZ;
    if (!p) return sz;
    memset(p, 0, sz);
    e->Relationship = rel; e->Size = sz;
    switch (rel) {
    case RelationProcessorCore: case RelationProcessorPackage:
        e->Processor.GroupCount = 1; e->Processor.GroupMask[0].Mask = 1; break;
    case RelationNumaNode:
        e->NumaNode.GroupMask.Mask = 1; break;
    case RelationCache:
        e->Cache.Level = g_cache[cache_idx].level; e->Cache.Associativity = g_cache[cache_idx].assoc;
        e->Cache.LineSize = g_cache[cache_idx].line; e->Cache.CacheSize = g_cache[cache_idx].size;
        e->Cache.Type = g_cache[cache_idx].type; e->Cache.GroupMask.Mask = 1; break;
    case RelationGroup:
        e->Group.MaximumGroupCount = 1; e->Group.ActiveGroupCount = 1;
        e->Group.GroupInfo[0].MaximumProcessorCount = 1; e->Group.GroupInfo[0].ActiveProcessorCount = 1;
        e->Group.GroupInfo[0].ActiveProcessorMask = 1; break;
    default: break;
    }
    return sz;
}

static DWORD ex_build(BYTE *p, LOGICAL_PROCESSOR_RELATIONSHIP want)
{
    static const LOGICAL_PROCESSOR_RELATIONSHIP order[] =
        { RelationProcessorCore, RelationNumaNode, RelationCache, RelationProcessorPackage, RelationGroup };
    DWORD total = 0;
    unsigned k;
    int i;
    for (k = 0; k < sizeof(order) / sizeof(order[0]); k++) {
        if (want != RelationAll && want != order[k]) continue;
        if (order[k] == RelationCache) {
            for (i = 0; i < g_ncache; i++) total += ex_record(p ? p + total : NULL, RelationCache, i);
        } else total += ex_record(p ? p + total : NULL, order[k], 0);
    }
    return total;
}

BOOL KEXAPI kex_GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP rel,
        PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX buf, PDWORD len)
{
    DWORD need;
    if (!len || (rel > RelationGroup && rel != RelationAll && rel != (LOGICAL_PROCESSOR_RELATIONSHIP)5 /*Die*/ &&
                 rel != (LOGICAL_PROCESSOR_RELATIONSHIP)7 /*Module*/)) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    detect_caches();
    need = ex_build(NULL, rel);
    if (!buf || *len < need) { *len = need; SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    ex_build((BYTE *)buf, rel);
    *len = need;
    return TRUE;
}

/* ========================= Processor counts / groups ========================= */
#define ALL_GROUPS 0xFFFF
DWORD KEXAPI kex_GetActiveProcessorCount(WORD g)  { return (g == 0 || g == ALL_GROUPS) ? 1 : 0; }
DWORD KEXAPI kex_GetMaximumProcessorCount(WORD g) { return (g == 0 || g == ALL_GROUPS) ? 1 : 0; }
WORD  KEXAPI kex_GetActiveProcessorGroupCount(void)  { return 1; }
WORD  KEXAPI kex_GetMaximumProcessorGroupCount(void) { return 1; }
DWORD KEXAPI kex_GetCurrentProcessorNumber(void)  { return 0; }
VOID  KEXAPI kex_GetCurrentProcessorNumberEx(PPROCESSOR_NUMBER n) { if (n) memset(n, 0, sizeof(*n)); }

BOOL KEXAPI kex_GetThreadGroupAffinity(HANDLE h, PGROUP_AFFINITY ga)
{
    if (!ga) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(ga, 0, sizeof(*ga)); ga->Mask = 1;
    return TRUE;
}

BOOL KEXAPI kex_SetThreadGroupAffinity(HANDLE h, const GROUP_AFFINITY *ga, PGROUP_AFFINITY prev)
{
    if (!ga || ga->Group != 0 || !(ga->Mask & 1)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (prev) { memset(prev, 0, sizeof(*prev)); prev->Mask = 1; }
    return TRUE;
}

/* ============================ Product / firmware ============================ */
/* The version layer reports 10.0.19045, so the matching SKU is Professional. */
BOOL KEXAPI kex_GetProductInfo(DWORD maj, DWORD min, DWORD spmaj, DWORD spmin, PDWORD type)
{
    if (!type) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *type = maj >= 6 ? PRODUCT_PROFESSIONAL : PRODUCT_UNDEFINED;
    return TRUE;
}

BOOL KEXAPI kex_GetFirmwareType(PFIRMWARE_TYPE t)
{
    if (!t) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *t = FirmwareTypeBios;
    return TRUE;
}

/* ================================ Stack limits ================================ */
VOID KEXAPI kex_GetCurrentThreadStackLimits(PULONG_PTR low, PULONG_PTR high)
{
    NT_TIB *tib;
    MEMORY_BASIC_INFORMATION mbi;
    __asm__ __volatile__("movl %%fs:0x18, %0" : "=r"(tib));     /* TIB self pointer (9x too) */
    if (high) *high = (ULONG_PTR)tib->StackBase;
    if (low) {
        *low = (ULONG_PTR)tib->StackLimit;
        if (VirtualQuery(tib->StackLimit, &mbi, sizeof(mbi))) *low = (ULONG_PTR)mbi.AllocationBase;
    }
}

/* ============================ Process handle helpers ============================ */
typedef DWORD (WINAPI *pGetProcessId)(HANDLE);

static BOOL is_self(HANDLE h) { return h == GetCurrentProcess() || h == (HANDLE)(LONG_PTR)-1; }

/* PID for a process handle. Native Win98 has no GetProcessId; KernelEx's kexbases provides
 * one (PDB lookup), so use it when the resolver exposes it. Returns 0 if unknown. */
static DWORD pid_of(HANDLE h)
{
    static pGetProcessId fn;
    static BOOL looked;
    if (is_self(h)) return GetCurrentProcessId();
    if (!looked) { fn = (pGetProcessId)kex_sysproc("kernel32.dll", "GetProcessId"); looked = TRUE; }
    return fn ? fn(h) : 0;
}

static DWORD a_to_w(const char *a, LPWSTR w, DWORD wlen)
{
    int n = MultiByteToWideChar(CP_ACP, 0, a, -1, w, (int)wlen);
    return n > 0 ? (DWORD)n - 1 : 0;
}

/* Copy string, NT GetModuleFileNameEx semantics: returns chars copied (no NUL), truncates. */
static DWORD out_name(const char *s, LPVOID buf, DWORD n, BOOL wide)
{
    DWORD len = (DWORD)strlen(s);
    if (!buf || !n) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
    if (wide) {
        WCHAR tmp[MAX_PATH * 2];
        DWORD wl = a_to_w(s, tmp, MAX_PATH * 2);
        if (wl >= n) wl = n - 1;
        memcpy(buf, tmp, wl * sizeof(WCHAR)); ((LPWSTR)buf)[wl] = 0;
        return wl;
    }
    if (len >= n) len = n - 1;
    memcpy(buf, s, len); ((char *)buf)[len] = 0;
    return len;
}

/* Find a module in a process: hmod NULL = the main exe. Fills full path and base name. */
static BOOL find_module(HANDLE hp, HMODULE hmod, char *path, char *base, MODULEINFO *mi)
{
    DWORD pid = pid_of(hp), exe_mid = 0;
    HANDLE snap;
    MODULEENTRY32 me;
    BOOL ok;
    if (!pid) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS, pid);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    if (!hmod) {    /* 9x: Module32First is not reliably the exe; match the process' module id */
        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        for (ok = Process32First(snap, &pe); ok; ok = Process32Next(snap, &pe))
            if (pe.th32ProcessID == pid) { exe_mid = pe.th32ModuleID; break; }
    }
    me.dwSize = sizeof(me);
    for (ok = Module32First(snap, &me); ok; ok = Module32Next(snap, &me)) {
        if (hmod ? me.hModule == hmod : (exe_mid ? me.th32ModuleID == exe_mid : TRUE)) {
            if (path) lstrcpynA(path, me.szExePath, MAX_PATH);
            if (base) lstrcpynA(base, me.szModule, MAX_PATH);
            if (mi) {
                mi->lpBaseOfDll = me.modBaseAddr; mi->SizeOfImage = me.modBaseSize; mi->EntryPoint = NULL;
            }
            CloseHandle(snap);
            return TRUE;
        }
    }
    CloseHandle(snap);
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
}

/* ===================================== psapi ===================================== */
BOOL KEXAPI kex_K32EnumProcessModules(HANDLE hp, HMODULE *mods, DWORD cb, LPDWORD needed)
{
    DWORD pid = pid_of(hp), exe_mid = 0, n = 0, cap = cb / sizeof(HMODULE);
    HANDLE snap;
    MODULEENTRY32 me;
    PROCESSENTRY32 pe;
    BOOL ok;
    if (!needed || (cb && !mods)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!pid) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS, pid);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    pe.dwSize = sizeof(pe);
    for (ok = Process32First(snap, &pe); ok; ok = Process32Next(snap, &pe))
        if (pe.th32ProcessID == pid) { exe_mid = pe.th32ModuleID; break; }
    me.dwSize = sizeof(me);
    for (ok = Module32First(snap, &me); ok; ok = Module32Next(snap, &me)) {
        if (n < cap) {
            mods[n] = me.hModule;
            if (me.th32ModuleID == exe_mid && n) {      /* NT contract: exe first */
                HMODULE t = mods[0]; mods[0] = mods[n]; mods[n] = t;
            }
        } else if (me.th32ModuleID == exe_mid && cap) mods[0] = me.hModule;
        n++;
    }
    CloseHandle(snap);
    *needed = n * sizeof(HMODULE);
    return TRUE;
}

BOOL KEXAPI kex_K32EnumProcessModulesEx(HANDLE hp, HMODULE *mods, DWORD cb, LPDWORD needed, DWORD filter)
{
    return kex_K32EnumProcessModules(hp, mods, cb, needed);    /* no 64-bit modules on 9x */
}

static DWORD module_name(HANDLE hp, HMODULE hm, LPVOID buf, DWORD n, BOOL wide, BOOL full)
{
    char path[MAX_PATH], base[MAX_PATH];
    if (is_self(hp)) {                                           /* fast path, no snapshot */
        DWORD l = GetModuleFileNameA(hm, path, MAX_PATH);
        const char *s;
        if (!l) return 0;
        s = strrchr(path, '\\');
        return out_name(full ? path : (s ? s + 1 : path), buf, n, wide);
    }
    if (!find_module(hp, hm, path, base, NULL)) return 0;
    return out_name(full ? path : base, buf, n, wide);
}

DWORD KEXAPI kex_K32GetModuleFileNameExA(HANDLE hp, HMODULE hm, LPSTR b, DWORD n)  { return module_name(hp, hm, b, n, FALSE, TRUE); }
DWORD KEXAPI kex_K32GetModuleFileNameExW(HANDLE hp, HMODULE hm, LPWSTR b, DWORD n) { return module_name(hp, hm, b, n, TRUE, TRUE); }
DWORD KEXAPI kex_K32GetModuleBaseNameA(HANDLE hp, HMODULE hm, LPSTR b, DWORD n)    { return module_name(hp, hm, b, n, FALSE, FALSE); }
DWORD KEXAPI kex_K32GetModuleBaseNameW(HANDLE hp, HMODULE hm, LPWSTR b, DWORD n)   { return module_name(hp, hm, b, n, TRUE, FALSE); }

BOOL KEXAPI kex_K32GetModuleInformation(HANDLE hp, HMODULE hm, LPMODULEINFO mi, DWORD cb)
{
    if (!mi || cb < sizeof(*mi)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (is_self(hp)) {                       /* read the PE header directly */
        BYTE *base = (BYTE *)(hm ? hm : GetModuleHandleA(NULL));
        IMAGE_NT_HEADERS *nt;
        if (IsBadReadPtr(base, sizeof(IMAGE_DOS_HEADER)) || ((IMAGE_DOS_HEADER *)base)->e_magic != IMAGE_DOS_SIGNATURE) {
            SetLastError(ERROR_INVALID_HANDLE); return FALSE;
        }
        nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
        mi->lpBaseOfDll = base;
        mi->SizeOfImage = nt->OptionalHeader.SizeOfImage;
        mi->EntryPoint  = nt->OptionalHeader.AddressOfEntryPoint ? base + nt->OptionalHeader.AddressOfEntryPoint : NULL;
        return TRUE;
    }
    return find_module(hp, hm, NULL, NULL, mi);
}

/* Memory counters for the current process: VirtualQuery walk of the private arena.
 * 9x has no per-process working-set accounting, so WorkingSetSize = committed private
 * bytes (approximation, documented). Other processes: not available on 9x. */
BOOL KEXAPI kex_K32GetProcessMemoryInfo(HANDLE hp, PPROCESS_MEMORY_COUNTERS pmc, DWORD cb)
{
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *p = (BYTE *)0x10000;
    SIZE_T priv = 0;
    if (!pmc || cb < sizeof(PROCESS_MEMORY_COUNTERS)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (!is_self(hp)) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
    while ((ULONG_PTR)p < 0x7FFF0000UL && VirtualQuery(p, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) priv += mbi.RegionSize;
        if (!mbi.RegionSize) break;
        p = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
    }
    memset(pmc, 0, cb < sizeof(PROCESS_MEMORY_COUNTERS_EX) ? cb : sizeof(PROCESS_MEMORY_COUNTERS_EX));
    pmc->cb = cb < sizeof(PROCESS_MEMORY_COUNTERS_EX) ? sizeof(PROCESS_MEMORY_COUNTERS) : sizeof(PROCESS_MEMORY_COUNTERS_EX);
    pmc->WorkingSetSize = pmc->PeakWorkingSetSize = priv;
    pmc->PagefileUsage  = pmc->PeakPagefileUsage  = priv;
    if (cb >= sizeof(PROCESS_MEMORY_COUNTERS_EX)) ((PPROCESS_MEMORY_COUNTERS_EX)pmc)->PrivateUsage = priv;
    return TRUE;
}

BOOL KEXAPI kex_K32GetPerformanceInfo(PPERFORMANCE_INFORMATION pi, DWORD cb)
{
    MEMORYSTATUS ms;
    HANDLE snap;
    PROCESSENTRY32 pe;
    BOOL ok;
    if (!pi || cb < sizeof(*pi)) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatus(&ms);
    memset(pi, 0, sizeof(*pi));
    pi->cb = sizeof(*pi);
    pi->PageSize          = 4096;
    pi->PhysicalTotal     = ms.dwTotalPhys / 4096;
    pi->PhysicalAvailable = ms.dwAvailPhys / 4096;
    pi->CommitLimit       = ms.dwTotalPageFile / 4096;
    pi->CommitTotal       = (ms.dwTotalPageFile - ms.dwAvailPageFile) / 4096;
    pi->CommitPeak        = pi->CommitTotal;
    pi->SystemCache       = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        pe.dwSize = sizeof(pe);
        for (ok = Process32First(snap, &pe); ok; ok = Process32Next(snap, &pe)) {
            pi->ProcessCount++; pi->ThreadCount += pe.cntThreads;
        }
        CloseHandle(snap);
    }
    return TRUE;
}

/* build 79: Chromium's memory instrumentation (process_memory_dump.cc:206 CountResidentBytes) asks this for every
 * page of its own allocations; the old "not supported" answer made it write an ERROR line each time (1652 lines in
 * a 20-minute run of CHRLOG8). For this process: Valid (bit 0) = the page is committed - Windows 98 cannot say
 * whether a committed page is in RAM or in the swap file, so committed counts as resident. Other processes: as before. */
BOOL  KEXAPI kex_K32QueryWorkingSetEx(HANDLE hp, PVOID pv, DWORD cb)
{
    struct { void *va; ULONG_PTR attr; } *e = pv;
    DWORD i, n = cb / sizeof(*e), lo = 1, hi = 0, st = 0;
    if (!is_self(hp) && pid_of(hp) != GetCurrentProcessId()) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
    if (!pv || IsBadWritePtr(pv, n * sizeof(*e))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < n; i++) {
        DWORD a = (DWORD)(ULONG_PTR)e[i].va;
        if (a < lo || a >= hi) {                     /* one VirtualQuery per region, not per page */
            MEMORY_BASIC_INFORMATION m;
            if (!VirtualQuery((void *)(ULONG_PTR)a, &m, sizeof(m))) { e[i].attr = 0; lo = 1; hi = 0; continue; }
            lo = (DWORD)(ULONG_PTR)m.BaseAddress; hi = lo + (DWORD)m.RegionSize; st = m.State;
        }
        e[i].attr = st == MEM_COMMIT ? 1 : 0;
    }
    return TRUE;
}
/* build 131: NT gives the file behind a mapped address as a device path ("\Device\HarddiskVolume1\WINDOWS\x.dll").
 * Here: addresses inside a module image of this process (Supermium's XP wrappers ask about their own code).
 * Other views (MapViewOfFile of a data file) are not known by name on 98 - ERROR_FILE_INVALID as NT gives for
 * memory without a file. */
DWORD KEXAPI kex_K32GetMappedFileNameW(HANDLE hp, LPVOID a, LPWSTR b, DWORD n)
{
    MEMORY_BASIC_INFORMATION m; char path[MAX_PATH], dev[MAX_PATH], drv[3]; WCHAR w[MAX_PATH * 2]; DWORD len, k;
    DWORD KEXAPI kex_QueryDosDeviceA(LPCSTR name, LPSTR buf, DWORD cap);
    if (!is_self(hp) && pid_of(hp) != GetCurrentProcessId()) { SetLastError(ERROR_NOT_SUPPORTED); return 0; }
    if (!b || !n) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!VirtualQuery(a, &m, sizeof(m)) || m.State == MEM_FREE || !m.AllocationBase) { SetLastError(ERROR_INVALID_ADDRESS); return 0; }
    if (!GetModuleFileNameA((HMODULE)m.AllocationBase, path, MAX_PATH) || path[1] != ':') { SetLastError(ERROR_FILE_INVALID); return 0; }
    drv[0] = path[0]; drv[1] = ':'; drv[2] = 0;
    if (!kex_QueryDosDeviceA(drv, dev, sizeof(dev))) { dev[0] = 0; lstrcpyA(dev, "\\Device\\HarddiskVolume1"); }
    lstrcatA(dev, path + 2);
    len = (DWORD)MultiByteToWideChar(CP_ACP, 0, dev, -1, w, MAX_PATH * 2);
    if (!len) return 0;
    len--;                                              /* without the 0 */
    k = len < n ? len : n - 1;
    memcpy(b, w, k * 2); b[k] = 0;
    if (len >= n) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return n; }
    return len;
}
DWORD KEXAPI kex_K32GetMappedFileNameA(HANDLE hp, LPVOID a, LPSTR b, DWORD n)
{
    WCHAR w[MAX_PATH * 2]; DWORD r, k;
    if (!b || !n) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    r = kex_K32GetMappedFileNameW(hp, a, w, MAX_PATH * 2);
    if (!r) return 0;
    k = (DWORD)WideCharToMultiByte(CP_ACP, 0, w, (int)r, b, (int)n, NULL, NULL);
    if (k >= n) { b[n - 1] = 0; SetLastError(ERROR_INSUFFICIENT_BUFFER); return n; }
    b[k] = 0; return k;
}

static BOOL full_image_name(HANDLE hp, DWORD flags, LPVOID buf, PDWORD size, BOOL wide)
{
    char path[MAX_PATH];
    DWORD len, wl;
    if (!size || !buf) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (flags & ~1u) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (flags & 1u) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }      /* PROCESS_NAME_NATIVE */
    if (is_self(hp)) { if (!GetModuleFileNameA(NULL, path, MAX_PATH)) return FALSE; }
    else if (!find_module(hp, NULL, path, NULL, NULL)) return FALSE;
    len = (DWORD)strlen(path);
    if (wide) {
        WCHAR tmp[MAX_PATH];
        wl = a_to_w(path, tmp, MAX_PATH);
        if (wl + 1 > *size) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        memcpy(buf, tmp, (wl + 1) * sizeof(WCHAR)); *size = wl;
    } else {
        if (len + 1 > *size) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        memcpy(buf, path, len + 1); *size = len;
    }
    return TRUE;
}

BOOL KEXAPI kex_QueryFullProcessImageNameA(HANDLE hp, DWORD f, LPSTR b, PDWORD s)  { return full_image_name(hp, f, b, s, FALSE); }
BOOL KEXAPI kex_QueryFullProcessImageNameW(HANDLE hp, DWORD f, LPWSTR b, PDWORD s) { return full_image_name(hp, f, b, s, TRUE); }

/* build 131: GetProcessImageFileName (K32 / PSAPI): the image path in NT device form ("\\Device\\HarddiskVolume1\\..."),
 * as NT gives it. Pale Moon 35's xul.dll imports K32GetProcessImageFileNameW statically ("linked to missing export"). */
DWORD KEXAPI kex_K32GetProcessImageFileNameW(HANDLE hp, LPWSTR b, DWORD n)
{
    char path[MAX_PATH], dev[MAX_PATH * 2], drv[3]; DWORD sz = MAX_PATH, len, k; WCHAR w[MAX_PATH * 2];
    DWORD KEXAPI kex_QueryDosDeviceA(LPCSTR name, LPSTR buf, DWORD cap);
    if (!b || !n) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!full_image_name(hp, 0, path, &sz, FALSE)) return 0;
    if (path[1] == ':') {
        drv[0] = path[0]; drv[1] = ':'; drv[2] = 0;
        if (!kex_QueryDosDeviceA(drv, dev, sizeof(dev))) lstrcpyA(dev, "\\Device\\HarddiskVolume1");
        lstrcatA(dev, path + 2);
    } else lstrcpynA(dev, path, sizeof(dev));
    len = (DWORD)MultiByteToWideChar(CP_ACP, 0, dev, -1, w, MAX_PATH * 2);
    if (!len) return 0;
    len--;
    if (len >= n) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
    for (k = 0; k <= len; k++) b[k] = w[k];
    return len;
}
DWORD KEXAPI kex_K32GetProcessImageFileNameA(HANDLE hp, LPSTR b, DWORD n)
{
    WCHAR w[MAX_PATH * 2]; DWORD r, k;
    if (!b || !n) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!(r = kex_K32GetProcessImageFileNameW(hp, w, MAX_PATH * 2))) return 0;
    k = (DWORD)WideCharToMultiByte(CP_ACP, 0, w, -1, b, (int)n, NULL, NULL);
    if (!k) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
    return k - 1;
}

/* ========================= Process / thread information ========================= */
#define MEMORY_PRIORITY_NORMAL_K 5

BOOL KEXAPI kex_SetThreadInformation(HANDLE h, int cls, LPVOID info, DWORD size)
{
    if (!info || cls < 0 || cls > 4) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return TRUE;      /* memory priority / power throttling / dynamic-code hints: no 9x equivalent */
}

BOOL KEXAPI kex_GetThreadInformation(HANDLE h, int cls, LPVOID info, DWORD size)
{
    if (!info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (cls == 0 /*ThreadMemoryPriority*/ && size >= sizeof(ULONG)) { *(ULONG *)info = MEMORY_PRIORITY_NORMAL_K; return TRUE; }
    SetLastError(ERROR_NOT_SUPPORTED); return FALSE;
}

BOOL KEXAPI kex_SetProcessInformation(HANDLE h, int cls, LPVOID info, DWORD size)
{
    if (!info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (cls == 0 /*ProcessMemoryPriority*/ || cls == 4 /*ProcessPowerThrottling*/) return TRUE;
    SetLastError(ERROR_NOT_SUPPORTED); return FALSE;
}

BOOL KEXAPI kex_GetProcessInformation(HANDLE h, int cls, LPVOID info, DWORD size)
{
    if (!info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (cls == 0 && size >= sizeof(ULONG)) { *(ULONG *)info = MEMORY_PRIORITY_NORMAL_K; return TRUE; }
    SetLastError(ERROR_NOT_SUPPORTED); return FALSE;
}

/* Every mitigation is OFF on 9x - reporting that is the truth. Turning one on is impossible. */
BOOL KEXAPI kex_GetProcessMitigationPolicy(HANDLE h, int policy, PVOID buf, SIZE_T len)
{
    if (!buf || !len) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    memset(buf, 0, len);
    return TRUE;
}
BOOL KEXAPI kex_SetProcessMitigationPolicy(int policy, PVOID buf, SIZE_T len) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
/* Windows 98 has no DEP: a system-wide state a program cannot change, as NT's AlwaysOff policy - NT then refuses with
 * ERROR_ACCESS_DENIED, which programs take for "set by the system" (build 131: Chromium's sandbox children treat any
 * other error as fatal, SBOX_FATAL_MITIGATION; ERROR_NOT_SUPPORTED made Firefox 115's content processes quit) */
BOOL KEXAPI kex_SetProcessDEPPolicy(DWORD flags) { (void)flags; SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
BOOL KEXAPI kex_GetProcessDEPPolicy(HANDLE h, LPDWORD flags, PBOOL permanent)
{
    if (!flags || !permanent) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *flags = 0; *permanent = FALSE;
    return TRUE;
}

/* Recorded only; the LOAD_LIBRARY_SEARCH_* search order is applied by the Phase 2 loader. */
static volatile DWORD g_default_dll_dirs;
BOOL KEXAPI kex_SetDefaultDllDirectories(DWORD flags)
{
    const DWORD valid = 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800 | 0x00001000;
    if (!flags || (flags & ~valid)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    g_default_dll_dirs = flags;
    return TRUE;
}
DWORD kex_GetDefaultDllDirectories(void) { return g_default_dll_dirs; }

/* ===================== Proc/thread attribute lists (storage) ===================== */
typedef struct { DWORD_PTR attr; SIZE_T size; PVOID value; } kex_pta_entry;
typedef struct { DWORD magic, count, max, reserved; kex_pta_entry e[1]; } kex_pta_list;
#define PTA_MAGIC 0x4154504B   /* 'KPTA' */

BOOL KEXAPI kex_InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST list, DWORD count, DWORD flags, PSIZE_T size)
{
    SIZE_T need;
    if (!size || flags || !count) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    need = FIELD_OFFSET(kex_pta_list, e) + count * sizeof(kex_pta_entry);
    if (!list || *size < need) { *size = need; SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    ((kex_pta_list *)list)->magic = PTA_MAGIC;
    ((kex_pta_list *)list)->count = 0;
    ((kex_pta_list *)list)->max = count;
    *size = need;
    return TRUE;
}

BOOL KEXAPI kex_UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST list, DWORD flags, DWORD_PTR attr,
                                          PVOID value, SIZE_T size, PVOID prev, PSIZE_T retsize)
{
    kex_pta_list *l = (kex_pta_list *)list;
    DWORD i;
    if (!l || l->magic != PTA_MAGIC || flags || !value) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < l->count; i++)
        if (l->e[i].attr == attr) { SetLastError(ERROR_ALREADY_EXISTS); return FALSE; }
    if (l->count >= l->max) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    l->e[l->count].attr = attr; l->e[l->count].size = size; l->e[l->count].value = value;
    l->count++;
    return TRUE;
}

VOID KEXAPI kex_DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST list)
{
    if (list && ((kex_pta_list *)list)->magic == PTA_MAGIC) ((kex_pta_list *)list)->magic = 0;
}

/* For the future CreateProcess path: look up an attribute (NULL if absent). */
PVOID kex_ProcThreadAttributeFind(LPPROC_THREAD_ATTRIBUTE_LIST list, DWORD_PTR attr, SIZE_T *size)
{
    kex_pta_list *l = (kex_pta_list *)list;
    DWORD i;
    if (!l || l->magic != PTA_MAGIC) return NULL;
    for (i = 0; i < l->count; i++)
        if (l->e[i].attr == attr) { if (size) *size = l->e[i].size; return l->e[i].value; }
    return NULL;
}

/* ================================ Miscellaneous ================================ */
BOOL KEXAPI kex_CheckRemoteDebuggerPresent(HANDLE hp, PBOOL present)
{
    if (!hp || !present) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *present = is_self(hp) ? IsDebuggerPresent() : FALSE;
    return TRUE;
}

BOOL KEXAPI kex_CompareObjectHandles(HANDLE a, HANDLE b) { return a == b; }

BOOL KEXAPI kex_GetProcessHandleCount(HANDLE h, PDWORD n)      { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
/* QueryThreadCycleTime / QueryProcessCycleTime: proctime_ext.c */

VOID KEXAPI kex_QueryInterruptTimePrecise(PULONGLONG t)         { kex_QueryUnbiasedInterruptTime(t); }
VOID KEXAPI kex_QueryUnbiasedInterruptTimePrecise(PULONGLONG t) { kex_QueryUnbiasedInterruptTime(t); }

/* Power requests -> SetThreadExecutionState (Win98+). The handle is a private event so
 * CloseHandle works. Note: 9x execution state is per calling thread, not per request. */
HANDLE KEXAPI kex_PowerCreateRequest(PVOID ctx) { return CreateEventA(NULL, TRUE, FALSE, NULL); }
BOOL KEXAPI kex_PowerSetRequest(HANDLE h, int type)
{
    EXECUTION_STATE es = ES_CONTINUOUS;
    if (!h) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    if (type == 0) es |= ES_DISPLAY_REQUIRED | ES_SYSTEM_REQUIRED;
    else if (type == 1 || type == 3) es |= ES_SYSTEM_REQUIRED;
    else if (type != 2) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }   /* 2 = AwayMode */
    SetThreadExecutionState(es);
    return TRUE;
}
BOOL KEXAPI kex_PowerClearRequest(HANDLE h, int type)
{
    if (!h) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    SetThreadExecutionState(ES_CONTINUOUS);
    return TRUE;
}

DWORD KEXAPI kex_GetDynamicTimeZoneInformation(PDYNAMIC_TIME_ZONE_INFORMATION d)
{
    TIME_ZONE_INFORMATION tz;
    DWORD r;
    if (!d) { SetLastError(ERROR_INVALID_PARAMETER); return TIME_ZONE_ID_INVALID; }
    r = GetTimeZoneInformation(&tz);
    if (r == TIME_ZONE_ID_INVALID) return r;
    memset(d, 0, sizeof(*d));
    d->Bias = tz.Bias; d->StandardBias = tz.StandardBias; d->DaylightBias = tz.DaylightBias;
    d->StandardDate = tz.StandardDate; d->DaylightDate = tz.DaylightDate;
    memcpy(d->StandardName, tz.StandardName, sizeof(d->StandardName));
    memcpy(d->DaylightName, tz.DaylightName, sizeof(d->DaylightName));
    memcpy(d->TimeZoneKeyName, tz.StandardName, sizeof(tz.StandardName));   /* registry key = std name on 9x */
    d->DynamicDaylightTimeDisabled = FALSE;
    return r;
}

HANDLE KEXAPI kex_CreateWaitableTimerExW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name, DWORD flags, DWORD access)
{
    char aname[MAX_PATH];
    if (flags & ~3u) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }   /* MANUAL_RESET | HIGH_RESOLUTION */
    if (name && !WideCharToMultiByte(CP_ACP, 0, name, -1, aname, MAX_PATH, NULL, NULL)) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE); return NULL;
    }
    return CreateWaitableTimerA(sa, (flags & 1) != 0, name ? aname : NULL);
}

HANDLE KEXAPI kex_CreateRemoteThreadEx(HANDLE hp, LPSECURITY_ATTRIBUTES sa, SIZE_T stack,
        LPTHREAD_START_ROUTINE fn, LPVOID param, DWORD flags, LPPROC_THREAD_ATTRIBUTE_LIST attrs, LPDWORD tid)
{
    if (!is_self(hp)) { SetLastError(ERROR_NOT_SUPPORTED); return NULL; }   /* no remote threads on 9x */
    return CreateThread(sa, stack, fn, param, flags & CREATE_SUSPENDED, tid);
}

/* CancelIo only cancels the calling thread's requests on 9x; that is what Chromium needs
 * (it cancels on the I/O thread that issued them). Overlapped filter is ignored. */

/* Must fail: success would make callers skip completion packets that 9x still queues. */
/* SetFileCompletionNotificationModes: iocp_ext.c */

BOOL  KEXAPI kex_PrefetchVirtualMemory(HANDLE hp, ULONG_PTR n, PVOID entries, ULONG flags) { return TRUE; }  /* hint */
/* DiscardVirtualMemory: "the contents are no longer needed". Leaving the pages as they are is a valid discard
 * (afterwards the contents are undefined), so committed memory answers ERROR_SUCCESS. Chromium discards
 * shared-memory views in the 9x shared arena (discardable_shared_memory.cc). */
SIZE_T KEXAPI kex_VirtualQuery(LPCVOID a, PMEMORY_BASIC_INFORMATION m, SIZE_T n);
DWORD KEXAPI kex_DiscardVirtualMemory(PVOID addr, SIZE_T size)
{
    MEMORY_BASIC_INFORMATION m;
    DWORD kex_discard_private(LPVOID addr, SIZE_T n);
    if (!addr || !size || !kex_VirtualQuery(addr, &m, sizeof(m)) || m.State != MEM_COMMIT) return ERROR_INVALID_PARAMETER;
    kex_discard_private(addr, size);             /* build 122: private memory really given back (mem_ext.c) */
    return ERROR_SUCCESS;
}


HRESULT KEXAPI kex_WerRegisterRuntimeExceptionModule(PCWSTR dll, PVOID ctx) { return E_NOTIMPL; }

/* No AppX/MSIX packages exist on 9x. */
LONG KEXAPI kex_GetPackagePathByFullName(PCWSTR full, UINT32 *len, PWSTR path) { return ERROR_NOT_FOUND; }
LONG KEXAPI kex_GetPackagesByPackageFamily(PCWSTR fam, UINT32 *count, PWSTR *names, UINT32 *buflen, WCHAR *buf)
{
    if (!count || !buflen) return ERROR_INVALID_PARAMETER;
    *count = 0; *buflen = 0;
    return ERROR_SUCCESS;
}

BOOL KEXAPI kex_GetConsoleDisplayMode(LPDWORD mode)
{
    if (!mode) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *mode = 0;                                    /* windowed */
    return TRUE;
}
