#include "../kexng_build.h"
/*
 * kextest.c - self-test for kexnt.dll. Loads kexnt.dll with LoadLibrary and calls the
 * exports through GetProcAddress, so it exercises OUR implementations even on a system
 * (Wine, NT) that has native versions. Imports only Win98 SE kernel32/msvcrt functions.
 *
 *   kextest.exe            run all tests (put kexnt.dll next to it)
 *   kextest.exe stress     same, 10x longer threaded loops
 * Exit code = number of failed checks. Output also goes to kextest.log.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <psapi.h>
#include <objbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FARPROC native_k32(const char *name)   /* KERNEL32's own export, found by walking its export table */
{
    BYTE *b = (BYTE *)GetModuleHandleA("KERNEL32.DLL");
    IMAGE_NT_HEADERS *nt; IMAGE_EXPORT_DIRECTORY *ex; DWORD *names, *funcs; WORD *ords; DWORD i;
    if (!b || ((IMAGE_DOS_HEADER *)b)->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    ex = (IMAGE_EXPORT_DIRECTORY *)(b + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names = (DWORD *)(b + ex->AddressOfNames); funcs = (DWORD *)(b + ex->AddressOfFunctions); ords = (WORD *)(b + ex->AddressOfNameOrdinals);
    for (i = 0; i < ex->NumberOfNames; i++)
        if (!strcmp((const char *)(b + names[i]), name)) return (FARPROC)(b + funcs[ords[i]]);
    return NULL;
}
static DWORD shared_free(void)   /* free bytes in the Windows 9x shared arena 80000000-BFFFFFFF */
{
    DWORD p = 0x80000000UL, fr = 0; MEMORY_BASIC_INFORMATION m;
    while (p < 0xC0000000UL && VirtualQuery((LPCVOID)p, &m, sizeof(m)) == sizeof(m) && m.RegionSize) {
        if (m.State == MEM_FREE) fr += (DWORD)m.RegionSize;
        p += (DWORD)m.RegionSize;
    }
    return fr;
}
static FILE *g_log;
static int g_fail, g_pass, g_scale = 1;

#define LOG(...) do { printf(__VA_ARGS__); if (g_log) { fprintf(g_log, __VA_ARGS__); fflush(g_log); } } while (0)
#define CHECK(c, ...) do { if (c) g_pass++; else { g_fail++; LOG("  FAIL %s:%d: ", __FILE__, __LINE__); LOG(__VA_ARGS__); LOG("\n"); } } while (0)

/* ---- function pointers resolved from kexnt.dll ---- */
static HMODULE kx;
#define FN(ret, name, args) static ret (WINAPI *p##name) args
FN(VOID, AcquireSRWLockExclusive, (PSRWLOCK));
FN(VOID, ReleaseSRWLockExclusive, (PSRWLOCK));
FN(VOID, AcquireSRWLockShared, (PSRWLOCK));
FN(VOID, ReleaseSRWLockShared, (PSRWLOCK));
FN(BOOLEAN, TryAcquireSRWLockExclusive, (PSRWLOCK));
FN(BOOLEAN, TryAcquireSRWLockShared, (PSRWLOCK));
FN(BOOL, SleepConditionVariableSRW, (PCONDITION_VARIABLE, PSRWLOCK, DWORD, ULONG));
FN(BOOL, SleepConditionVariableCS, (PCONDITION_VARIABLE, PCRITICAL_SECTION, DWORD));
FN(VOID, WakeConditionVariable, (PCONDITION_VARIABLE));
FN(VOID, WakeAllConditionVariable, (PCONDITION_VARIABLE));
FN(BOOL, WaitOnAddress, (volatile VOID *, PVOID, SIZE_T, DWORD));
FN(VOID, WakeByAddressSingle, (PVOID));
FN(VOID, WakeByAddressAll, (PVOID));
FN(BOOL, InitOnceExecuteOnce, (PINIT_ONCE, PINIT_ONCE_FN, PVOID, LPVOID *));
FN(BOOL, InitOnceBeginInitialize, (LPINIT_ONCE, DWORD, PBOOL, LPVOID *));
FN(BOOL, InitOnceComplete, (LPINIT_ONCE, DWORD, LPVOID));
FN(DWORD, FlsAlloc, (PFLS_CALLBACK_FUNCTION));
FN(BOOL, FlsFree, (DWORD));
FN(PVOID, FlsGetValue, (DWORD));
FN(BOOL, FlsSetValue, (DWORD, PVOID));
FN(BOOL, GetLogicalProcessorInformation, (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION, PDWORD));
FN(BOOL, GetLogicalProcessorInformationEx, (LOGICAL_PROCESSOR_RELATIONSHIP, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, PDWORD));
FN(DWORD, GetActiveProcessorCount, (WORD));
FN(BOOL, K32GetModuleInformation, (HANDLE, HMODULE, LPMODULEINFO, DWORD));
FN(BOOL, K32EnumProcessModules, (HANDLE, HMODULE *, DWORD, LPDWORD));
FN(DWORD, K32GetModuleFileNameExA, (HANDLE, HMODULE, LPSTR, DWORD));
FN(DWORD, K32GetModuleBaseNameA, (HANDLE, HMODULE, LPSTR, DWORD));
FN(BOOL, K32GetProcessMemoryInfo, (HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD));
FN(BOOL, K32QueryWorkingSetEx, (HANDLE, PVOID, DWORD));
FN(BOOL, QueryFullProcessImageNameW, (HANDLE, DWORD, LPWSTR, PDWORD));
FN(BOOL, InitializeProcThreadAttributeList, (LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T));
FN(BOOL, UpdateProcThreadAttribute, (LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T));
FN(VOID, DeleteProcThreadAttributeList, (LPPROC_THREAD_ATTRIBUTE_LIST));
FN(VOID, GetCurrentThreadStackLimits, (PULONG_PTR, PULONG_PTR));
FN(ULONGLONG, GetTickCount64, (void));
FN(VOID, GetSystemTimePreciseAsFileTime, (LPFILETIME));
FN(BOOL, GetProductInfo, (DWORD, DWORD, DWORD, DWORD, PDWORD));
/* Phase 3b locale-name APIs */
typedef BOOL (CALLBACK *kt_LOCALE_ENUMPROCEX)(LPWSTR, DWORD, LPARAM);
FN(int, LCIDToLocaleName, (LCID, LPWSTR, int, DWORD));
FN(LCID, LocaleNameToLCID, (LPCWSTR, DWORD));
FN(int, GetUserDefaultLocaleName, (LPWSTR, int));
FN(int, GetSystemDefaultLocaleName, (LPWSTR, int));
FN(BOOL, IsValidLocaleName, (LPCWSTR));
FN(int, ResolveLocaleName, (LPCWSTR, LPWSTR, int));
FN(BOOL, EnumSystemLocalesEx, (kt_LOCALE_ENUMPROCEX, DWORD, LPARAM, LPVOID));
FN(int, GetLocaleInfoEx, (LPCWSTR, LCTYPE, LPWSTR, int));
FN(int, GetNumberFormatEx, (LPCWSTR, DWORD, LPCWSTR, const NUMBERFMTW *, LPWSTR, int));
FN(int, GetCurrencyFormatEx, (LPCWSTR, DWORD, LPCWSTR, const CURRENCYFMTW *, LPWSTR, int));
FN(int, GetDateFormatEx, (LPCWSTR, DWORD, const SYSTEMTIME *, LPCWSTR, LPWSTR, int, LPCWSTR));
FN(int, GetTimeFormatEx, (LPCWSTR, DWORD, const SYSTEMTIME *, LPCWSTR, LPWSTR, int));
FN(int, CompareStringEx, (LPCWSTR, DWORD, LPCWSTR, int, LPCWSTR, int, LPVOID, LPVOID, LPARAM));
FN(int, LCMapStringEx, (LPCWSTR, DWORD, LPCWSTR, int, LPWSTR, int, LPVOID, LPVOID, LPARAM));
FN(int, CompareStringOrdinal, (LPCWSTR, int, LPCWSTR, int, BOOL));
FN(BOOL, GetUserPreferredUILanguages, (DWORD, PULONG, PZZWSTR, PULONG));
FN(BOOL, SetThreadPreferredUILanguages, (DWORD, PCZZWSTR, PULONG));
FN(DWORD, KexNlsUnicodeBackend, (void));
/* vectored exception handling */
FN(PVOID, AddVectoredExceptionHandler, (ULONG, PVECTORED_EXCEPTION_HANDLER));
FN(ULONG, RemoveVectoredExceptionHandler, (PVOID));
FN(PVOID, AddVectoredContinueHandler, (ULONG, PVECTORED_EXCEPTION_HANDLER));
FN(ULONG, RemoveVectoredContinueHandler, (PVOID));
FN(LONG, KexVehState, (void));

static int resolve(void)
{
    int missing = 0;
#define R(name) do { *(FARPROC *)&p##name = GetProcAddress(kx, #name); if (!p##name) { LOG("  missing export %s\n", #name); missing++; } } while (0)
    R(AcquireSRWLockExclusive); R(ReleaseSRWLockExclusive); R(AcquireSRWLockShared); R(ReleaseSRWLockShared);
    R(TryAcquireSRWLockExclusive); R(TryAcquireSRWLockShared); R(SleepConditionVariableSRW); R(SleepConditionVariableCS);
    R(WakeConditionVariable); R(WakeAllConditionVariable); R(WaitOnAddress); R(WakeByAddressSingle); R(WakeByAddressAll);
    R(InitOnceExecuteOnce); R(InitOnceBeginInitialize); R(InitOnceComplete);
    R(FlsAlloc); R(FlsFree); R(FlsGetValue); R(FlsSetValue);
    R(GetLogicalProcessorInformation); R(GetLogicalProcessorInformationEx); R(GetActiveProcessorCount);
    R(K32GetModuleInformation); R(K32EnumProcessModules); R(K32GetModuleFileNameExA); R(K32GetModuleBaseNameA);
    R(K32GetProcessMemoryInfo); R(QueryFullProcessImageNameW); R(K32QueryWorkingSetEx);
    R(InitializeProcThreadAttributeList); R(UpdateProcThreadAttribute); R(DeleteProcThreadAttributeList);
    R(GetCurrentThreadStackLimits); R(GetTickCount64); R(GetSystemTimePreciseAsFileTime); R(GetProductInfo);
    R(LCIDToLocaleName); R(LocaleNameToLCID); R(GetUserDefaultLocaleName); R(GetSystemDefaultLocaleName);
    R(IsValidLocaleName); R(ResolveLocaleName); R(EnumSystemLocalesEx); R(GetLocaleInfoEx);
    R(GetNumberFormatEx); R(GetCurrencyFormatEx); R(GetDateFormatEx); R(GetTimeFormatEx);
    R(CompareStringEx); R(LCMapStringEx); R(CompareStringOrdinal); R(GetUserPreferredUILanguages);
    R(SetThreadPreferredUILanguages); R(KexNlsUnicodeBackend);
    R(AddVectoredExceptionHandler); R(RemoveVectoredExceptionHandler); R(AddVectoredContinueHandler);
    R(RemoveVectoredContinueHandler); R(KexVehState);
    return missing;
}

static void run_threads(int n, LPTHREAD_START_ROUTINE fn, void *arg)
{
    HANDLE h[16];
    DWORD tid;
    int i;
    for (i = 0; i < n; i++) h[i] = CreateThread(NULL, 0, fn, arg, 0, &tid);
    for (i = 0; i < n; i++) { WaitForSingleObject(h[i], INFINITE); CloseHandle(h[i]); }
}

/* ------------------------------- SRW ------------------------------- */
static SRWLOCK g_srw;
static volatile LONG g_counter, g_a, g_b, g_torn;

static DWORD WINAPI srw_excl_worker(LPVOID p)
{
    int i, n = 20000 * g_scale;
    for (i = 0; i < n; i++) {
        pAcquireSRWLockExclusive(&g_srw);
        LONG v = g_counter; if ((i & 63) == 0) Sleep(0); g_counter = v + 1;
        pReleaseSRWLockExclusive(&g_srw);
    }
    return 0;
}

static DWORD WINAPI srw_mixed_worker(LPVOID p)
{
    int i, n = 10000 * g_scale, writer = (int)(INT_PTR)p;
    for (i = 0; i < n; i++) {
        if ((i % 4) == 0 || writer) {
            pAcquireSRWLockExclusive(&g_srw);
            g_a++; if ((i & 31) == 0) Sleep(0); g_b++;
            pReleaseSRWLockExclusive(&g_srw);
        } else {
            pAcquireSRWLockShared(&g_srw);
            if (g_a != g_b) InterlockedIncrement(&g_torn);
            pReleaseSRWLockShared(&g_srw);
        }
    }
    return 0;
}

static void test_srw(void)
{
    LOG("[srw]\n");
    g_srw.Ptr = NULL; g_counter = 0;
    run_threads(4, srw_excl_worker, NULL);
    CHECK(g_counter == 4 * 20000 * g_scale, "exclusive counter %ld", g_counter);
    CHECK(g_srw.Ptr == NULL, "lock word not clean after use: %p", g_srw.Ptr);

    g_a = g_b = g_torn = 0;
    {
        HANDLE h[4]; DWORD t; int i;
        for (i = 0; i < 4; i++) h[i] = CreateThread(NULL, 0, srw_mixed_worker, (LPVOID)(INT_PTR)(i == 0), 0, &t);
        for (i = 0; i < 4; i++) { WaitForSingleObject(h[i], INFINITE); CloseHandle(h[i]); }
    }
    CHECK(g_torn == 0, "readers saw torn state %ld times", g_torn);
    CHECK(g_a == g_b, "a=%ld b=%ld", g_a, g_b);
    CHECK(g_srw.Ptr == NULL, "lock word not clean after mixed use: %p", g_srw.Ptr);

    CHECK(pTryAcquireSRWLockExclusive(&g_srw), "try excl on free lock");
    CHECK(!pTryAcquireSRWLockShared(&g_srw), "try shared while excl held");
    CHECK(!pTryAcquireSRWLockExclusive(&g_srw), "try excl while excl held");
    pReleaseSRWLockExclusive(&g_srw);
    CHECK(pTryAcquireSRWLockShared(&g_srw) && pTryAcquireSRWLockShared(&g_srw), "two shared");
    CHECK(!pTryAcquireSRWLockExclusive(&g_srw), "try excl while shared held");
    pReleaseSRWLockShared(&g_srw); pReleaseSRWLockShared(&g_srw);
    CHECK(g_srw.Ptr == NULL, "lock word after try tests: %p", g_srw.Ptr);

    SetLastError(1234);
    pAcquireSRWLockExclusive(&g_srw); pReleaseSRWLockExclusive(&g_srw);
    CHECK(GetLastError() == 1234, "SRW clobbered last error (%lu)", GetLastError());
}

/* --------------------------- condition variables --------------------------- */
#define QCAP 8
static CONDITION_VARIABLE g_not_empty, g_not_full;
static int g_q[QCAP], g_qh, g_qn;
static volatile LONG g_sum_in, g_sum_out, g_items_left;
static CRITICAL_SECTION g_cs;

static DWORD WINAPI producer(LPVOID p)
{
    int i, n = 5000 * g_scale;
    for (i = 1; i <= n; i++) {
        pAcquireSRWLockExclusive(&g_srw);
        while (g_qn == QCAP) pSleepConditionVariableSRW(&g_not_full, &g_srw, INFINITE, 0);
        g_q[(g_qh + g_qn++) % QCAP] = i;
        InterlockedExchangeAdd(&g_sum_in, i);
        pReleaseSRWLockExclusive(&g_srw);
        pWakeConditionVariable(&g_not_empty);
    }
    return 0;
}

static DWORD WINAPI consumer(LPVOID p)
{
    for (;;) {
        int v;
        pAcquireSRWLockExclusive(&g_srw);
        while (g_qn == 0 && g_items_left > 0) pSleepConditionVariableSRW(&g_not_empty, &g_srw, 100, 0);
        if (g_qn == 0) { pReleaseSRWLockExclusive(&g_srw); return 0; }
        v = g_q[g_qh]; g_qh = (g_qh + 1) % QCAP; g_qn--;
        g_items_left--;
        pReleaseSRWLockExclusive(&g_srw);
        pWakeConditionVariable(&g_not_full);
        InterlockedExchangeAdd(&g_sum_out, v);
    }
}

static volatile LONG g_cs_flag;
static DWORD WINAPI cs_waker(LPVOID p)
{
    Sleep(30);
    EnterCriticalSection(&g_cs); g_cs_flag = 1; LeaveCriticalSection(&g_cs);
    pWakeAllConditionVariable(&g_not_empty);
    return 0;
}

static void test_cv(void)
{
    HANDLE h[4]; DWORD t, t0, el; int i; BOOL r;
    LOG("[condition variables]\n");
    g_srw.Ptr = NULL; g_not_empty.Ptr = g_not_full.Ptr = NULL;
    g_qh = g_qn = 0; g_sum_in = g_sum_out = 0; g_items_left = 2 * 5000 * g_scale;
    h[0] = CreateThread(NULL, 0, producer, NULL, 0, &t);
    h[1] = CreateThread(NULL, 0, producer, NULL, 0, &t);
    h[2] = CreateThread(NULL, 0, consumer, NULL, 0, &t);
    h[3] = CreateThread(NULL, 0, consumer, NULL, 0, &t);
    for (i = 0; i < 4; i++) { CHECK(WaitForSingleObject(h[i], 60000) == WAIT_OBJECT_0, "pc thread %d hung", i); CloseHandle(h[i]); }
    {   /* 2 producers x (1..n): n*(n+1) exceeds 2^31 at scale 10 -> compare modulo 2^32 like the LONG sums */
        ULONGLONG n = 5000ULL * g_scale;
        LONG expect = (LONG)(DWORD)(n * (n + 1));
        CHECK(g_sum_in == g_sum_out && g_sum_in == expect,
              "producer/consumer sums in=%ld out=%ld expected=%ld", g_sum_in, g_sum_out, expect);
    }

    pAcquireSRWLockExclusive(&g_srw);
    t0 = GetTickCount();
    r = pSleepConditionVariableSRW(&g_not_empty, &g_srw, 60, 0);
    el = GetTickCount() - t0;
    CHECK(!r && GetLastError() == ERROR_TIMEOUT, "CV timeout result %d err %lu", r, GetLastError());
    CHECK(el >= 40 && el < 2000, "CV timeout elapsed %lu ms", el);
    CHECK(!pTryAcquireSRWLockExclusive(&g_srw), "lock not reacquired after CV timeout");
    pReleaseSRWLockExclusive(&g_srw);

    InitializeCriticalSection(&g_cs);
    g_cs_flag = 0;
    h[0] = CreateThread(NULL, 0, cs_waker, NULL, 0, &t);
    EnterCriticalSection(&g_cs);
    while (!g_cs_flag) if (!pSleepConditionVariableCS(&g_not_empty, &g_cs, 5000)) break;
    CHECK(g_cs_flag == 1, "SleepConditionVariableCS never woke");
    LeaveCriticalSection(&g_cs);
    WaitForSingleObject(h[0], INFINITE); CloseHandle(h[0]);
    DeleteCriticalSection(&g_cs);
}

/* ------------------------------ WaitOnAddress ------------------------------ */
static volatile LONG g_addr;
static volatile LONGLONG g_addr64;
static DWORD WINAPI addr_waker(LPVOID p)
{
    Sleep(30);
    InterlockedExchange(&g_addr, 1);
    pWakeByAddressSingle((PVOID)&g_addr);
    return 0;
}

static void test_wait_on_address(void)
{
    LONG cmp = 5; LONGLONG cmp64 = 7; HANDLE h; DWORD t, t0, el; BOOL r;
    LOG("[WaitOnAddress]\n");
    g_addr = 0;
    CHECK(pWaitOnAddress(&g_addr, &cmp, 4, INFINITE), "differing value must return TRUE at once");
    cmp = 0; t0 = GetTickCount();
    r = pWaitOnAddress(&g_addr, &cmp, 4, 50); el = GetTickCount() - t0;
    CHECK(!r && GetLastError() == ERROR_TIMEOUT, "timeout r=%d err=%lu", r, GetLastError());
    CHECK(el >= 30, "timeout elapsed %lu", el);
    h = CreateThread(NULL, 0, addr_waker, NULL, 0, &t);
    while (g_addr == 0) pWaitOnAddress(&g_addr, &cmp, 4, 5000);
    CHECK(g_addr == 1, "woken by WakeByAddressSingle");
    WaitForSingleObject(h, INFINITE); CloseHandle(h);
    g_addr64 = 0x100000000LL;
    CHECK(pWaitOnAddress(&g_addr64, &cmp64, 8, 0), "8-byte differing compare");
    cmp64 = 0x100000000LL;
    CHECK(!pWaitOnAddress(&g_addr64, &cmp64, 8, 0), "8-byte equal compare with 0 timeout must time out");
    CHECK(!pWaitOnAddress(&g_addr, &cmp, 3, 0) && GetLastError() == ERROR_INVALID_PARAMETER, "size 3 rejected");
}

/* --------------------------------- InitOnce -------------------------------- */
static INIT_ONCE g_once;
static volatile LONG g_once_calls, g_once_ok;
static BOOL CALLBACK once_fn(PINIT_ONCE o, PVOID param, PVOID *ctx)
{
    InterlockedIncrement(&g_once_calls);
    Sleep(20);
    *ctx = (PVOID)0x1230;
    return TRUE;
}
static DWORD WINAPI once_worker(LPVOID p)
{
    LPVOID ctx = NULL;
    if (pInitOnceExecuteOnce(&g_once, once_fn, NULL, &ctx) && ctx == (PVOID)0x1230) InterlockedIncrement(&g_once_ok);
    return 0;
}
static int g_fail_first;
static BOOL CALLBACK once_fail_fn(PINIT_ONCE o, PVOID param, PVOID *ctx) { return g_fail_first++ > 0; }

static void test_init_once(void)
{
    INIT_ONCE o = INIT_ONCE_STATIC_INIT; BOOL pending; LPVOID ctx;
    LOG("[InitOnce]\n");
    g_once.Ptr = NULL; g_once_calls = g_once_ok = 0;
    run_threads(8, once_worker, NULL);
    CHECK(g_once_calls == 1, "init fn called %ld times", g_once_calls);
    CHECK(g_once_ok == 8, "%ld/8 threads saw the context", g_once_ok);

    g_fail_first = 0;
    CHECK(!pInitOnceExecuteOnce(&o, once_fail_fn, NULL, NULL), "failing init returns FALSE");
    CHECK(pInitOnceExecuteOnce(&o, once_fail_fn, NULL, NULL), "retry after failure succeeds");

    o.Ptr = NULL;
    CHECK(!pInitOnceBeginInitialize(&o, INIT_ONCE_CHECK_ONLY, &pending, &ctx), "check-only on uninitialised fails");
    CHECK(pInitOnceBeginInitialize(&o, INIT_ONCE_ASYNC, &pending, &ctx) && pending, "async begin #1");
    CHECK(pInitOnceBeginInitialize(&o, INIT_ONCE_ASYNC, &pending, &ctx) && pending, "async begin #2 (parallel allowed)");
    CHECK(pInitOnceComplete(&o, INIT_ONCE_ASYNC, (LPVOID)0x40), "async complete #1 wins");
    CHECK(!pInitOnceComplete(&o, INIT_ONCE_ASYNC, (LPVOID)0x80), "async complete #2 loses");
    CHECK(pInitOnceBeginInitialize(&o, INIT_ONCE_CHECK_ONLY, &pending, &ctx) && !pending && ctx == (LPVOID)0x40,
          "check-only after async completion (ctx=%p)", ctx);
    CHECK(!pInitOnceComplete(&o, 0, (LPVOID)0x41), "misaligned context rejected");
}

/* ----------------------------------- FLS ----------------------------------- */
static volatile LONG g_fls_cb_calls; static volatile PVOID g_fls_cb_last;
static void WINAPI fls_cb(PVOID v) { InterlockedIncrement(&g_fls_cb_calls); g_fls_cb_last = v; }
static DWORD g_fls_idx;
static DWORD WINAPI fls_worker(LPVOID p)
{
    if (pFlsGetValue(g_fls_idx) != NULL) return 1;          /* fresh thread starts empty */
    pFlsSetValue(g_fls_idx, p);
    return pFlsGetValue(g_fls_idx) == p ? 0 : 2;
}

static void test_fls(void)
{
    HANDLE h; DWORD t, code = 99;
    LOG("[FLS]\n");
    g_fls_idx = pFlsAlloc(fls_cb);
    CHECK(g_fls_idx != FLS_OUT_OF_INDEXES && g_fls_idx != 0, "FlsAlloc index %lu", g_fls_idx);
    SetLastError(77);
    CHECK(pFlsGetValue(g_fls_idx) == NULL && GetLastError() == 0, "unset value is NULL with error 0");
    CHECK(pFlsSetValue(g_fls_idx, (PVOID)0x11) && pFlsGetValue(g_fls_idx) == (PVOID)0x11, "set/get main thread");
    g_fls_cb_calls = 0;
    h = CreateThread(NULL, 0, fls_worker, (LPVOID)0x22, 0, &t);
    WaitForSingleObject(h, INFINITE); GetExitCodeThread(h, &code); CloseHandle(h);
    CHECK(code == 0, "worker FLS isolation code %lu", code);
    CHECK(g_fls_cb_calls == 1 && g_fls_cb_last == (PVOID)0x22, "thread-exit callback calls=%ld last=%p", g_fls_cb_calls, g_fls_cb_last);
    CHECK(pFlsGetValue(g_fls_idx) == (PVOID)0x11, "main value untouched by worker");
    CHECK(pFlsFree(g_fls_idx), "FlsFree");
    CHECK(g_fls_cb_calls == 2 && g_fls_cb_last == (PVOID)0x11, "FlsFree runs callback for live values (calls=%ld)", g_fls_cb_calls);
    CHECK(pFlsGetValue(g_fls_idx) == NULL && GetLastError() == ERROR_INVALID_PARAMETER, "freed index rejected");
    CHECK(!pFlsSetValue(1000, NULL), "out-of-range index rejected");
}

/* ------------------------------ system / psapi ------------------------------ */
static void test_sysinfo(void)
{
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION lpi[16]; DWORD len = 0, i, cores = 0, caches = 0;
    BYTE exbuf[2048]; HMODULE mods[256]; MODULEINFO mi; char path[MAX_PATH], self[MAX_PATH];
    WCHAR wpath[MAX_PATH]; DWORD n; PROCESS_MEMORY_COUNTERS pmc; ULONG_PTR lo, hi; int local;
    FILETIME a, b; ULONGLONG ua, ub; DWORD type = 0;
    LOG("[sysinfo / psapi]\n");
    CHECK(!pGetLogicalProcessorInformation(NULL, &len) && GetLastError() == ERROR_INSUFFICIENT_BUFFER && len, "LPI size query");
    CHECK(len <= sizeof(lpi) && pGetLogicalProcessorInformation(lpi, &len), "LPI fill (len %lu)", len);
    for (i = 0; i < len / sizeof(lpi[0]); i++) {
        if (lpi[i].Relationship == RelationProcessorCore) cores++;
        if (lpi[i].Relationship == RelationCache) {
            caches++;
            LOG("    cache L%u %s %lu KB line %u assoc %u\n", lpi[i].Cache.Level,
                lpi[i].Cache.Type == CacheData ? "D" : lpi[i].Cache.Type == CacheInstruction ? "I" : "U",
                lpi[i].Cache.Size / 1024, lpi[i].Cache.LineSize, lpi[i].Cache.Associativity);
        }
    }
    CHECK(cores == 1, "cores %lu", cores);
    {   /* process CPU times on a duplicated handle of this process (Chrome's ProcessMetrics) */
        typedef BOOL (WINAPI *T_GPT)(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME);
        typedef BOOL (WINAPI *T_QPC)(HANDLE, PULONG64);
        T_GPT gpt = (T_GPT)(void *)GetProcAddress(kx, "GetProcessTimes");
        T_QPC qpc = (T_QPC)(void *)GetProcAddress(kx, "QueryProcessCycleTime");
        HANDLE dup = NULL; FILETIME c, e, k, u; ULONG64 cyc = 0; BOOL ok1, ok2;
        DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &dup, PROCESS_QUERY_INFORMATION, FALSE, 0);
        ok1 = gpt && dup && gpt(dup, &c, &e, &k, &u);
        ok2 = qpc && dup && qpc(dup, &cyc);
        LOG("    GetProcessTimes %d: created %08lx%08lx kernel %lu user %lu (100 ns), cycles %lu\n", ok1,
            ok1 ? c.dwHighDateTime : 0, ok1 ? c.dwLowDateTime : 0, ok1 ? k.dwLowDateTime : 0, ok1 ? u.dwLowDateTime : 0, (unsigned long)cyc);
        CHECK(ok1 && (c.dwHighDateTime || c.dwLowDateTime), "GetProcessTimes on a duplicated process handle");
        CHECK(ok2, "QueryProcessCycleTime on a duplicated process handle");
        if (dup) CloseHandle(dup);
    }
    {   /* NTDLL token functions and NtQuerySection, looked up the way programs do (GetProcAddress on ntdll) */
        typedef LONG (WINAPI *T_QS)(HANDLE, ULONG, PVOID, SIZE_T, PSIZE_T);
        typedef LONG (WINAPI *T_OPT)(HANDLE, DWORD, PHANDLE);
        typedef LONG (WINAPI *T_QIT)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        typedef LONG (WINAPI *T_NC)(HANDLE);
        HMODULE nt = LoadLibraryA("NTDLL.DLL");             /* kextest itself does not import NTDLL */
        T_QS qs = nt ? (T_QS)(void *)GetProcAddress(nt, "NtQuerySection") : NULL;
        T_OPT opt = nt ? (T_OPT)(void *)GetProcAddress(nt, "NtOpenProcessToken") : NULL;
        T_QIT qit = nt ? (T_QIT)(void *)GetProcAddress(nt, "NtQueryInformationToken") : NULL;
        T_NC nc = nt ? (T_NC)(void *)GetProcAddress(nt, "NtClose") : NULL;
        FARPROC mine = GetProcAddress(kx, "NtQuerySection");
        HANDLE sec = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 65536, NULL), tok = NULL;
        DWORD info[4] = { 0, 0, 0, 0 }, elev = 0; SIZE_T got = 0; ULONG got2 = 0; LONG s1 = -1, s2 = -1, s3 = -1, s4 = -1;
        LOG("    ntdll %p: NtQuerySection %p (kexnt's %p), NtOpenProcessToken %p\n", (void *)nt, (void *)qs, (void *)mine, (void *)opt);
        {   /* the installed kexnt (C:\\WINDOWS\\KERNELEX) answers routed lookups; kx may be a test copy */
            MEMORY_BASIC_INFORMATION mb; char mod[MAX_PATH] = ""; int l;
            if (qs && VirtualQuery((void *)qs, &mb, sizeof(mb))) GetModuleFileNameA((HMODULE)mb.AllocationBase, mod, MAX_PATH);
            l = lstrlenA(mod);
            LOG("    NtQuerySection comes from %s\n", mod[0] ? mod : "(nowhere)");
            CHECK(l >= 9 && !lstrcmpiA(mod + l - 9, "KEXNT.DLL"), "GetProcAddress(ntdll, NtQuerySection) gives kexnt's");
            if (l >= 9 && !lstrcmpiA(mod + l - 9, "KEXNT.DLL") && sec) s1 = qs(sec, 0, info, sizeof(info), &got);
        }
        LOG("    NtQuerySection: status %08lx attributes %08lx size %lu\n", (unsigned long)s1, info[1], info[2]);
        CHECK(s1 == 0 && !(info[1] & 0x1000000) && info[2] >= 65536, "NtQuerySection on a 64 KB section");
        if (sec) CloseHandle(sec);
        if (opt) s2 = opt(GetCurrentProcess(), 8 /* TOKEN_QUERY */, &tok);
        if (!s2 && qit) s3 = qit(tok, 20 /* TokenElevation */, &elev, sizeof(elev), &got2);
        if (!s2 && nc) s4 = nc(tok);
        LOG("    NtOpenProcessToken %08lx, TokenElevation %08lx = %lu, NtClose %08lx\n", (unsigned long)s2, (unsigned long)s3, elev, (unsigned long)s4);
        CHECK(s2 == 0 && s3 == 0 && elev == 1 && s4 == 0, "NtOpenProcessToken / NtQueryInformationToken / NtClose");
    }
    {   /* kernel32.dll's file version follows the NT profile (Chromium's OSInfo::Kernel32Version) */
        typedef BOOL (WINAPI *T_GFV)(LPCWSTR, DWORD, DWORD, LPVOID);
        typedef VOID (WINAPI *T_SNV)(DWORD, DWORD, DWORD);
        T_GFV gfv = (T_GFV)(void *)GetProcAddress(kx, "GetFileVersionInfoW");
        T_SNV snv = (T_SNV)(void *)GetProcAddress(kx, "KexSetNtVersion");
        WCHAR wp[MAX_PATH]; char ap[MAX_PATH];
        DWORD sz, i, ms = 0, ls = 0; BYTE *buf; BOOL ok;
        GetSystemDirectoryA(ap, MAX_PATH - 16); lstrcatA(ap, "\\KERNEL32.DLL");
        MultiByteToWideChar(CP_ACP, 0, ap, -1, wp, MAX_PATH);
        sz = GetFileVersionInfoSizeW(wp, NULL);
        buf = sz ? (BYTE *)malloc(sz) : NULL;
        if (snv) snv(10, 0, 19044);                               /* what the api-ms shells pass under Windows 10 21H2 */
        ok = buf && gfv && gfv(wp, 0, sz, buf);
        LOG("    GetFileVersionInfoW: size %lu, result %d, error %lu\n", sz, ok, ok ? 0 : GetLastError());
        if (ok)
            for (i = 0; i + 16 <= sz; i += 4) if (*(DWORD *)(buf + i) == 0xFEEF04BDUL) { ms = *(DWORD *)(buf + i + 8); ls = *(DWORD *)(buf + i + 12); break; }
        LOG("    GetFileVersionInfoW(KERNEL32.DLL) under a 10.0.19044 profile: %lu.%lu.%lu.%lu\n", ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF);
        CHECK(ms == 0x000A0000 && (ls >> 16) == 19044, "kernel32.dll file version follows the NT profile");
        free(buf);
    }
    {   /* the user's identity: token user SID as a string and back (Chrome's per-user registry suffix) */
        typedef BOOL (WINAPI *T_GTI)(HANDLE, DWORD, LPVOID, DWORD, PDWORD);
        typedef BOOL (WINAPI *T_S2W)(PSID, LPWSTR *);
        typedef BOOL (WINAPI *T_W2S)(LPCWSTR, PSID *);
        T_GTI gti = (T_GTI)(void *)GetProcAddress(kx, "GetTokenInformation");
        T_S2W s2w = (T_S2W)(void *)GetProcAddress(kx, "ConvertSidToStringSidW");
        T_W2S w2s = (T_W2S)(void *)GetProcAddress(kx, "ConvertStringSidToSidW");
        DWORD need = 0, buf[32]; LPWSTR str = NULL; PSID back = NULL; char a[64] = "";
        BOOL ok1 = FALSE, ok2 = FALSE, ok3 = FALSE, small;
        small = gti && !gti((HANDLE)(ULONG_PTR)0xCAFE, 1 /* TokenUser */, NULL, 0, &need) && GetLastError() == ERROR_INSUFFICIENT_BUFFER;
        if (gti && need <= sizeof(buf)) ok1 = gti((HANDLE)(ULONG_PTR)0xCAFE, 1, buf, sizeof(buf), &need);
        if (ok1 && s2w) ok2 = s2w((PSID)(ULONG_PTR)buf[0], &str);
        if (ok2) WideCharToMultiByte(CP_ACP, 0, str, -1, a, sizeof(a), NULL, NULL);
        if (ok2 && w2s) ok3 = w2s(str, &back) && EqualSid(back, (PSID)(ULONG_PTR)buf[0]);
        LOG("    token user: size query %d (%lu bytes), SID %s, back to SID %d\n", small, need, a, ok3);
        CHECK(small && ok1 && !lstrcmpA(a, "S-1-5-21-0-0-0-1000") && ok3, "token user SID as a string and back");
        if (str) LocalFree(str);
        if (back) LocalFree(back);
    }
    {   /* KernelEx 4.5.2 stubs Chrome imports: computer name, ReplaceFile */
        typedef BOOL (WINAPI *T_CNX)(int, LPWSTR, LPDWORD);
        typedef BOOL (WINAPI *T_RF)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPVOID, LPVOID);
        T_CNX cnx = (T_CNX)(void *)GetProcAddress(kx, "GetComputerNameExW");
        T_RF rf = (T_RF)(void *)GetProcAddress(kx, "ReplaceFileW");
        WCHAR nm[64]; DWORD n = 64; char got[16] = ""; HANDLE f; DWORD w; BOOL ok1, ok2 = FALSE;
        ok1 = cnx && cnx(0 /* ComputerNameNetBIOS */, nm, &n) && n > 0;
        LOG("    GetComputerNameExW: %d, %lu characters\n", ok1, n);
        CHECK(ok1, "GetComputerNameExW (NetBIOS name)");
        f = CreateFileA("C:\\KEXTEST\\RF_OLD.TMP", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) { WriteFile(f, "old", 3, &w, NULL); CloseHandle(f); }
        f = CreateFileA("C:\\KEXTEST\\RF_NEW.TMP", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) { WriteFile(f, "new", 3, &w, NULL); CloseHandle(f); }
        if (rf && rf(L"C:\\KEXTEST\\RF_OLD.TMP", L"C:\\KEXTEST\\RF_NEW.TMP", NULL, 0, NULL, NULL)) {
            f = CreateFileA("C:\\KEXTEST\\RF_OLD.TMP", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (f != INVALID_HANDLE_VALUE) { ReadFile(f, got, 3, &w, NULL); CloseHandle(f); }
            ok2 = !lstrcmpA(got, "new") && GetFileAttributesA("C:\\KEXTEST\\RF_NEW.TMP") == 0xFFFFFFFF;
        }
        LOG("    ReplaceFileW: content now \"%s\"\n", got);
        CHECK(ok2, "ReplaceFileW replaces the file");
        DeleteFileA("C:\\KEXTEST\\RF_OLD.TMP"); DeleteFileA("C:\\KEXTEST\\RF_NEW.TMP");
    }
    {   /* read-only shared memory stays read-only (Chromium's PlatformSharedMemoryRegion check) */
        typedef HANDLE (WINAPI *T_CFM)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
        typedef BOOL (WINAPI *T_DH)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
        typedef BOOL (WINAPI *T_CH)(HANDLE);
        T_CFM cfm = (T_CFM)(void *)GetProcAddress(kx, "CreateFileMappingA");
        T_DH dh = (T_DH)(void *)GetProcAddress(kx, "DuplicateHandle");
        T_CH ch = (T_CH)(void *)GetProcAddress(kx, "CloseHandle");
        HANDLE w = NULL, ro = NULL, w2 = NULL, rw = NULL; BOOL ok1 = FALSE, ok2 = FALSE, ok3 = FALSE;
        if (cfm && dh && ch) {
            w = cfm(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, NULL);
            ok1 = w && dh(GetCurrentProcess(), w, GetCurrentProcess(), &rw, FILE_MAP_READ | FILE_MAP_WRITE | 1, FALSE, 0);
            ok2 = w && dh(GetCurrentProcess(), w, GetCurrentProcess(), &ro, FILE_MAP_READ | 1 /* SECTION_QUERY */, FALSE, DUPLICATE_CLOSE_SOURCE);
            ok3 = ok2 && !dh(GetCurrentProcess(), ro, GetCurrentProcess(), &w2, FILE_MAP_WRITE, FALSE, 0) && GetLastError() == ERROR_ACCESS_DENIED;
            if (w2) ch(w2);
            if (ro) ch(ro);
            if (rw) ch(rw);
        }
        LOG("    section handles: writable copy %d, read-only copy %d, write access from read-only refused %d\n", ok1, ok2, ok3);
        CHECK(ok1 && ok2 && ok3, "read-only section handle cannot be duplicated for writing");
    }
    LOG("    %lu cache descriptors from CPUID\n", caches);
    len = sizeof(exbuf);
    CHECK(pGetLogicalProcessorInformationEx(RelationAll, (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)exbuf, &len), "LPIEx all");
    {   /* walk records: sizes must chain exactly to len */
        DWORD off = 0, recs = 0;
        while (off < len) { PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX e = (void *)(exbuf + off); if (!e->Size) break; off += e->Size; recs++; }
        CHECK(off == len && recs >= 4, "LPIEx record chain off=%lu len=%lu recs=%lu", off, len, recs);
    }
    CHECK(pGetActiveProcessorCount(0xFFFF) == 1, "active processors");

    GetModuleFileNameA(NULL, self, MAX_PATH);
    CHECK(pK32GetModuleInformation(GetCurrentProcess(), NULL, &mi, sizeof(mi)) &&
          mi.lpBaseOfDll == GetModuleHandleA(NULL) && mi.SizeOfImage > 0, "GetModuleInformation self");
    CHECK(pK32GetModuleInformation(GetCurrentProcess(), kx, &mi, sizeof(mi)) && mi.lpBaseOfDll == kx, "GetModuleInformation kexnt");
    CHECK(pK32EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &n) && n >= 2 * sizeof(HMODULE), "EnumProcessModules n=%lu", n);
    CHECK(mods[0] == GetModuleHandleA(NULL), "exe listed first (%p vs %p)", mods[0], GetModuleHandleA(NULL));
    {
        int found = 0; for (i = 0; i < n / sizeof(HMODULE) && i < 256; i++) found |= mods[i] == kx;
        CHECK(found, "kexnt.dll present in module list");
    }
    CHECK(pK32EnumProcessModules(GetCurrentProcess(), mods, sizeof(HMODULE), &n) && mods[0] == GetModuleHandleA(NULL),
          "small buffer still returns exe first and full size (%lu)", n);
    CHECK(pK32GetModuleFileNameExA(GetCurrentProcess(), NULL, path, MAX_PATH) == strlen(self) && !lstrcmpiA(path, self),
          "GetModuleFileNameExA self '%s'", path);
    CHECK(pK32GetModuleFileNameExA(GetCurrentProcess(), NULL, path, 4) == 3 && path[3] == 0, "truncation to 3 chars");
    CHECK(pK32GetModuleBaseNameA(GetCurrentProcess(), kx, path, MAX_PATH) && !lstrcmpiA(path, "kexnt.dll"), "base name '%s'", path);
    n = MAX_PATH;
    CHECK(pQueryFullProcessImageNameW(GetCurrentProcess(), 0, wpath, &n) && n == strlen(self), "QueryFullProcessImageNameW n=%lu", n);
    n = 2;
    CHECK(!pQueryFullProcessImageNameW(GetCurrentProcess(), 0, wpath, &n) && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "QFPIN small buffer");
    CHECK(pK32GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)) && pmc.PagefileUsage > 0, "memory info %lu KB",
          (unsigned long)(pmc.PagefileUsage / 1024));
    {   /* build 79: committed pages of this process report Valid (Chromium memory dumps) */
        static volatile BYTE pg[8192]; struct { void *va; ULONG_PTR attr; } ws[2];
        pg[0] = 1; ws[0].va = (void *)pg; ws[0].attr = 0xFF; ws[1].va = (void *)0x10; ws[1].attr = 0xFF;
        CHECK(pK32QueryWorkingSetEx(GetCurrentProcess(), ws, sizeof(ws)) && (ws[0].attr & 1) && !(ws[1].attr & 1),
              "QueryWorkingSetEx valid %lu / %lu", (unsigned long)ws[0].attr, (unsigned long)ws[1].attr);
    }

    {
        SIZE_T sz = 0; BYTE buf[256]; DWORD_PTR v = 1;
        CHECK(!pInitializeProcThreadAttributeList(NULL, 2, 0, &sz) && sz && sz <= sizeof(buf), "PTA size %lu", (unsigned long)sz);
        CHECK(pInitializeProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)buf, 2, 0, &sz), "PTA init");
        CHECK(pUpdateProcThreadAttribute((LPPROC_THREAD_ATTRIBUTE_LIST)buf, 0, 0x20007, &v, sizeof(v), NULL, NULL), "PTA update");
        CHECK(!pUpdateProcThreadAttribute((LPPROC_THREAD_ATTRIBUTE_LIST)buf, 0, 0x20007, &v, sizeof(v), NULL, NULL), "PTA dup rejected");
        pDeleteProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)buf);
    }
    pGetCurrentThreadStackLimits(&lo, &hi);
    CHECK(lo < (ULONG_PTR)&local && (ULONG_PTR)&local < hi, "stack limits %08lx < %p < %08lx", (unsigned long)lo, (void *)&local, (unsigned long)hi);
    CHECK(pGetTickCount64() > 0, "GetTickCount64");
    pGetSystemTimePreciseAsFileTime(&a); Sleep(15); pGetSystemTimePreciseAsFileTime(&b);
    ua = ((ULONGLONG)a.dwHighDateTime << 32) | a.dwLowDateTime; ub = ((ULONGLONG)b.dwHighDateTime << 32) | b.dwLowDateTime;
    CHECK(ub > ua && ub - ua >= 100000, "precise time advances (%lu us)", (unsigned long)((ub - ua) / 10));
    CHECK(pGetProductInfo(10, 0, 0, 0, &type) && type == PRODUCT_PROFESSIONAL, "GetProductInfo %lu", type);
}

/* ------------------------------ locale names ------------------------------ */
/* UTF-16 equals ASCII literal */
static int weq(const WCHAR *w, const char *a)
{
    while (*a) if (*w++ != (WCHAR)(unsigned char)*a++) return 0;
    return *w == 0;
}
/* printable copy of a UTF-16 string for the log (non-ASCII as '?') */
static const char *wa(const WCHAR *w)
{
    static char b[4][128]; static int k;
    char *o = b[k++ & 3]; int i;
    for (i = 0; w[i] && i < 127; i++) o[i] = w[i] < 128 ? (char)w[i] : '?';
    o[i] = 0;
    return o;
}

static int g_enum_n, g_enum_enus;
static BOOL CALLBACK enum_cb(LPWSTR name, DWORD flags, LPARAM lp)
{
    g_enum_n++;
    if (weq(name, "en-US")) g_enum_enus = 1;
    return TRUE;
}

static void test_locale(void)
{
    WCHAR w[128]; DWORD num = 0; ULONG n = 0, cnt = 0; int r;
    SYSTEMTIME st; NUMBERFMTW nf;
    LOG("[locale names]  unicode collation backend: %s\n", pKexNlsUnicodeBackend() ? "KernelEx" : "ANSI fallback");

    /* LCID <-> name (pure table, independent of the installed locale) */
    CHECK(pLCIDToLocaleName(0x0409, w, 128, 0) == 6 && weq(w, "en-US"), "LCIDToLocaleName(0409) '%s'", wa(w));
    CHECK(pLCIDToLocaleName(0x0407, w, 128, 0) == 6 && weq(w, "de-DE"), "LCIDToLocaleName(0407) '%s'", wa(w));
    CHECK(pLCIDToLocaleName(0x0009, w, 128, LOCALE_ALLOW_NEUTRAL_NAMES) == 3 && weq(w, "en"), "neutral 0009 '%s'", wa(w));
    CHECK(pLCIDToLocaleName(0x0009, w, 128, 0) == 6 && weq(w, "en-US"), "0009 without ALLOW_NEUTRAL '%s'", wa(w));
    CHECK(pLCIDToLocaleName(0x007F, w, 128, 0) == 1 && w[0] == 0, "invariant -> empty name");
    CHECK(pLCIDToLocaleName(0x0409, NULL, 0, 0) == 6, "size query");
    SetLastError(0);
    CHECK(!pLCIDToLocaleName(0x0409, w, 3, 0) && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "small buffer (err %lu)", GetLastError());
    CHECK(!pLCIDToLocaleName(0x7777, w, 128, 0), "unknown LCID rejected");
    CHECK(pLocaleNameToLCID(L"en-US", 0) == 0x0409, "LocaleNameToLCID(en-US)");
    CHECK(pLocaleNameToLCID(L"EN-us", 0) == 0x0409, "name lookup is case-insensitive");
    CHECK(pLocaleNameToLCID(L"de", 0) == 0x0407, "de -> de-DE");
    CHECK(pLocaleNameToLCID(L"de", LOCALE_ALLOW_NEUTRAL_NAMES) == 0x0007, "de neutral -> 0007");
    CHECK(pLocaleNameToLCID(L"zh-Hans", 0) == 0x0804, "zh-Hans -> zh-CN (%04lx)", pLocaleNameToLCID(L"zh-Hans", 0));
    CHECK(pLocaleNameToLCID(L"", 0) == 0x007F, "invariant name");
    SetLastError(0);
    CHECK(pLocaleNameToLCID(L"xx-YY", 0) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "unknown name rejected");
    CHECK(pIsValidLocaleName(L"sl-SI") && !pIsValidLocaleName(L"bogus") && !pIsValidLocaleName(NULL), "IsValidLocaleName");
    CHECK(pResolveLocaleName(L"fr", w, 128) && weq(w, "fr-FR"), "ResolveLocaleName(fr) '%s'", wa(w));
    r = pGetUserDefaultLocaleName(w, 128);
    LOG("    user default locale %s (LCID %04lx), system %s\n", wa(w), (unsigned long)GetUserDefaultLCID(),
        pGetSystemDefaultLocaleName(w + 64, 64) ? wa(w + 64) : "?");
    CHECK(r > 1 && LANGIDFROMLCID(pLocaleNameToLCID(w, 0)) == LANGIDFROMLCID(GetUserDefaultLCID()), "user default name round-trips");
    g_enum_n = g_enum_enus = 0;
    CHECK(pEnumSystemLocalesEx(enum_cb, LOCALE_WINDOWS, 0, NULL) && g_enum_n > 0 && g_enum_enus, "EnumSystemLocalesEx %d locales", g_enum_n);

    /* GetLocaleInfoEx: computed NT6 types + Win98 ANSI data */
#define LI(name, type, want) CHECK(pGetLocaleInfoEx(L##name, type, w, 128) && weq(w, want), "GetLocaleInfoEx(%s, %s) '%s'", name, #type, wa(w))
    LI("en-US", LOCALE_SNAME, "en-US");
    LI("en-US", LOCALE_SPARENT, "en");
    LI("en", LOCALE_SPARENT, "");
    LI("en-US", LOCALE_SISO639LANGNAME, "en");
    LI("en-US", LOCALE_SISO3166CTRYNAME, "US");
    LI("es-ES_tradnl", LOCALE_SISO3166CTRYNAME, "ES");
    LI("en-US", LOCALE_SENGLANGUAGE | LOCALE_NOUSEROVERRIDE, "English");
    LI("en-US", LOCALE_SDECIMAL | LOCALE_NOUSEROVERRIDE, ".");
    LI("de-DE", LOCALE_SDECIMAL | LOCALE_NOUSEROVERRIDE, ",");
    LI("en-US", LOCALE_SNAN, "NaN");
    LI("en-US", LOCALE_IREADINGLAYOUT, "0");
    LI("ar-SA", LOCALE_IREADINGLAYOUT, "1");
    LI("de-DE", LOCALE_SSHORTTIME | LOCALE_NOUSEROVERRIDE, "HH:mm");
    LI("en-US", LOCALE_SENGLISHDISPLAYNAME | LOCALE_NOUSEROVERRIDE, "English (United States)");
    CHECK(pGetLocaleInfoEx(L"en-US", LOCALE_SPERMILLE, w, 128) == 2 && w[0] == 0x2030, "SPERMILLE U+2030");
    CHECK(pGetLocaleInfoEx(L"en-US", LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER, (LPWSTR)&num, 2) == 2 && num == 1252,
          "IDEFAULTANSICODEPAGE as number = %lu", num);
    CHECK(pGetLocaleInfoEx(L"en-US", LOCALE_SNAME, NULL, 0) == 6, "GetLocaleInfoEx size query");
    CHECK(!pGetLocaleInfoEx(L"xx-YY", LOCALE_SNAME, w, 128), "GetLocaleInfoEx unknown locale");

    /* formatting through the ANSI Win98 functions */
    CHECK(pGetNumberFormatEx(L"en-US", LOCALE_NOUSEROVERRIDE, L"1234.5", NULL, w, 128) && weq(w, "1,234.50"),
          "GetNumberFormatEx '%s'", wa(w));
    nf.NumDigits = 1; nf.LeadingZero = 1; nf.Grouping = 3; nf.lpDecimalSep = L","; nf.lpThousandSep = L"."; nf.NegativeOrder = 1;
    CHECK(pGetNumberFormatEx(L"en-US", 0, L"-1234.56", &nf, w, 128) && weq(w, "-1.234,6"), "GetNumberFormatEx custom '%s'", wa(w));
    CHECK(pGetCurrencyFormatEx(L"en-US", LOCALE_NOUSEROVERRIDE, L"1234.5", NULL, w, 128) && weq(w, "$1,234.50"),
          "GetCurrencyFormatEx '%s'", wa(w));
    memset(&st, 0, sizeof(st));
    st.wYear = 2026; st.wMonth = 10; st.wDay = 31; st.wDayOfWeek = 6; st.wHour = 13; st.wMinute = 5; st.wSecond = 9;
    CHECK(pGetDateFormatEx(L"en-US", 0, &st, L"yyyy-MM-dd", w, 128, NULL) == 11 && weq(w, "2026-10-31"), "GetDateFormatEx '%s'", wa(w));
    CHECK(pGetDateFormatEx(L"en-US", 0, &st, L"dddd, MMMM d", w, 128, NULL) && weq(w, "Saturday, October 31"),
          "GetDateFormatEx names '%s'", wa(w));
    CHECK(pGetDateFormatEx(L"en-US", 0, &st, L"yyyy-MM-dd", NULL, 0, NULL) == 11, "GetDateFormatEx size query");
    CHECK(pGetTimeFormatEx(L"en-US", 0, &st, L"HH:mm:ss", w, 128) == 9 && weq(w, "13:05:09"), "GetTimeFormatEx '%s'", wa(w));

    /* collation / mapping */
    CHECK(pCompareStringEx(L"en-US", 0, L"apple", -1, L"Banana", -1, NULL, NULL, 0) == CSTR_LESS_THAN, "CompareStringEx linguistic order");
    CHECK(pCompareStringEx(L"en-US", NORM_IGNORECASE, L"ABC", -1, L"abc", -1, NULL, NULL, 0) == CSTR_EQUAL, "NORM_IGNORECASE");
    CHECK(pCompareStringEx(L"en-US", LINGUISTIC_IGNORECASE, L"ABC", 3, L"abc", 3, NULL, NULL, 0) == CSTR_EQUAL, "LINGUISTIC_IGNORECASE");
    CHECK(pCompareStringEx(NULL, 0, L"b", -1, L"a", -1, NULL, NULL, 0) == CSTR_GREATER_THAN, "user-default locale (NULL name)");
    r = pLCMapStringEx(L"en-US", LCMAP_UPPERCASE, L"hello", -1, w, 128, NULL, NULL, 0);
    CHECK(r == 6 && weq(w, "HELLO"), "LCMapStringEx upper r=%d '%s'", r, wa(w));
    r = pLCMapStringEx(L"en-US", LCMAP_LOWERCASE, L"MiXeD", 5, w, 128, NULL, NULL, 0);
    CHECK(r == 5 && w[0] == 'm' && w[4] == 'd', "LCMapStringEx lower r=%d", r);
    CHECK(pLCMapStringEx(L"en-US", LCMAP_SORTKEY, L"abc", -1, NULL, 0, NULL, NULL, 0) > 0, "LCMapStringEx sort key size");
    CHECK(pCompareStringOrdinal(L"abc", -1, L"ABC", -1, TRUE) == CSTR_EQUAL, "ordinal ignore case");
    CHECK(pCompareStringOrdinal(L"abc", -1, L"ABC", -1, FALSE) == CSTR_GREATER_THAN, "ordinal exact 'a' > 'A'");
    CHECK(pCompareStringOrdinal(L"ab", -1, L"abc", -1, FALSE) == CSTR_LESS_THAN, "ordinal prefix shorter");
    CHECK(pCompareStringOrdinal(L"\x0434\x00E9", 2, L"\x0414\x00C9", 2, TRUE) == CSTR_EQUAL, "ordinal ignore case Cyrillic/Latin-1");

    /* UI languages */
    CHECK(pGetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &cnt, NULL, &n) && cnt == 1 && n > 2, "UI languages size n=%lu", n);
    CHECK(n <= 128 && pGetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &cnt, w, &n) && w[n - 1] == 0 && w[n - 2] == 0,
          "UI languages list '%s' double-NUL", wa(w));
    n = 128;
    CHECK(pGetUserPreferredUILanguages(MUI_LANGUAGE_ID, &cnt, w, &n) && n == 6 && w[4] == 0, "UI language id '%s'", wa(w));
    CHECK(pSetThreadPreferredUILanguages(MUI_LANGUAGE_NAME, L"en-US\0", &n), "SetThreadPreferredUILanguages accepted");
}

static int g_nopause;
static int finish(int code)
{
    if (g_log) { fclose(g_log); g_log = NULL; }
    if (!g_nopause) {   /* Win98 closes the console window on exit when started from Explorer */
        printf("\nPress Enter to close...");
        fflush(stdout);
        getchar();
    }
    return code;
}


/* ============================ vectored exception handling ============================ */
extern char kt_av_site[], kt_bp_site[];
/* build 120: the fault goes to a page this test reserved and never committed (an access violation on every
 * Windows). Builds up to 119 wrote to address 0, which faults in the VMware VM but NOT in the QEMU VM (kextest
 * 119 there: "order ''" - no exception at all, and the other-thread test passed only because nothing faulted).
 * movl %eax, (%ecx)  ->  89 01 (2 bytes) */
static volatile DWORD *g_av_page;
static void __attribute__((noinline)) do_av(void)
{ __asm__ __volatile__(".globl _kt_av_site\n_kt_av_site:\n\tmovl %%eax, (%%ecx)\n" :: "c"(g_av_page) : "eax", "memory"); }
#define KT_AV_LEN 2
static void __attribute__((noinline)) do_bp(void)
{ __asm__ __volatile__(".globl _kt_bp_site\n_kt_bp_site:\n\tint3\n\tnop\n" ::: "memory"); }

static char g_order[32];
static int  g_norder;
static volatile LONG g_veh_hits, g_bp_eip_delta = -99;
static void mark(char c) { if (g_norder < 31) g_order[g_norder++] = c; g_order[g_norder] = 0; }

static LONG CALLBACK veh_fix(PEXCEPTION_POINTERS ep)
{
    PEXCEPTION_RECORD r = ep->ExceptionRecord;
    InterlockedIncrement(&g_veh_hits);
    if (r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && r->ExceptionAddress == (PVOID)kt_av_site) {
        mark('A'); ep->ContextRecord->Eip += KT_AV_LEN; return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (r->ExceptionCode == EXCEPTION_BREAKPOINT &&
        (ep->ContextRecord->Eip == (DWORD)kt_bp_site || ep->ContextRecord->Eip == (DWORD)kt_bp_site + 1)) {
        g_bp_eip_delta = (LONG)(ep->ContextRecord->Eip - (DWORD)kt_bp_site);
        mark('B'); ep->ContextRecord->Eip = (DWORD)kt_bp_site + 1; return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (r->ExceptionCode == 0xE0001234) { mark('R'); return EXCEPTION_CONTINUE_EXECUTION; }
    if (r->ExceptionCode == 0xE0005678) { mark('V'); return EXCEPTION_CONTINUE_SEARCH; }
    return EXCEPTION_CONTINUE_SEARCH;
}
static LONG CALLBACK veh_first(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode == 0xE0009999) mark('1');
    return EXCEPTION_CONTINUE_SEARCH;
}
static LONG CALLBACK veh_last(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode == 0xE0009999) { mark('2'); return EXCEPTION_CONTINUE_EXECUTION; }
    return EXCEPTION_CONTINUE_SEARCH;
}
static LONG CALLBACK vch(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode == 0xE0009999) mark('C');
    return EXCEPTION_CONTINUE_SEARCH;
}

/* A classic SEH frame registered by hand (GCC has no __try): proves the normal 9x path still runs. */
typedef struct seh_reg { struct seh_reg *prev; void *handler; } seh_reg;
static EXCEPTION_DISPOSITION __cdecl seh_handler(PEXCEPTION_RECORD r, void *frame, PCONTEXT c, void *dc)
{
    if (r->ExceptionCode == 0xE0005678 && !(r->ExceptionFlags & 6)) { mark('S'); return ExceptionContinueExecution; }
    return ExceptionContinueSearch;
}
static void raise_with_seh(DWORD code)
{
    seh_reg f;
    f.handler = (void *)seh_handler;
    __asm__ __volatile__("movl %%fs:0, %0" : "=r"(f.prev));
    __asm__ __volatile__("movl %0, %%fs:0" :: "r"(&f) : "memory");
    RaiseException(code, 0, 0, NULL);
    __asm__ __volatile__("movl %0, %%fs:0" :: "r"(f.prev) : "memory");
}
static DWORD WINAPI av_thread(LPVOID p) { do_av(); return 7; }

static void test_veh(void)
{
    PVOID h, h1, h2, hc;
    HANDLE th;
    DWORD code = 0, tid;
    LOG("[vectored exceptions]\n");
    h = pAddVectoredExceptionHandler(1, veh_fix);
    CHECK(h != NULL, "AddVectoredExceptionHandler");
    LOG("    hook state %ld (1 = KERNEL32 dispatcher hooked)\n", pKexVehState());
    {   /* big-file section hook (KERNEL32 map_section), same install machinery */
        typedef LONG (WINAPI *T_BA)(void); typedef LONG (WINAPI *T_BS)(PDWORD, PDWORD);
        T_BA ba = (T_BA)(void *)GetProcAddress(kx, "KexBigSecActivate");
        T_BS bs = (T_BS)(void *)GetProcAddress(kx, "KexBigSecState");
        if (!ba || !bs) CHECK(0, "kexnt exports KexBigSecActivate/KexBigSecState");
        else {
            LONG st = ba(); DWORD c = 0, f = 0;
            bs(&c, &f);
            LOG("    big-file section hook state %ld (1 = KERNEL32 section mapper hooked; -3 routine not found,\n"
                "      -5 no room in KERNEL32, -6/-9/-10/-12/-13/-14 KernelEx process storage, -8 foreign hook, -11 not writable)\n", st);
            CHECK(st == 1, "big-file section hook installs (state %ld)", st);
            {
                T_BA ea = (T_BA)(void *)GetProcAddress(kx, "KexTlsEntryActivate");
                LONG es = ea ? ea() : -99;
                LOG("    DLL entry hook state %ld (1 = KERNEL32 DLL-entry caller hooked: static TLS before DllMain)\n", es);
                CHECK(es == 1, "DLL entry hook installs (state %ld)", es);
            }
        }
    }
    if (pKexVehState() != 1) {
        CHECK(0, "VEH hook not active (needs KernelEx and Win98 SE KERNEL32 4.10.2222) - skipping fault tests");
        pRemoveVectoredExceptionHandler(h);
        return;
    }
    if (!g_av_page) {
        MEMORY_BASIC_INFORMATION mi;
        g_av_page = (volatile DWORD *)VirtualAlloc(NULL, 4096, MEM_RESERVE, PAGE_NOACCESS);
        CHECK(g_av_page && VirtualQuery((LPCVOID)g_av_page, &mi, sizeof(mi)) && mi.State == MEM_RESERVE,
              "a reserved, uncommitted page to fault on (%p)", (void *)g_av_page);
    }
    g_norder = 0; g_order[0] = 0;
    do_av();
    CHECK(!strcmp(g_order, "A"), "access violation fixed by VEH (order '%s')", g_order);
    g_norder = 0; g_order[0] = 0;
    do_bp();
    CHECK(!strcmp(g_order, "B"), "int3 handled by VEH (order '%s')", g_order);
    CHECK(g_bp_eip_delta == 0, "int3 seen NT-style: context Eip = site%+ld (NT: +0)", g_bp_eip_delta);
    g_norder = 0; g_order[0] = 0;
    RaiseException(0xE0001234, 0, 0, NULL);
    CHECK(!strcmp(g_order, "R"), "RaiseException continued by VEH (order '%s')", g_order);
    g_norder = 0; g_order[0] = 0;
    raise_with_seh(0xE0005678);
    CHECK(!strcmp(g_order, "VS"), "VEH first, then SEH frame (order '%s')", g_order);

    h1 = pAddVectoredExceptionHandler(0, veh_last);      /* tail */
    h2 = pAddVectoredExceptionHandler(1, veh_first);     /* head */
    hc = pAddVectoredContinueHandler(0, vch);
    g_norder = 0; g_order[0] = 0;
    RaiseException(0xE0009999, 0, 0, NULL);
    CHECK(!strcmp(g_order, "12C"), "handler order + continue handler (order '%s')", g_order);
    CHECK(pRemoveVectoredExceptionHandler(h2) == 1 && pRemoveVectoredExceptionHandler(h2) == 0, "remove once");
    pRemoveVectoredExceptionHandler(h1); pRemoveVectoredContinueHandler(hc);

    g_norder = 0; g_order[0] = 0;
    th = CreateThread(NULL, 0, av_thread, NULL, 0, &tid);
    WaitForSingleObject(th, 5000); GetExitCodeThread(th, &code); CloseHandle(th);
    CHECK(code == 7 && !strcmp(g_order, "A"), "fault in another thread handled (exit %lu, order '%s')", code, g_order);

    CHECK(pRemoveVectoredExceptionHandler(h) == 1, "RemoveVectoredExceptionHandler");
    g_norder = 0; g_order[0] = 0;
    raise_with_seh(0xE0005678);
    CHECK(!strcmp(g_order, "S"), "after removal only SEH sees it (order '%s')", g_order);
}

/* ============================ version profiles (kexver.dll) ============================ */
static ULONGLONG vscm(ULONGLONG m, DWORD type, BYTE cond)
{
    int i;
    for (i = 0; i < 8; i++) if (type & (1u << i)) m |= (ULONGLONG)cond << (i * 3);
    return m;
}

/* ---------------- Chromium round: functions added for Chromium's imports ---------------- */
#define GP(type, name) type name = (type)(void *)GetProcAddress(kx, &(#name)[2])
typedef DWORD (WINAPI *T_GETTID)(HANDLE);
typedef VOID (WINAPI *T_SLINIT)(PSLIST_HEADER);
typedef PSLIST_ENTRY (WINAPI *T_SLPUSH)(PSLIST_HEADER, PSLIST_ENTRY);
typedef PSLIST_ENTRY (WINAPI *T_SLPOP)(PSLIST_HEADER);
typedef USHORT (WINAPI *T_SLDEPTH)(PSLIST_HEADER);
typedef BOOL (WINAPI *T_FIBHEX)(HANDLE, int, LPVOID, DWORD);
typedef BOOL (WINAPI *T_SFIBH)(HANDLE, int, LPVOID, DWORD);
typedef LONG (WINAPI *T_REGGETW)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
typedef HRESULT (WINAPI *T_KFP)(const GUID *, DWORD, HANDLE, PWSTR *);
typedef PCSTR (WINAPI *T_NTOP)(INT, const void *, PSTR, SIZE_T);
typedef INT (WINAPI *T_PTON)(INT, PCSTR, PVOID);
typedef HRESULT (WINAPI *T_HSCREATE)(const WCHAR *, UINT32, void **);
typedef HRESULT (WINAPI *T_HSREF)(const WCHAR *, UINT32, void *, void **);
typedef PCWSTR (WINAPI *T_HSRAW)(void *, UINT32 *);
typedef HRESULT (WINAPI *T_HSDEL)(void *);
typedef BOOL (WINAPI *T_RAND)(PVOID, SIZE_T);
typedef BOOL (WINAPI *T_CPM)(LPVOID, DWORD, DWORD);
typedef LONG (WINAPI *T_GEOID)(DWORD);
typedef int (WINAPI *T_GEOINFO)(LONG, DWORD, LPWSTR, int, LANGID);
typedef LONG (WINAPI *T_NTQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef VOID (WINAPI *T_RTLINIT)(void *, PCWSTR);
typedef ULONG (WINAPI *T_EVREG)(const GUID *, PVOID, PVOID, PULONGLONG);
typedef HRESULT (WINAPI *T_DPI)(HANDLE, int, UINT *, UINT *);

static DWORD WINAPI tid_thread(LPVOID p) { Sleep(300); return 0; }

static void test_chromium(void)
{
    GP(T_GETTID, p_GetThreadId);
    GP(T_GETTID, p_GetProcessIdOfThread);
    GP(T_SLINIT, p_InitializeSListHead);
    GP(T_SLPUSH, p_InterlockedPushEntrySList);
    GP(T_SLPOP, p_InterlockedPopEntrySList);
    GP(T_SLPOP, p_InterlockedFlushSList);
    GP(T_SLDEPTH, p_QueryDepthSList);
    GP(T_FIBHEX, p_GetFileInformationByHandleEx);
    GP(T_SFIBH, p_SetFileInformationByHandle);
    GP(T_REGGETW, p_RegGetValueW);
    GP(T_KFP, p_SHGetKnownFolderPath);
    GP(T_NTOP, p_inet_ntop);
    GP(T_PTON, p_inet_pton);
    GP(T_HSCREATE, p_WindowsCreateString);
    GP(T_HSREF, p_WindowsCreateStringReference);
    GP(T_HSRAW, p_WindowsGetStringRawBuffer);
    GP(T_HSDEL, p_WindowsDeleteString);
    GP(T_RAND, p_KexGenRandom);
    GP(T_CPM, p_CryptProtectMemory);
    GP(T_CPM, p_CryptUnprotectMemory);
    GP(T_GEOID, p_GetUserGeoID);
    GP(T_GEOINFO, p_GetGeoInfoW);
    GP(T_NTQIP, p_NtQueryInformationProcess);
    GP(T_RTLINIT, p_RtlInitUnicodeString);
    GP(T_EVREG, p_EventRegister);
    GP(T_DPI, p_GetDpiForMonitor);
    LOG("[Chromium round]\n");
    CHECK(p_GetThreadId && p_GetProcessIdOfThread && p_InitializeSListHead && p_InterlockedPushEntrySList &&
          p_InterlockedPopEntrySList && p_InterlockedFlushSList && p_QueryDepthSList && p_GetFileInformationByHandleEx &&
          p_SetFileInformationByHandle && p_RegGetValueW && p_SHGetKnownFolderPath && p_inet_ntop && p_inet_pton &&
          p_WindowsCreateString && p_WindowsCreateStringReference && p_WindowsGetStringRawBuffer && p_WindowsDeleteString &&
          p_KexGenRandom && p_CryptProtectMemory && p_CryptUnprotectMemory && p_GetUserGeoID && p_GetGeoInfoW &&
          p_NtQueryInformationProcess && p_RtlInitUnicodeString && p_EventRegister && p_GetDpiForMonitor, "new exports present");
    if (!(p_GetThreadId && p_InterlockedPushEntrySList && p_RegGetValueW && p_inet_ntop && p_WindowsCreateString &&
          p_KexGenRandom && p_CryptProtectMemory && p_NtQueryInformationProcess && p_SHGetKnownFolderPath &&
          p_GetFileInformationByHandleEx && p_SetFileInformationByHandle && p_GetGeoInfoW && p_EventRegister && p_GetDpiForMonitor)) return;

    {   /* thread / process ids from handles */
        DWORD tid = 0, got, gotp; HANDLE h = CreateThread(NULL, 0, tid_thread, NULL, 0, &tid);
        got = p_GetThreadId(h); gotp = p_GetProcessIdOfThread(h);
        CHECK(got == tid, "GetThreadId(handle) %08lx, CreateThread said %08lx", got, tid);
        CHECK(gotp == GetCurrentProcessId(), "GetProcessIdOfThread %08lx vs %08lx", gotp, GetCurrentProcessId());
        CHECK(p_GetThreadId(GetCurrentThread()) == GetCurrentThreadId(), "GetThreadId(pseudo handle)");
        CHECK(p_GetThreadId((HANDLE)0x12345) == 0, "GetThreadId(bad handle) must be 0");
        WaitForSingleObject(h, 5000); CloseHandle(h);
    }
    {   /* interlocked SLIST */
        static SLIST_HEADER hd __attribute__((aligned(8)));
        static SLIST_ENTRY e[3] __attribute__((aligned(8)));
        PSLIST_ENTRY a, b;
        p_InitializeSListHead(&hd);
        p_InterlockedPushEntrySList(&hd, &e[0]); p_InterlockedPushEntrySList(&hd, &e[1]); p_InterlockedPushEntrySList(&hd, &e[2]);
        CHECK(p_QueryDepthSList(&hd) == 3, "SLIST depth %u", p_QueryDepthSList(&hd));
        a = p_InterlockedPopEntrySList(&hd);
        CHECK(a == &e[2], "SLIST pop is LIFO");
        b = p_InterlockedFlushSList(&hd);
        CHECK(b == &e[1] && b->Next == &e[0] && !p_InterlockedPopEntrySList(&hd), "SLIST flush returns the chain");
    }
    {   /* file information by handle */
        char tmp[MAX_PATH], fn[MAX_PATH]; HANDLE f; DWORD w;
        struct { LONGLONG c, a, wr, ch; DWORD attr; } bi;
        struct { LONGLONG alloc, eof; DWORD links; BOOLEAN del, dir; } si;
        LONGLONG eof = 10;
        GetTempPathA(MAX_PATH, tmp); GetTempFileNameA(tmp, "kxf", 0, fn);
        f = CreateFileA(fn, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        WriteFile(f, "hello world, 25 bytes...", 25, &w, NULL);
        CHECK(p_GetFileInformationByHandleEx(f, 1, &si, sizeof(si)) && si.eof == 25 && !si.dir, "FileStandardInfo eof %ld", (long)si.eof);
        CHECK(p_GetFileInformationByHandleEx(f, 0, &bi, sizeof(bi)) && bi.wr != 0, "FileBasicInfo");
        CHECK(p_SetFileInformationByHandle(f, 6, &eof, sizeof(eof)) && GetFileSize(f, NULL) == 10, "FileEndOfFileInfo -> %lu", GetFileSize(f, NULL));
        CHECK(!p_SetFileInformationByHandle(f, 4, &w, 1) && GetLastError() == ERROR_NOT_SUPPORTED, "FileDispositionInfo reports not supported");
        CloseHandle(f); DeleteFileA(fn);
    }
    {   /* RegGetValueW (REG_SZ conversion, REG_DWORD, type filter) */
        WCHAR buf[MAX_PATH]; DWORD cb = sizeof(buf), type = 0, dw = 0, cbd = 4; LONG r;
        r = p_RegGetValueW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion", L"ProgramFilesDir",
                           0x02 /*RRF_RT_REG_SZ*/, &type, buf, &cb);
        CHECK(r == 0 && type == REG_SZ && buf[1] == L':' && cb == (lstrlenW(buf) + 1) * 2, "RegGetValueW ProgramFilesDir r=%ld", r);
        r = p_RegGetValueW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion", L"ProgramFilesDir",
                           0x10 /*RRF_RT_REG_DWORD*/, &type, &dw, &cbd);
        CHECK(r == ERROR_UNSUPPORTED_TYPE, "RegGetValueW type filter r=%ld", r);
    }
    {   /* known folders */
        static const GUID roaming = {0x3EB685DB,0x65F9,0x4CF6,{0xA0,0x3A,0xE3,0xEF,0x65,0x72,0x9F,0x3D}};
        static const GUID local = {0xF1B32785,0x6FBA,0x4FCF,{0x9D,0x55,0x7B,0x8E,0x7F,0x15,0x70,0x91}};
        PWSTR p = NULL; HRESULT hr = p_SHGetKnownFolderPath(&roaming, 0, NULL, &p);
        CHECK(hr == S_OK && p && p[1] == L':', "FOLDERID_RoamingAppData hr=%08lx", (unsigned long)hr);
        if (p) { char a[MAX_PATH]; WideCharToMultiByte(CP_ACP, 0, p, -1, a, MAX_PATH, NULL, NULL); LOG("  RoamingAppData = %s\n", a); CoTaskMemFree(p); }
        p = NULL; hr = p_SHGetKnownFolderPath(&local, 0x8000, NULL, &p);
        CHECK(hr == S_OK && p, "FOLDERID_LocalAppData hr=%08lx", (unsigned long)hr);
        if (p) { char a[MAX_PATH]; WideCharToMultiByte(CP_ACP, 0, p, -1, a, MAX_PATH, NULL, NULL); LOG("  LocalAppData   = %s\n", a); CoTaskMemFree(p); }
    }
    {   /* inet_ntop / inet_pton */
        BYTE v6[16], v4[4]; char s[64];
        CHECK(p_inet_pton(23, "2001:db8::1", v6) == 1 && v6[0] == 0x20 && v6[15] == 1, "inet_pton v6");
        CHECK(p_inet_ntop(23, v6, s, sizeof(s)) && !strcmp(s, "2001:db8::1"), "inet_ntop v6 '%s'", s);
        CHECK(p_inet_pton(2, "192.168.1.20", v4) == 1 && p_inet_ntop(2, v4, s, sizeof(s)) && !strcmp(s, "192.168.1.20"), "v4 round trip '%s'", s);
        CHECK(p_inet_pton(23, "::ffff:10.0.0.1", v6) == 1 && p_inet_ntop(23, v6, s, sizeof(s)) && !strcmp(s, "::ffff:10.0.0.1"), "v4-mapped '%s'", s);
        CHECK(p_inet_pton(2, "300.1.1.1", v4) == 0, "bad v4 rejected");
    }
    {   /* HSTRING */
        void *h = NULL, *r = NULL; BYTE hdr[24]; UINT32 n = 0; PCWSTR raw;
        CHECK(p_WindowsCreateString(L"chromium", 8, &h) == S_OK && h, "WindowsCreateString");
        raw = p_WindowsGetStringRawBuffer(h, &n);
        CHECK(n == 8 && raw && raw[0] == L'c' && raw[8] == 0, "raw buffer len %u", n);
        CHECK(p_WindowsCreateStringReference(L"ref", 3, hdr, &r) == S_OK && r == hdr, "fast-pass reference");
        CHECK(p_WindowsDeleteString(h) == S_OK && p_WindowsDeleteString(r) == S_OK, "delete");
        raw = p_WindowsGetStringRawBuffer(NULL, &n);
        CHECK(raw && !raw[0] && n == 0, "NULL HSTRING is empty");
    }
    {   /* random numbers + CryptProtectMemory */
        BYTE a[64], b[64], m[32], orig[32]; int i, same = 0, zero = 0;
        p_KexGenRandom(a, sizeof(a)); p_KexGenRandom(b, sizeof(b));
        for (i = 0; i < 64; i++) { same += a[i] == b[i]; zero += !a[i]; }
        CHECK(same < 8 && zero < 8, "random output looks random (same %d, zero %d)", same, zero);
        for (i = 0; i < 32; i++) m[i] = orig[i] = (BYTE)i;
        CHECK(p_CryptProtectMemory(m, 32, 0) && memcmp(m, orig, 32), "CryptProtectMemory changes data");
        CHECK(p_CryptUnprotectMemory(m, 32, 0) && !memcmp(m, orig, 32), "CryptUnprotectMemory restores it");
        CHECK(!p_CryptProtectMemory(m, 30, 0), "size not a multiple of 16 rejected");
    }
    {   /* misc */
        struct { LONG exit; PVOID peb; ULONG_PTR aff; LONG prio; ULONG_PTR pid, ppid; } pbi; ULONG rl = 0; LONG st;
        WCHAR iso[8] = { 0 }; LONG geo = p_GetUserGeoID(16); ULONGLONG eh = 0; UINT dx = 0, dy = 0;
        struct { USHORT l, m; PWSTR b; } us;
        st = p_NtQueryInformationProcess(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &rl);
        CHECK(st == 0 && pbi.pid == GetCurrentProcessId() && pbi.peb, "NtQueryInformationProcess basic st=%08lx", (unsigned long)st);
        if (geo != -1) CHECK(p_GetGeoInfoW(geo, 4, iso, 8, 0) == 3, "GetGeoInfoW ISO2 for geo %ld", geo);
        LOG("  user GeoID %ld (%c%c)\n", geo, (char)iso[0], (char)iso[1]);
        p_RtlInitUnicodeString(&us, L"abc");
        CHECK(us.l == 6 && us.m == 8, "RtlInitUnicodeString lengths");
        CHECK(p_EventRegister(&IID_IUnknown, NULL, NULL, &eh) == 0 && eh, "EventRegister succeeds");
        CHECK(p_GetDpiForMonitor(NULL, 0, &dx, &dy) == S_OK && dx >= 72 && dx == dy, "GetDpiForMonitor %u", dx);
    }
}

/* ---------------- named pipes (pipe_ext.c) ---------------- */
typedef HANDLE (WINAPI *T_CNPW)(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
typedef HANDLE (WINAPI *T_CFW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *T_CONN)(HANDLE, LPOVERLAPPED);
typedef BOOL (WINAPI *T_RF)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *T_WF)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *T_GOR)(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
typedef BOOL (WINAPI *T_SNPHS)(HANDLE, LPDWORD, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *T_TNP)(HANDLE, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *T_CIOX)(HANDLE, LPOVERLAPPED);
typedef BOOL (WINAPI *T_PNP)(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *T_H)(HANDLE);
typedef DWORD (WINAPI *T_GFT)(HANDLE);
typedef BOOL (WINAPI *T_GNPC)(HANDLE, PULONG);
typedef BOOL (WINAPI *T_WNPW)(LPCWSTR, DWORD);

static struct {
    T_CNPW CreateNamedPipeW; T_CFW CreateFileW; T_CONN ConnectNamedPipe; T_RF ReadFile; T_WF WriteFile;
    T_GOR GetOverlappedResult; T_SNPHS SetNamedPipeHandleState; T_TNP TransactNamedPipe; T_CIOX CancelIoEx;
    T_PNP PeekNamedPipe; T_H DisconnectNamedPipe; T_GFT GetFileType; T_GNPC GetNamedPipeClientProcessId;
    T_WNPW WaitNamedPipeW;
} np;

static BOOL np_resolve(void)
{
#define NPR(f) (*(FARPROC *)&np.f = GetProcAddress(kx, #f)) != NULL
    return NPR(CreateNamedPipeW) && NPR(CreateFileW) && NPR(ConnectNamedPipe) && NPR(ReadFile) && NPR(WriteFile) &&
           NPR(GetOverlappedResult) && NPR(SetNamedPipeHandleState) && NPR(TransactNamedPipe) && NPR(CancelIoEx) &&
           NPR(PeekNamedPipe) && NPR(DisconnectNamedPipe) && NPR(GetFileType) && NPR(GetNamedPipeClientProcessId) &&
           NPR(WaitNamedPipeW);
#undef NPR
}

/* overlapped read on h, waits up to ms; returns bytes or -1 (error in *err) */
static int np_read_ov(HANDLE h, void *buf, DWORD n, DWORD ms, DWORD *err)
{
    OVERLAPPED ov; DWORD got = 0;
    memset(&ov, 0, sizeof(ov)); ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    *err = 0;
    if (!np.ReadFile(h, buf, n, &got, &ov)) {
        *err = GetLastError();
        if (*err == ERROR_IO_PENDING) {
            if (WaitForSingleObject(ov.hEvent, ms) != WAIT_OBJECT_0) { np.CancelIoEx(h, &ov); np.GetOverlappedResult(h, &ov, &got, TRUE); *err = WAIT_TIMEOUT; CloseHandle(ov.hEvent); return -1; }
            *err = np.GetOverlappedResult(h, &ov, &got, FALSE) ? 0 : GetLastError();
        }
    }
    CloseHandle(ov.hEvent);
    return (*err && *err != ERROR_MORE_DATA) ? -1 : (int)got;
}

static HANDLE g_np_srv;
static DWORD WINAPI np_echo_thread(LPVOID p)         /* server side of the TransactNamedPipe test */
{
    char buf[64]; DWORD err, w; int n = np_read_ov(g_np_srv, buf, sizeof(buf), 5000, &err);
    if (n == 4 && !memcmp(buf, "ping", 4)) np.WriteFile(g_np_srv, "pong", 4, &w, NULL);
    return 0;
}

static DWORD WINAPI np_stream_writer(LPVOID p)       /* 100000 bytes through a 32 KB ring */
{
    HANDLE h = (HANDLE)p; BYTE b[3000]; DWORD i, w, sent = 0;
    while (sent < 100000) {
        DWORD k = 100000 - sent < sizeof(b) ? 100000 - sent : sizeof(b);
        for (i = 0; i < k; i++) b[i] = (BYTE)((sent + i) * 7);
        if (!np.WriteFile(h, b, k, &w, NULL) || w != k) return 1;
        sent += k;
    }
    return 0;
}

static const WCHAR NP_NAME_T[] = L"\\\\.\\pipe\\KexNgTest";

/* child mode: kextest pipechild */
static int pipe_child(void)
{
    HANDLE h; DWORD mode = PIPE_READMODE_MESSAGE, w, got = 0; char buf[64];
    if (!np_resolve()) return 2;
    if (!np.WaitNamedPipeW(NP_NAME_T, 5000)) return 3;
    h = np.CreateFileW(NP_NAME_T, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 4;
    if (!np.SetNamedPipeHandleState(h, &mode, NULL, NULL)) return 5;
    if (!np.WriteFile(h, "from child", 10, &w, NULL) || w != 10) return 6;
    if (!np.ReadFile(h, buf, sizeof(buf), &got, NULL) || got != 8 || memcmp(buf, "to child", 8)) return 7;
    CloseHandle(h);
    return 0;
}

static void test_pipes(void)
{
    HANDLE srv, cli, ev, th; OVERLAPPED ov; DWORD n = 0, err, r, avail, left, mode;
    char buf[128]; int k;
    LOG("[named pipes]\n");
    CHECK(np_resolve(), "pipe exports present");
    if (!np.CreateNamedPipeW) return;

    srv = np.CreateNamedPipeW(NP_NAME_T, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                              PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
    CHECK(srv != INVALID_HANDLE_VALUE, "CreateNamedPipeW error %lu", GetLastError());
    if (srv == INVALID_HANDLE_VALUE) return;
    {
        HANDLE s2 = np.CreateNamedPipeW(NP_NAME_T, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_MESSAGE, 1, 0, 0, 0, NULL);
        CHECK(s2 == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED, "second FIRST_PIPE_INSTANCE refused (%lu)", GetLastError());
        if (s2 != INVALID_HANDLE_VALUE) CloseHandle(s2);
    }
    CHECK(np.GetFileType(srv) == FILE_TYPE_PIPE, "GetFileType = FILE_TYPE_PIPE");

    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    memset(&ov, 0, sizeof(ov)); ov.hEvent = ev;
    CHECK(!np.ConnectNamedPipe(srv, &ov) && GetLastError() == ERROR_IO_PENDING, "ConnectNamedPipe(overlapped) pending (%lu)", GetLastError());
    cli = np.CreateFileW(NP_NAME_T, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    CHECK(cli != INVALID_HANDLE_VALUE, "client CreateFileW error %lu", GetLastError());
    if (cli == INVALID_HANDLE_VALUE) { CloseHandle(srv); return; }
    CHECK(WaitForSingleObject(ev, 3000) == WAIT_OBJECT_0 && np.GetOverlappedResult(srv, &ov, &n, FALSE), "connect completes");
    {
        ULONG pid = 0;
        CHECK(np.GetNamedPipeClientProcessId(srv, &pid) && pid == GetCurrentProcessId(), "GetNamedPipeClientProcessId");
    }
    {
        HANDLE c2 = np.CreateFileW(NP_NAME_T, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        CHECK(c2 == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY, "second client -> ERROR_PIPE_BUSY (%lu)", GetLastError());
    }

    /* messages: boundaries, peek, partial read */
    CHECK(np.WriteFile(cli, "hello", 5, &n, NULL) && n == 5, "client WriteFile");
    CHECK(np.WriteFile(cli, "world!!", 7, &n, NULL) && n == 7, "client WriteFile #2");
    CHECK(np.PeekNamedPipe(srv, buf, 3, &r, &avail, &left) && r == 3 && avail == 12 && left == 2,
          "PeekNamedPipe read %lu avail %lu left %lu", r, avail, left);
    k = np_read_ov(srv, buf, 3, 2000, &err);
    CHECK(k == 3 && err == ERROR_MORE_DATA && !memcmp(buf, "hel", 3), "partial message read -> ERROR_MORE_DATA (%d, %lu)", k, err);
    k = np_read_ov(srv, buf, sizeof(buf), 2000, &err);
    CHECK(k == 2 && !err && !memcmp(buf, "lo", 2), "rest of message (%d, %lu)", k, err);
    k = np_read_ov(srv, buf, sizeof(buf), 2000, &err);
    CHECK(k == 7 && !err && !memcmp(buf, "world!!", 7), "second message intact (%d, %lu)", k, err);

    /* pending read completed by a later write */
    memset(&ov, 0, sizeof(ov)); ov.hEvent = ev; ResetEvent(ev);
    CHECK(!np.ReadFile(srv, buf, sizeof(buf), &n, &ov) && GetLastError() == ERROR_IO_PENDING, "ReadFile pending");
    np.WriteFile(cli, "x", 1, &n, NULL);
    CHECK(np.GetOverlappedResult(srv, &ov, &n, TRUE) && n == 1 && buf[0] == 'x', "pending read completed (%lu)", n);

    /* cancel */
    memset(&ov, 0, sizeof(ov)); ov.hEvent = ev; ResetEvent(ev);
    np.ReadFile(srv, buf, sizeof(buf), &n, &ov);
    CHECK(np.CancelIoEx(srv, &ov), "CancelIoEx");
    CHECK(!np.GetOverlappedResult(srv, &ov, &n, TRUE) && GetLastError() == ERROR_OPERATION_ABORTED, "cancelled read -> ERROR_OPERATION_ABORTED (%lu)", GetLastError());

    /* TransactNamedPipe (what Crashpad's client uses) */
    mode = PIPE_READMODE_MESSAGE;
    CHECK(np.SetNamedPipeHandleState(cli, &mode, NULL, NULL), "SetNamedPipeHandleState(message)");
    g_np_srv = srv;
    th = CreateThread(NULL, 0, np_echo_thread, NULL, 0, &r);
    n = 0; memset(buf, 0, sizeof(buf));
    CHECK(np.TransactNamedPipe(cli, "ping", 4, buf, sizeof(buf), &n, NULL) && n == 4 && !memcmp(buf, "pong", 4), "TransactNamedPipe ping/pong (%lu)", n);
    WaitForSingleObject(th, 5000); CloseHandle(th);

    /* client closes -> broken pipe; then disconnect */
    CloseHandle(cli);
    k = np_read_ov(srv, buf, sizeof(buf), 2000, &err);
    CHECK(k < 0 && err == ERROR_BROKEN_PIPE, "read after client closed -> ERROR_BROKEN_PIPE (%lu)", err);
    CHECK(np.DisconnectNamedPipe(srv), "DisconnectNamedPipe");

    /* another process */
    {
        STARTUPINFOA si; PROCESS_INFORMATION pi; char cmd[MAX_PATH + 16]; DWORD code = 99;
        memset(&ov, 0, sizeof(ov)); ov.hEvent = ev; ResetEvent(ev);
        np.ConnectNamedPipe(srv, &ov);
        GetModuleFileNameA(NULL, cmd, MAX_PATH); strcat(cmd, " pipechild");
        memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
        if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            BOOL conn = WaitForSingleObject(ev, 10000) == WAIT_OBJECT_0;
            CHECK(conn, "child process connected");
            if (conn) {
                k = np_read_ov(srv, buf, sizeof(buf), 5000, &err);
                CHECK(k == 10 && !memcmp(buf, "from child", 10), "message from child (%d, %lu)", k, err);
                CHECK(np.WriteFile(srv, "to child", 8, &n, NULL) && n == 8, "reply to child");
            }
            WaitForSingleObject(pi.hProcess, 10000);
            GetExitCodeProcess(pi.hProcess, &code);
            CHECK(code == 0, "child process result %lu (0 = ok)", code);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        } else CHECK(0, "CreateProcess(kextest pipechild) error %lu", GetLastError());
        np.DisconnectNamedPipe(srv);
    }
    CloseHandle(srv);
    cli = np.CreateFileW(NP_NAME_T, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(cli == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND, "pipe gone after server close (%lu)", GetLastError());

    /* byte mode stream larger than the ring */
    srv = np.CreateNamedPipeW(L"\\\\.\\pipe\\KexNgStream", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, 0, 0, 0, NULL);
    cli = srv != INVALID_HANDLE_VALUE ? np.CreateFileW(L"\\\\.\\pipe\\KexNgStream", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL) : INVALID_HANDLE_VALUE;
    CHECK(srv != INVALID_HANDLE_VALUE && cli != INVALID_HANDLE_VALUE, "byte-mode pipe");
    if (srv != INVALID_HANDLE_VALUE && cli != INVALID_HANDLE_VALUE) {
        BYTE b[5000]; DWORD total = 0, bad = 0, i, wcode = 1;
        th = CreateThread(NULL, 0, np_stream_writer, cli, 0, &r);
        while (total < 100000) {
            if (!np.ReadFile(srv, b, sizeof(b), &n, NULL) || !n) break;
            for (i = 0; i < n; i++) if (b[i] != (BYTE)((total + i) * 7)) bad++;
            total += n;
        }
        WaitForSingleObject(th, 10000); GetExitCodeThread(th, &wcode); CloseHandle(th);
        CHECK(total == 100000 && !bad && wcode == 0, "100000 bytes streamed (%lu, %lu bad, writer %lu)", total, bad, wcode);
    }
    if (cli != INVALID_HANDLE_VALUE) CloseHandle(cli);
    if (srv != INVALID_HANDLE_VALUE) CloseHandle(srv);
    CloseHandle(ev);

    {   /* build 121: Windows 98 puts a new event at the address of an event just destroyed. A pipe whose server end
         * was closed must not claim such a new event as its end (build 120: Chrome's renderers had ordinary events
         * taken for dead pipe ends, and a dead pipe kept "alive" by them). kexnt's CloseHandle, as Chrome uses it. */
        T_H kclose = (T_H)GetProcAddress(kx, "CloseHandle");
        HANDLE s3, c3, evs[16]; int k, piped = 0, piped2 = 0; char b = 0; DWORD got = 0; BOOL rok;
        s3 = np.CreateNamedPipeW(L"\\\\.\\pipe\\KexNgStale", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, 0, 0, 0, NULL);
        c3 = s3 != INVALID_HANDLE_VALUE ? np.CreateFileW(L"\\\\.\\pipe\\KexNgStale", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL) : INVALID_HANDLE_VALUE;
        CHECK(kclose && s3 != INVALID_HANDLE_VALUE && c3 != INVALID_HANDLE_VALUE, "pipe for the reused-address test");
        if (kclose && s3 != INVALID_HANDLE_VALUE && c3 != INVALID_HANDLE_VALUE) {
            kclose(s3);                                            /* server end destroyed, client still open */
            for (k = 0; k < 16; k++) { evs[k] = CreateEventA(NULL, TRUE, FALSE, NULL); if (np.GetFileType(evs[k]) == FILE_TYPE_PIPE) piped++; }
            CHECK(piped == 0, "new events after a pipe's server end closed are not pipe ends (%d of 16 taken for one)", piped);
            rok = np.ReadFile(c3, &b, 1, &got, NULL);
            CHECK(!rok && GetLastError() == ERROR_BROKEN_PIPE, "client read after the server end closed -> ERROR_BROKEN_PIPE (%d, %lu)", rok, GetLastError());
            kclose(c3);
            for (k = 0; k < 16; k++) { HANDLE e2 = CreateEventA(NULL, TRUE, FALSE, NULL); if (np.GetFileType(e2) == FILE_TYPE_PIPE) piped2++; kclose(e2); }
            CHECK(piped2 == 0, "new events after the client end closed too are not pipe ends (%d of 16)", piped2);
            /* a new pipe made now works (its end may sit at a dead end's old address) */
            s3 = np.CreateNamedPipeW(L"\\\\.\\pipe\\KexNgStale2", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, 0, 0, 0, NULL);
            c3 = s3 != INVALID_HANDLE_VALUE ? np.CreateFileW(L"\\\\.\\pipe\\KexNgStale2", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL) : INVALID_HANDLE_VALUE;
            if (s3 != INVALID_HANDLE_VALUE && c3 != INVALID_HANDLE_VALUE) {
                DWORD w = 0, v = 0x4B584E47, rd = 0, n2 = 0;
                BOOL wok = np.WriteFile(c3, &v, 4, &w, NULL), rok2 = np.ReadFile(s3, &rd, 4, &n2, NULL);
                CHECK(wok && rok2 && w == 4 && n2 == 4 && rd == v, "new pipe after the dead one: 4 bytes through (%d %d %lu %lu %08lx)", wok, rok2, w, n2, rd);
            } else CHECK(0, "new pipe after the dead one (%lu)", GetLastError());
            if (c3 != INVALID_HANDLE_VALUE) kclose(c3);
            if (s3 != INVALID_HANDLE_VALUE) kclose(s3);
            for (k = 0; k < 16; k++) if (evs[k]) kclose(evs[k]);
        }
    }
}


/* ---------------- LoadLibrary of a DLL with static TLS (chrome.dll has one) ---------------- */
/* ---- kextest bigimage: which PE layout limit makes Windows 98 refuse chrome.dll (error 11)? ----
 * Writes synthetic DLLs (headers only; section contents are whatever the disk had - nothing is run)
 * to %TEMP%\KXBIG.DLL, extends them with SetEndOfFile, loads each with DONT_RESOLVE_DLL_REFERENCES
 * and deletes it again. */
typedef struct { DWORD va, vsize, raw, rawsize, flags; const char *name; } BIGSEC;
typedef struct { const char *what; int n; BIGSEC s[11]; } BIGCASE;
#define CODE 0x60000020
#define DATA 0xC0000040
#define RDAT 0x40000040
static const BIGCASE g_big[] = {
    { "control: 4 KB image", 1, {{0x1000, 0x1000, 0x400, 0x200, CODE, ".text"}} },
    { "A: 277 MB in memory, tiny file", 1, {{0x1000, 0x114A0000, 0x400, 0x200, CODE, ".text"}} },
    { "B: one 64 MB section in the file", 1, {{0x1000, 0x4000000, 0x400, 0x4000000, CODE, ".text"}} },
    { "C: one 240 MB section in the file", 1, {{0x1000, 0xF000000, 0x400, 0xF000000, CODE, ".text"}} },
    { "D: C + small section, file offset below 256 MB", 2, {{0x1000, 0xF000000, 0x400, 0xF000000, CODE, ".text"},
        {0xF001000, 0x1000, 0xF000400, 0x200, DATA, ".data"}} },
    { "E: C + small section, file offset above 256 MB", 2, {{0x1000, 0xF000000, 0x400, 0xF000000, CODE, ".text"},
        {0xF001000, 0x1000, 0x10000400, 0x200, DATA, ".data"}} },
    { "F: one section crossing the 256 MB file offset", 1, {{0x1000, 0x10100000, 0x400, 0x10100000, CODE, ".text"}} },
    { "G: chrome.dll 159 section table", 11, {
        {0x00001000, 0x0eb21776, 0x00000400, 0x0eb21800, CODE, ".text"},
        {0x0eb23000, 0x01d6dbac, 0x0eb21c00, 0x01d6dc00, RDAT, ".rdata"},
        {0x10891000, 0x002411d8, 0x1088f800, 0x000c5000, DATA, ".data"},
        {0x10ad3000, 0x00000060, 0x10954800, 0x00000200, RDAT, ".eh_fram"},
        {0x10ad4000, 0x00000080, 0x10954a00, 0x00000200, DATA, ".fptable"},
        {0x10ad5000, 0x000004ad, 0x10954c00, 0x00000600, DATA, ".tls"},
        {0x10ad6000, 0x00000028, 0x10955200, 0x00000200, DATA, "CPADinfo"},
        {0x10ad7000, 0x00000167, 0x10955400, 0x00000200, CODE, "malloc_h"},
        {0x10ad8000, 0x00000083, 0x10955600, 0x00000200, RDAT, "prot"},
        {0x10ad9000, 0x00024330, 0x10955800, 0x00024400, RDAT, ".rsrc"},
        {0x10afe000, 0x009aaa5c, 0x10979c00, 0x009aac00, 0x42000040, ".reloc"}} },
};

static void build_big_hdr(const BIGCASE *c, BYTE *hdr, DWORD *filesize)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hdr;
    IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(hdr + 0x40);
    IMAGE_SECTION_HEADER *sh = (IMAGE_SECTION_HEADER *)(nt + 1);
    DWORD end = 0x400, top = 0; int i;
    memset(hdr, 0, 0x400);
    dos->e_magic = IMAGE_DOS_SIGNATURE; dos->e_lfanew = 0x40;
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    nt->FileHeader.NumberOfSections = (WORD)c->n;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    nt->FileHeader.Characteristics = 0x2122;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    nt->OptionalHeader.MajorLinkerVersion = 14;
    nt->OptionalHeader.ImageBase = 0x10000000;
    nt->OptionalHeader.SectionAlignment = 0x1000;
    nt->OptionalHeader.FileAlignment = 0x200;
    nt->OptionalHeader.MajorOperatingSystemVersion = 4;
    nt->OptionalHeader.MajorSubsystemVersion = 4;
    nt->OptionalHeader.SizeOfHeaders = 0x400;
    nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    nt->OptionalHeader.SizeOfStackReserve = 0x100000; nt->OptionalHeader.SizeOfStackCommit = 0x1000;
    nt->OptionalHeader.SizeOfHeapReserve = 0x100000; nt->OptionalHeader.SizeOfHeapCommit = 0x1000;
    nt->OptionalHeader.NumberOfRvaAndSizes = 16;
    for (i = 0; i < c->n; i++) {
        memcpy(sh[i].Name, c->s[i].name, strlen(c->s[i].name) > 8 ? 8 : strlen(c->s[i].name));
        sh[i].Misc.VirtualSize = c->s[i].vsize; sh[i].VirtualAddress = c->s[i].va;
        sh[i].SizeOfRawData = c->s[i].rawsize; sh[i].PointerToRawData = c->s[i].raw;
        sh[i].Characteristics = c->s[i].flags;
        if (c->s[i].raw + c->s[i].rawsize > end) end = c->s[i].raw + c->s[i].rawsize;
        if (c->s[i].va + c->s[i].vsize > top) top = c->s[i].va + c->s[i].vsize;
        if (c->s[i].flags & IMAGE_SCN_CNT_CODE) nt->OptionalHeader.SizeOfCode += c->s[i].rawsize;
    }
    nt->OptionalHeader.SizeOfImage = (top + 0xFFF) & ~0xFFFu;
    nt->OptionalHeader.BaseOfCode = 0x1000;
    *filesize = end;
}

static BOOL write_big(const char *path, const BIGCASE *c, DWORD *filesize)
{
    BYTE hdr[0x400]; DWORD end, wr; HANDLE f;
    build_big_hdr(c, hdr, &end);
    *filesize = end;
    f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    if (!WriteFile(f, hdr, sizeof(hdr), &wr, NULL) || wr != sizeof(hdr) ||
        SetFilePointer(f, (LONG)end, NULL, FILE_BEGIN) == 0xFFFFFFFF || !SetEndOfFile(f)) {
        CloseHandle(f); DeleteFileA(path); return FALSE;
    }
    CloseHandle(f);
    return TRUE;
}

static int big_image(void)
{
    char dir[MAX_PATH], path[MAX_PATH]; ULARGE_INTEGER avail, tot, fr; unsigned i;
    GetTempPathA(MAX_PATH, dir);
    strcpy(path, dir); strcat(path, "KXBIG.DLL");
    LOG("[big images]  writing test DLLs to %s\n", path);
    if (GetDiskFreeSpaceExA(dir, &avail, &tot, &fr))
        LOG("    free space there: %lu MB\n", (unsigned long)(avail.QuadPart >> 20));
    else avail.QuadPart = 0xFFFFFFFFu;
    for (i = 0; i < sizeof(g_big) / sizeof(g_big[0]); i++) {
        const BIGCASE *c = &g_big[i]; DWORD fsz = 0, t0, t1, e1 = 0, e2 = 0; HMODULE h1, h2 = NULL;
        BYTE probe[0x400]; DWORD dummy;
        write_big(path, c, &fsz);       /* computes the size even when it fails */
        DeleteFileA(path);
        if ((ULONGLONG)fsz + (16u << 20) > avail.QuadPart) {
            LOG("    %-48s SKIPPED (needs %lu MB free)\n", c->what, fsz >> 20); continue;
        }
        if (!write_big(path, c, &fsz)) { LOG("    %-48s cannot write file (error %lu)\n", c->what, GetLastError()); continue; }
        (void)probe; (void)dummy;
        t0 = GetTickCount();
        SetLastError(0);
        h1 = LoadLibraryExA(path, NULL, DONT_RESOLVE_DLL_REFERENCES); e1 = GetLastError();
        t1 = GetTickCount();
        if (h1) FreeLibrary(h1);
        if (h1) {                       /* the full loader path too (no imports, no entry point) */
            SetLastError(0); h2 = LoadLibraryA(path); e2 = GetLastError();
            if (h2) FreeLibrary(h2);
        }
        LOG("    %-48s file %4lu MB  DONT_RESOLVE: %s err %lu (%lu ms)", c->what, fsz >> 20,
            h1 ? "ok    " : "FAILED", h1 ? 0 : e1, t1 - t0);
        if (h1) LOG("  LoadLibrary: %s err %lu", h2 ? "ok" : "FAILED", h2 ? 0 : e2);
        LOG("\n");
        DeleteFileA(path);
    }
    LOG("\n");
    return 0;
}

/* ---- kextest realimage [path]: which header field of the REAL chrome.dll does Windows 98 refuse? ----
 * Copies the DLL to %TEMP%\KXREAL.DLL, then for each variant rewrites only the first 0x400 bytes (headers),
 * loads with DONT_RESOLVE_DLL_REFERENCES (no code runs), frees it and restores the header. */
static const char *g_dirnames[16] = { "export", "import", "resource", "exception", "security", "basereloc",
    "debug", "arch", "globalptr", "TLS", "loadconfig", "boundimport", "IAT", "delayimport", "COM", "reserved" };

static BOOL put_hdr(const char *path, const BYTE *hdr)
{
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD wr = 0;
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(f, hdr, 0x400, &wr, NULL);
    CloseHandle(f);
    return wr == 0x400;
}

/* child mode "kextest realtry <path> <flags>": one load attempt in a fresh process.
 * Exit code: 0 loaded, 1000 + error failed. */
static int real_try(const char *path, DWORD flags)
{
    HMODULE h; DWORD e;
    SetLastError(0);
    h = LoadLibraryExA(path, NULL, flags); e = GetLastError();
    if (h) { FreeLibrary(h); return 0; }
    return 1000 + (int)e;
}

static void mem_report(void)
{
    MEMORYSTATUS ms; ms.dwLength = sizeof(ms); GlobalMemoryStatus(&ms);
    LOG("    memory: RAM %lu MB (%lu free), page file %lu MB (%lu free), address space %lu MB free\n",
        (unsigned long)(ms.dwTotalPhys >> 20), (unsigned long)(ms.dwAvailPhys >> 20),
        (unsigned long)(ms.dwTotalPageFile >> 20), (unsigned long)(ms.dwAvailPageFile >> 20),
        (unsigned long)(ms.dwAvailVirtual >> 20));
}

/* run one load attempt of path in a separate kextest process (a failed load can leave memory behind) */
static DWORD child_load(const char *path, DWORD flags)
{
    char cmd[MAX_PATH * 2 + 32]; STARTUPINFOA si; PROCESS_INFORMATION pi; DWORD code = 0xFFFFFFFF;
    GetModuleFileNameA(NULL, cmd, MAX_PATH);
    sprintf(cmd + strlen(cmd), " realtry %s %lu", path, (unsigned long)flags);
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return 0xFFFFFFFE;
    if (WaitForSingleObject(pi.hProcess, 120000) == WAIT_TIMEOUT) { TerminateProcess(pi.hProcess, 0xFFFF); code = 0xFFFFFFFD; }
    else GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return code;
}

static void log_child(const char *what, DWORD code)
{
    LOG("    %-44s ", what);
    if (code == 0) LOG("LOADS\n");
    else if (code >= 1000 && code < 0x10000) LOG("FAILED error %lu\n", code - 1000);
    else if (code == 0xFFFFFFFE) LOG("cannot start child process\n");
    else if (code == 0xFFFFFFFD) LOG("child hung (killed after 2 min)\n");
    else LOG("child crashed (%08lx)\n", code);
}

static void try_variant(const char *path, const BYTE *orig, const BYTE *hdr, const char *what)
{
    if (!put_hdr(path, hdr)) { LOG("    %-44s cannot write header (error %lu)\n", what, GetLastError()); return; }
    log_child(what, child_load(path, DONT_RESOLVE_DLL_REFERENCES));
    put_hdr(path, orig);
}

static void region_report(DWORD base, DWORD size)
{
    MEMORY_BASIC_INFORMATION mbi; DWORD a = base; int n = 0;
    LOG("    address range %08lx-%08lx before loading:\n", base, base + size);
    while (a < base + size && n < 8 && VirtualQuery((LPCVOID)(ULONG_PTR)a, &mbi, sizeof(mbi))) {
        LOG("      %08lx size %08lx %s\n", (unsigned long)(ULONG_PTR)mbi.BaseAddress, (unsigned long)mbi.RegionSize,
            mbi.State == MEM_FREE ? "free" : mbi.State == MEM_RESERVE ? "RESERVED" : "COMMITTED");
        a = (DWORD)(ULONG_PTR)mbi.BaseAddress + (DWORD)mbi.RegionSize; n++;
        if (!mbi.RegionSize) break;
    }
}

static int real_image(const char *src)
{
    char dir[MAX_PATH], path[MAX_PATH]; BYTE orig[0x400], v[0x400]; HANDLE f; DWORD rd = 0, fsz; int i;
    IMAGE_NT_HEADERS32 *nt; HMODULE h;
    LOG("[real image]  %s\n", src);
    f = CreateFileA(src, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { LOG("    cannot open it (error %lu)\n\n", GetLastError()); return 1; }
    ReadFile(f, orig, sizeof(orig), &rd, NULL); CloseHandle(f);
    nt = (IMAGE_NT_HEADERS32 *)(orig + *(LONG *)(orig + 0x3C));
    if (rd != sizeof(orig) || *(WORD *)orig != IMAGE_DOS_SIGNATURE || (BYTE *)nt + sizeof(*nt) > orig + sizeof(orig) ||
        nt->Signature != IMAGE_NT_SIGNATURE) { LOG("    not a PE file\n\n"); return 1; }
    LOG("    ImageBase %08lx SizeOfImage %08lx entry %08lx checksum %08lx DllCharacteristics %04x\n",
        nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage, nt->OptionalHeader.AddressOfEntryPoint,
        nt->OptionalHeader.CheckSum, nt->OptionalHeader.DllCharacteristics);
    region_report(nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage);
    mem_report();
    (void)h;
    LOG("    each try below runs in its own new process\n");
    log_child("original file, DONT_RESOLVE", child_load(src, DONT_RESOLVE_DLL_REFERENCES));
    log_child("original file, DONT_RESOLVE (again)", child_load(src, DONT_RESOLVE_DLL_REFERENCES));
    log_child("original file, AS_DATAFILE", child_load(src, LOAD_LIBRARY_AS_DATAFILE));
    mem_report();

    GetTempPathA(MAX_PATH, dir); strcpy(path, dir); strcat(path, "KXREAL.DLL");
    SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL); DeleteFileA(path);
    LOG("    copying to %s ...\n", path);
    if (!CopyFileA(src, path, FALSE)) { LOG("    copy failed (error %lu)\n\n", GetLastError()); return 1; }
    SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);

    nt = (IMAGE_NT_HEADERS32 *)(v + *(LONG *)(orig + 0x3C));
#define FRESH() memcpy(v, orig, sizeof(v))
    build_big_hdr(&g_big[7], v, &fsz);  /* kextest bigimage case G: same sections, nothing else */
    try_variant(path, orig, v, "synthetic header (bigimage G) on real data");
    FRESH(); try_variant(path, orig, v, "copy, unchanged");
    FRESH(); memset(nt->OptionalHeader.DataDirectory, 0, sizeof(nt->OptionalHeader.DataDirectory));
    try_variant(path, orig, v, "all 16 data directories zeroed");
    for (i = 0; i < 16; i++) {
        char what[64];
        FRESH();
        if (!nt->OptionalHeader.DataDirectory[i].VirtualAddress && !nt->OptionalHeader.DataDirectory[i].Size) continue;
        nt->OptionalHeader.DataDirectory[i].VirtualAddress = 0; nt->OptionalHeader.DataDirectory[i].Size = 0;
        sprintf(what, "only %s directory zeroed", g_dirnames[i]);
        try_variant(path, orig, v, what);
    }
    FRESH(); nt->OptionalHeader.DllCharacteristics = 0; try_variant(path, orig, v, "DllCharacteristics 0");
    FRESH(); nt->OptionalHeader.MajorOperatingSystemVersion = 4; nt->OptionalHeader.MinorOperatingSystemVersion = 0;
    nt->OptionalHeader.MajorSubsystemVersion = 4; nt->OptionalHeader.MinorSubsystemVersion = 0;
    try_variant(path, orig, v, "OS + subsystem version 4.0");
    FRESH(); nt->OptionalHeader.CheckSum = 0; try_variant(path, orig, v, "checksum 0");
    FRESH(); nt->OptionalHeader.ImageBase = 0x30000000; try_variant(path, orig, v, "ImageBase 30000000 (forces relocation)");
    /* the synthetic G file itself (no real data) as a control, in a child too */
    if (write_big(path, &g_big[7], &fsz)) log_child("synthetic G file (no real data), control", child_load(path, DONT_RESOLVE_DLL_REFERENCES));
    mem_report();
#undef FRESH
    DeleteFileA(path);
    LOG("\n");
    return 0;
}

/* ---- kextest rsrcimage: does Windows 98 refuse a resource directory placed past some RVA? ----
 * Small synthetic DLLs (no code, no imports): .text at 0x1000, .rsrc at RVA x with a tiny valid resource
 * tree (empty root, or one RT_VERSION entry with 4 bytes of data). Each load runs in its own process. */
static BOOL write_rsrc_dll(const char *path, DWORD x, BOOL one_entry)
{
    BYTE hdr[0x400], rs[0x200]; DWORD wr, rsize; HANDLE f;
    IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(hdr + 0x40);
    IMAGE_SECTION_HEADER *sh = (IMAGE_SECTION_HEADER *)(nt + 1);
    DWORD *d = (DWORD *)rs;
    memset(hdr, 0, sizeof(hdr)); memset(rs, 0, sizeof(rs));
    ((IMAGE_DOS_HEADER *)hdr)->e_magic = IMAGE_DOS_SIGNATURE; ((IMAGE_DOS_HEADER *)hdr)->e_lfanew = 0x40;
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386; nt->FileHeader.NumberOfSections = 2;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32); nt->FileHeader.Characteristics = 0x2122;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    nt->OptionalHeader.ImageBase = 0x10000000;
    nt->OptionalHeader.SectionAlignment = 0x1000; nt->OptionalHeader.FileAlignment = 0x200;
    nt->OptionalHeader.MajorOperatingSystemVersion = 4; nt->OptionalHeader.MajorSubsystemVersion = 4;
    nt->OptionalHeader.SizeOfHeaders = 0x400; nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    nt->OptionalHeader.SizeOfStackReserve = 0x100000; nt->OptionalHeader.SizeOfStackCommit = 0x1000;
    nt->OptionalHeader.SizeOfHeapReserve = 0x100000; nt->OptionalHeader.SizeOfHeapCommit = 0x1000;
    nt->OptionalHeader.NumberOfRvaAndSizes = 16;
    nt->OptionalHeader.SizeOfImage = x + 0x1000;
    memcpy(sh[0].Name, ".text", 5); sh[0].Misc.VirtualSize = 0x10; sh[0].VirtualAddress = 0x1000;
    sh[0].SizeOfRawData = 0x200; sh[0].PointerToRawData = 0x400; sh[0].Characteristics = 0x60000020;
    rs[0x200 - 1] = 0;
    if (one_entry) {   /* root -> type 16 -> name 1 -> lang 0409 -> data entry */
        d[0x0C/4] = 1 << 16;                 d[0x10/4] = 16;    d[0x14/4] = 0x80000018;
        d[0x24/4] = 1 << 16;                 d[0x28/4] = 1;     d[0x2C/4] = 0x80000030;
        d[0x3C/4] = 1 << 16;                 d[0x40/4] = 0x409; d[0x44/4] = 0x48;
        d[0x48/4] = x + 0x60; d[0x4C/4] = 4; d[0x60/4] = 0x12345678;
        rsize = 0x64;
    } else rsize = 0x10;                     /* empty root directory */
    memcpy(sh[1].Name, ".rsrc", 5); sh[1].Misc.VirtualSize = rsize; sh[1].VirtualAddress = x;
    sh[1].SizeOfRawData = 0x200; sh[1].PointerToRawData = 0x600; sh[1].Characteristics = 0x40000040;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = x;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = rsize;
    f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(f, hdr, sizeof(hdr), &wr, NULL); WriteFile(f, rs, sizeof(rs), &wr, NULL);   /* .text = zeros */
    WriteFile(f, rs, sizeof(rs), &wr, NULL);
    CloseHandle(f);
    return TRUE;
}

static int rsrc_image(void)
{
    static const DWORD rvas[] = { 0x2000, 0x01000000, 0x04000000, 0x08000000, 0x0FFFF000,
                                  0x10000000, 0x10001000, 0x10AD9000, 0x20000000 };
    char dir[MAX_PATH], path[MAX_PATH]; unsigned i; int e;
    GetTempPathA(MAX_PATH, dir); strcpy(path, dir); strcat(path, "KXRSRC.DLL");
    LOG("[resource RVA]  %s, each load in its own process\n", path);
    for (e = 0; e < 2; e++)
        for (i = 0; i < sizeof(rvas) / sizeof(rvas[0]); i++) {
            char what[80];
            sprintf(what, "resources at RVA %08lx, %s", (unsigned long)rvas[i], e ? "one entry" : "empty root");
            if (!write_rsrc_dll(path, rvas[i], e)) { LOG("    %-44s cannot write (error %lu)\n", what, GetLastError()); continue; }
            log_child(what, child_load(path, DONT_RESOLVE_DLL_REFERENCES));
        }
    DeleteFileA(path);
    LOG("\n");
    return 0;
}

/* ---- kextest rsrcbisect [path]: which part of chrome.dll's resource tree does Windows 98 refuse? ----
 * Dumps the resource tree, copies the DLL to %TEMP%\KXRSRC2.DLL and, in that copy only, rewrites the
 * resource directory headers so that only some entries remain (first k types / one type / one name of a
 * type). Each variant is loaded in its own process. Error 11 = refused; 1157 = got past the check (the
 * copy has no chrome_elf.dll beside it, so its imports fail before any code could run). */
static BYTE *g_rs; static DWORD g_rslen, g_rsva, g_rsfo;

static const char *rs_name(DWORD e, char *buf)
{
    if (e & 0x80000000) {
        DWORD o = e & 0x7FFFFFFF; WORD n, i;
        if (o + 2 > g_rslen) { strcpy(buf, "\"?bad name\""); return buf; }
        n = *(WORD *)(g_rs + o); buf[0] = '"';
        for (i = 0; i < n && i < 24 && o + 2 + i * 2 + 2 <= g_rslen; i++) buf[1 + i] = (char)*(WORD *)(g_rs + o + 2 + i * 2);
        buf[1 + i] = '"'; buf[2 + i] = 0;
    } else sprintf(buf, "%lu", (unsigned long)e);
    return buf;
}

static DWORD rs_count(DWORD dir) { return dir + 16 > g_rslen ? 0 : (DWORD)*(WORD *)(g_rs + dir + 12) + *(WORD *)(g_rs + dir + 14); }

/* walk a subtree; returns number of data entries, adds sizes, counts problems */
static DWORD rs_walk(DWORD dir, int depth, DWORD *bytes, DWORD *bad)
{
    DWORD n = rs_count(dir), i, leaves = 0;
    if (depth > 3 || dir + 16 + n * 8 > g_rslen) { (*bad)++; return 0; }
    for (i = 0; i < n; i++) {
        DWORD off = *(DWORD *)(g_rs + dir + 16 + i * 8 + 4);
        if (off & 0x80000000) leaves += rs_walk(off & 0x7FFFFFFF, depth + 1, bytes, bad);
        else if (off + 16 > g_rslen) (*bad)++;
        else {
            DWORD rva = *(DWORD *)(g_rs + off), sz = *(DWORD *)(g_rs + off + 4);
            if (rva < g_rsva || rva + sz > g_rsva + g_rslen) (*bad)++;
            *bytes += sz; leaves++;
        }
    }
    return leaves;
}

static BOOL put_bytes(const char *path, DWORD off, const void *p, DWORD n)
{
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); DWORD wr = 0;
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    SetFilePointer(f, (LONG)off, NULL, FILE_BEGIN); WriteFile(f, p, n, &wr, NULL); CloseHandle(f);
    return wr == n;
}

/* write directory 'dir' of the copy keeping only entries [first, first+cnt) moved to the front */
static void rs_keep(const char *path, DWORD dir, DWORD first, DWORD cnt)
{
    BYTE tmp[16 + 8 * 64]; WORD named = *(WORD *)(g_rs + dir + 12), nn = 0, ni = 0; DWORD i;
    if (cnt > 64) cnt = 64;
    memcpy(tmp, g_rs + dir, 16);
    for (i = 0; i < cnt; i++) { memcpy(tmp + 16 + i * 8, g_rs + dir + 16 + (first + i) * 8, 8); if (first + i < named) nn++; else ni++; }
    *(WORD *)(tmp + 12) = nn; *(WORD *)(tmp + 14) = ni;
    put_bytes(path, g_rsfo + dir, tmp, 16 + cnt * 8);
}
static void rs_restore(const char *path, DWORD dir) { put_bytes(path, g_rsfo + dir, g_rs + dir, 16 + rs_count(dir) * 8); }

static BOOL refused(DWORD code) { return code == 1000 + ERROR_BAD_FORMAT; }

static int rsrc_bisect(const char *src)
{
    char path[MAX_PATH], what[96], nm[40]; BYTE hdr[0x400]; HANDLE f; DWORD rd, rva, size, ntypes, t, k, code, tries = 0;
    IMAGE_NT_HEADERS32 *nt; IMAGE_SECTION_HEADER *sh; int i; int bad_types = 0;
    LOG("[resource bisect]  %s\n", src);
    f = CreateFileA(src, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { LOG("    cannot open (error %lu)\n\n", GetLastError()); return 1; }
    ReadFile(f, hdr, sizeof(hdr), &rd, NULL);
    nt = (IMAGE_NT_HEADERS32 *)(hdr + *(LONG *)(hdr + 0x3C)); sh = IMAGE_FIRST_SECTION(nt);
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
    size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (rva >= sh[i].VirtualAddress && rva < sh[i].VirtualAddress + sh[i].SizeOfRawData) break;
    if (!rva || i == nt->FileHeader.NumberOfSections) { LOG("    no resource section found\n\n"); CloseHandle(f); return 1; }
    g_rsva = rva; g_rslen = sh[i].SizeOfRawData - (rva - sh[i].VirtualAddress); g_rsfo = sh[i].PointerToRawData + (rva - sh[i].VirtualAddress);
    LOG("    resource dir rva %08lx size %08lx, in section %.8s (va %08lx raw %08lx), %lu bytes read\n",
        rva, size, sh[i].Name, sh[i].VirtualAddress, sh[i].PointerToRawData, g_rslen);
    g_rs = (BYTE *)malloc(g_rslen);
    SetFilePointer(f, (LONG)g_rsfo, NULL, FILE_BEGIN); ReadFile(f, g_rs, g_rslen, &rd, NULL); CloseHandle(f);
    LOG("    root: %u named + %u id types\n", *(WORD *)(g_rs + 12), *(WORD *)(g_rs + 14));
    ntypes = rs_count(0);
    for (t = 0; t < ntypes && t < 64; t++) {
        DWORD e = *(DWORD *)(g_rs + 16 + t * 8), off = *(DWORD *)(g_rs + 16 + t * 8 + 4), bytes = 0, bad = 0, leaves = 0, nn = 0;
        if (off & 0x80000000) { nn = rs_count(off & 0x7FFFFFFF); leaves = rs_walk(off & 0x7FFFFFFF, 1, &bytes, &bad); }
        LOG("    type %-12s %4lu names %4lu items %8lu bytes%s\n", rs_name(e, nm), nn, leaves, bytes, bad ? "  <-- odd entries" : "");
        if ((off & 0x80000000) && nn <= 6) {
            DWORD sd = off & 0x7FFFFFFF;
            for (k = 0; k < nn; k++) {
                DWORD e2 = *(DWORD *)(g_rs + sd + 16 + k * 8), o2 = *(DWORD *)(g_rs + sd + 16 + k * 8 + 4), b2 = 0, x2 = 0, l2 = 0;
                if (o2 & 0x80000000) l2 = rs_walk(o2 & 0x7FFFFFFF, 2, &b2, &x2);
                LOG("        name %-24s %lu lang(s) %lu bytes\n", rs_name(e2, nm), l2, b2);
            }
        }
    }
    GetTempPathA(MAX_PATH, path); strcat(path, "KXRSRC2.DLL");
    SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL); DeleteFileA(path);
    LOG("    copying to %s ...\n", path);
    if (!CopyFileA(src, path, FALSE)) { LOG("    copy failed (error %lu)\n\n", GetLastError()); return 1; }
    SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
    LOG("    (11 = refused; 1157 = passed the check, then could not find chrome_elf.dll - expected)\n");
    log_child("copy, unchanged", child_load(path, DONT_RESOLVE_DLL_REFERENCES));
    rs_keep(path, 0, 0, 0); log_child("no types at all", child_load(path, DONT_RESOLVE_DLL_REFERENCES)); rs_restore(path, 0);
    for (k = 1; k < ntypes && k <= 64; k++) {
        sprintf(what, "first %lu types only", k);
        rs_keep(path, 0, 0, k); log_child(what, code = child_load(path, DONT_RESOLVE_DLL_REFERENCES)); rs_restore(path, 0);
        if (refused(code)) break;
    }
    for (t = 0; t < ntypes && t < 64; t++) {
        DWORD off = *(DWORD *)(g_rs + 16 + t * 8 + 4);
        sprintf(what, "only type %s", rs_name(*(DWORD *)(g_rs + 16 + t * 8), nm));
        rs_keep(path, 0, t, 1); code = child_load(path, DONT_RESOLVE_DLL_REFERENCES); log_child(what, code);
        if (refused(code) && (off & 0x80000000) && bad_types++ < 3) {
            DWORD sd = off & 0x7FFFFFFF, nn = rs_count(sd);
            for (k = 0; k < nn && tries < 80; k++, tries++) {
                char n2[40];
                sprintf(what, "  only %s / %s", nm, rs_name(*(DWORD *)(g_rs + sd + 16 + k * 8), n2));
                rs_keep(path, sd, k, 1); log_child(what, child_load(path, DONT_RESOLVE_DLL_REFERENCES)); rs_restore(path, sd);
            }
            if (nn > 1) { /* first k names, to catch a count limit */
                for (k = 1; k < nn && k <= 64; k++) {
                    sprintf(what, "  %s: first %lu names", nm, k);
                    rs_keep(path, sd, 0, k); code = child_load(path, DONT_RESOLVE_DLL_REFERENCES); rs_restore(path, sd);
                    if (refused(code)) { log_child(what, code); break; }
                }
            }
        }
        rs_restore(path, 0);
    }
    DeleteFileA(path); free(g_rs);
    LOG("\n");
    return 0;
}

/* ---- kextest fileoffs: are section bytes stored past 256 MB in the file loaded correctly? ----
 * Synthetic DLL: .text at 0x1000, then section 2 at RVA 0x2000 (0x3000 bytes) whose file bytes sit at offset R
 * and hold a pattern (DWORD at file offset o = o ^ 0xA5C3E1F7). Kind "data" = writable data section,
 * "rsrc" = read-only section that is also the resource directory (empty root in its first 16 bytes - the
 * loader walks it at load time). Each file is loaded twice, each time in a new process: with kexnt's
 * big-file fix and with it switched off (KEXNG_NOBIGSEC=1), and the child compares the section bytes. */
#define OFF_KEY 0xA5C3E1F7UL
static BOOL write_off_dll(const char *path, DWORD R, BOOL rsrc)
{
    BYTE hdr[0x400], *buf; DWORD wr, i; HANDLE f; BOOL ok;
    IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(hdr + 0x40);
    IMAGE_SECTION_HEADER *sh = (IMAGE_SECTION_HEADER *)(nt + 1);
    memset(hdr, 0, sizeof(hdr));
    ((IMAGE_DOS_HEADER *)hdr)->e_magic = IMAGE_DOS_SIGNATURE; ((IMAGE_DOS_HEADER *)hdr)->e_lfanew = 0x40;
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386; nt->FileHeader.NumberOfSections = 2;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32); nt->FileHeader.Characteristics = 0x2122;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC; nt->OptionalHeader.ImageBase = 0x10000000;
    nt->OptionalHeader.SectionAlignment = 0x1000; nt->OptionalHeader.FileAlignment = 0x200;
    nt->OptionalHeader.MajorOperatingSystemVersion = 4; nt->OptionalHeader.MajorSubsystemVersion = 4;
    nt->OptionalHeader.SizeOfHeaders = 0x400; nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    nt->OptionalHeader.SizeOfStackReserve = 0x100000; nt->OptionalHeader.SizeOfStackCommit = 0x1000;
    nt->OptionalHeader.SizeOfHeapReserve = 0x100000; nt->OptionalHeader.SizeOfHeapCommit = 0x1000;
    nt->OptionalHeader.NumberOfRvaAndSizes = 16; nt->OptionalHeader.SizeOfImage = 0x5000;
    memcpy(sh[0].Name, ".text", 5); sh[0].Misc.VirtualSize = 0x10; sh[0].VirtualAddress = 0x1000;
    sh[0].SizeOfRawData = 0x200; sh[0].PointerToRawData = 0x400; sh[0].Characteristics = 0x60000020;
    memcpy(sh[1].Name, rsrc ? ".rsrc" : ".data", 5); sh[1].Misc.VirtualSize = 0x3000; sh[1].VirtualAddress = 0x2000;
    sh[1].SizeOfRawData = 0x3000; sh[1].PointerToRawData = R; sh[1].Characteristics = rsrc ? 0x40000040 : 0xC0000040;
    if (rsrc) { nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = 0x2000;
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 0x10; }
    if (!(buf = (BYTE *)malloc(0x3000))) return FALSE;
    for (i = 0; i < 0x3000; i += 4) *(DWORD *)(buf + i) = (R + i) ^ OFF_KEY;
    if (rsrc) memset(buf, 0, 16);                      /* empty resource root */
    f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { free(buf); return FALSE; }
    ok = WriteFile(f, hdr, sizeof(hdr), &wr, NULL) && WriteFile(f, buf, 0x200, &wr, NULL) &&
         SetFilePointer(f, (LONG)R, NULL, FILE_BEGIN) != 0xFFFFFFFF && WriteFile(f, buf, 0x3000, &wr, NULL) && wr == 0x3000;
    CloseHandle(f); free(buf);
    return ok;
}

/* child "kextest offtry <path>": 0 ok, 2 bytes differ, 3 unreadable, 1000+error load failed;
 * +0x100000 when kexnt's big-file hook was live in this process */
static int off_try(const char *path)
{
    HMODULE h, kn; BYTE *p; IMAGE_NT_HEADERS32 *nt; IMAGE_SECTION_HEADER *sh; DWORD R, i, from; int r = 0, live = 0;
    typedef LONG (WINAPI *T_BS)(PDWORD, PDWORD); T_BS bs; DWORD calls = 0, fails = 0; LONG st = 99;
    int extra;
    SetLastError(0);
    h = LoadLibraryA(path);
    r = h ? 0 : 1000 + (int)GetLastError();
    if ((kn = GetModuleHandleA("KEXNT.DLL")) && (bs = (T_BS)(void *)GetProcAddress(kn, "KexBigSecState")))
        st = bs(&calls, &fails);
    live = st == 1 && calls > 0;
    /* bits 16-19: live + calls>0; 20-26: state+64; 27-29: prepare progress */
    extra = (live ? 0x10000 : 0) | ((int)((st + 64) & 0x7F) << 20) | (int)(((fails >> 24) & 7) << 27);
    if (!h) return r + extra;
    nt = (IMAGE_NT_HEADERS32 *)((BYTE *)h + ((IMAGE_DOS_HEADER *)h)->e_lfanew);
    sh = IMAGE_FIRST_SECTION(nt);
    R = sh[1].PointerToRawData; p = (BYTE *)h + 0x2000;
    from = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress ? 16 : 0;
    if (IsBadReadPtr(p, 0x3000)) r = 3;
    else for (i = from; i < 0x3000; i += 4) if (*(DWORD *)(p + i) != ((R + i) ^ OFF_KEY)) { r = 2; break; }
    FreeLibrary(h);
    return r + extra;
}

static void log_off(DWORD code)
{
    DWORD c = code & 0xFFFF; LONG st = (LONG)((code >> 20) & 0x7F) - 64; DWORD prep = (code >> 27) & 7;
    char b[64];
    if (code == 0xFFFFFFFE) { LOG("%-28s", "cannot start child"); return; }
    if (code == 0xFFFFFFFD) { LOG("%-28s", "child hung"); return; }
    if ((code & 0xC0000000) == 0xC0000000 && !(code & 0x30000000)) { sprintf(b, "CRASH %08lx", code); LOG("%-28s", b); return; }
    if (c == 0) strcpy(b, "ok");
    else if (c == 2) strcpy(b, "WRONG BYTES");
    else if (c == 3) strcpy(b, "UNREADABLE");
    else if (c >= 1000) sprintf(b, "load err %lu", c - 1000);
    else sprintf(b, "result %lu", c);
    if (code & 0x10000) strcat(b, " (fix used)");
    else sprintf(b + strlen(b), " [hook %ld p%lu]", st, prep);
    LOG("%-28s", b);
}

static DWORD child_cmd(const char *verb, const char *path)
{
    char cmd[MAX_PATH * 2 + 32]; STARTUPINFOA si; PROCESS_INFORMATION pi; DWORD code = 0xFFFFFFFF;
    GetModuleFileNameA(NULL, cmd, MAX_PATH);
    sprintf(cmd + strlen(cmd), " %s %s", verb, path);
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return 0xFFFFFFFE;
    if (WaitForSingleObject(pi.hProcess, 120000) == WAIT_TIMEOUT) { TerminateProcess(pi.hProcess, 0xFFFF); code = 0xFFFFFFFD; }
    else GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return code;
}

static int file_offs(void)
{
    static const DWORD offs[] = { 0x600, 0x0FFF0000, 0x0FFFE000, 0x10000000, 0x10000600, 0x12345600 };
    char path[MAX_PATH]; unsigned i; int k;
    GetTempPathA(MAX_PATH, path); strcat(path, "KXOFF.DLL");
    LOG("[file offsets]  %s, each load in its own process\n", path);
    LOG("    %-30s %-28s %s\n", "section bytes at file offset", "with kexnt fix", "fix switched off");
    LOG("    ([hook N pM]: N = hook state, 1 live / 0 not started / -20 switched off / <0 install failed;\n"
        "     M = how far kexnt's LoadLibrary check got, 6 = decided the file needs the hook)\n");
    for (k = 0; k < 2; k++)
        for (i = 0; i < sizeof(offs) / sizeof(offs[0]); i++) {
            DWORD a, b;
            if (!write_off_dll(path, offs[i], k)) { LOG("    %08lx %s: cannot write (error %lu)\n", offs[i], k ? "rsrc" : "data", GetLastError()); continue; }
            SetEnvironmentVariableA("KEXNG_NOBIGSEC", NULL);
            a = child_cmd("offtry", path);
            SetEnvironmentVariableA("KEXNG_NOBIGSEC", "1");
            b = child_cmd("offtry", path);
            SetEnvironmentVariableA("KEXNG_NOBIGSEC", NULL);
            LOG("    %08lx %-4s (%s)          ", offs[i], k ? "rsrc" : "data",
                offs[i] + 0x3000 > 0x10000000 ? "past 256 MB " : "below 256 MB");
            log_off(a); LOG(" "); log_off(b); LOG("\n");
            if (offs[i] >= 0x0FFFE000 && !k && ((a & 0xFFFF) || !(a & 0x10000)))
                CHECK(0, "section at file offset %08lx loads correctly with the fix", offs[i]);
        }
    DeleteFileA(path);
    LOG("\n");
    return 0;
}

/* child mode: kextest tlschild - loads kextls.dll, checks its thread_local on this thread, on a thread
 * that existed before the load, and on a new thread; and that its TLS callback ran.
 * Exit code: 0 ok, 1000+error load failed, 3 export missing, 4 wrong here, 5 wrong on the old thread,
 * 6 wrong on a new thread, 7 TLS callback not called, 8 threads did not get separate copies,
 * 9 TLS not ready inside DllMain(PROCESS_ATTACH), 10 TLS callback ran after DllMain instead of before. */
typedef int (*T_GT)(void); typedef void (*T_ST)(int); typedef LONG (*T_CB)(int); typedef int (*T_GA)(int);
static T_GT g_gt; static T_ST g_st;
static HANDLE g_go;
static DWORD WINAPI tls_thread(LPVOID p)
{
    int r;
    /* build 120: no time limit - in the QEMU VM (all CPU emulated) loading the 40 extra TLS DLLs took longer than
     * the old 10 s, the thread gave up before the DLL was there and the test reported "TLS not working on an
     * older thread" (child result 5) although nothing was checked. */
    if (p) WaitForSingleObject(g_go, INFINITE);   /* the "old" thread: started before the load */
    if (!g_gt) return 99;
    r = g_gt();
    g_st(7);                                      /* must not change the main thread's copy */
    return r == 42 && g_gt() == 7 ? 0 : 1;
}
static HMODULE g_notls_base;
static int g_tls_moved;
static int tls_child(void)
{
    char path[MAX_PATH], *bs; HMODULE h; T_CB cb; HANDLE old, nw; DWORD c1 = 1, c2 = 1;
    g_go = CreateEventA(NULL, TRUE, FALSE, NULL);
    old = CreateThread(NULL, 0, tls_thread, (LPVOID)1, 0, NULL);
    GetModuleFileNameA(NULL, path, MAX_PATH);
    if ((bs = strrchr(path, '\\'))) {   /* build 45: a TLS-less DLL at kextls.dll's address first, then freed */
        HMODULE n; bs[1] = 0; strcat(path, "kexnotls.dll");
        if (!(n = LoadLibraryA(path))) return 13;
        g_notls_base = n;
        FreeLibrary(n);
        bs[1] = 0; strcat(path, "kextls.dll");
    }
    {   /* build 47: Chromium had 40+ modules with static TLS before vk_swiftshader.dll; kexnt's table held 32 and the
         * rest silently got no TLS. Load 40 renamed copies of kextls.dll first (%TEMP%\\kxtlsNN.dll). */
        char tmp[MAX_PATH], cp[MAX_PATH]; int k;
        GetTempPathA(MAX_PATH, tmp);
        for (k = 0; k < 40; k++) {
            sprintf(cp, "%skxtls%02d.dll", tmp, k);
            /* build 50: files copied from the CD are read-only and CopyFile keeps that, so the next run could
             * neither delete nor overwrite them (LoadLibrary/CopyFile error 5) - clear the attribute first */
            SetFileAttributesA(cp, FILE_ATTRIBUTE_NORMAL);
            DeleteFileA(cp);
            {   BOOL copied = CopyFileA(path, cp, FALSE);
                if (copied) SetFileAttributesA(cp, FILE_ATTRIBUTE_NORMAL);
                /* build 48: say which step failed and why (%TEMP%\\kxtls.txt, read by the parent) */
                if (!copied || !LoadLibraryA(cp)) {
                    DWORD e = GetLastError(); char t[MAX_PATH + 160], why[MAX_PATH + 16]; HANDLE f; DWORD w;
                    sprintf(why, "%skxtls.txt", tmp);
                    sprintf(t, "copy %d (%s): %s failed, error %lu", k, cp, copied ? "LoadLibrary" : "CopyFile", e);
                    if ((f = CreateFileA(why, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)) != INVALID_HANDLE_VALUE) { WriteFile(f, t, (DWORD)strlen(t), &w, NULL); CloseHandle(f); }
                    return 15;
                }
            }
        }
    }
    if (!(h = LoadLibraryA(path))) return 1000 + (int)GetLastError();
    { static int moved; moved = h != g_notls_base; g_tls_moved = moved; }
    g_gt = (T_GT)(void *)GetProcAddress(h, "get_tls"); g_st = (T_ST)(void *)GetProcAddress(h, "set_tls");
    cb = (T_CB)(void *)GetProcAddress(h, "get_cb");
    if (!g_gt || !g_st || !cb) return 3;
    if (g_gt() != 42) return 4;
    SetEvent(g_go);
    WaitForSingleObject(old, 120000); GetExitCodeThread(old, &c1);
    nw = CreateThread(NULL, 0, tls_thread, NULL, 0, NULL);
    WaitForSingleObject(nw, 120000); GetExitCodeThread(nw, &c2);
    if (c1) return 5;
    if (c2) return 6;
    if (cb(0) < 1 || cb(1) < 1) return 7;
    if (g_gt() != 42) return 8;
    {
        T_GA ga = (T_GA)(void *)GetProcAddress(h, "get_attach");
        if (!ga) return 3;
        if (ga(0) != 42) return 9;
        if (ga(1) < 1) return 10;
    }
    /* build 44: unload and load again (Chromium does this with vk_swiftshader.dll: Vulkan probed at startup and
     * again for chrome://gpu). The reloaded DLL's DllMain must see fresh TLS, not another module's slot. */
    g_st(7);
    FreeLibrary(h);
    if (!(h = LoadLibraryA(path))) return 1000 + (int)GetLastError();
    {
        T_GA ga = (T_GA)(void *)GetProcAddress(h, "get_attach");
        g_gt = (T_GT)(void *)GetProcAddress(h, "get_tls");
        if (!ga || !g_gt) return 3;
        if (ga(0) != 42) return 11;
        if (g_gt() != 42) return 12;
    }
    return g_tls_moved ? 14 : 0;
}

/* ---------------- LockFileEx with shared locks (lockfile_ext.c; SQLite's NT locking) ---------------- */
typedef BOOL (WINAPI *T_LFX)(HANDLE, DWORD, DWORD, DWORD, DWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *T_ULFX)(HANDLE, DWORD, DWORD, DWORD, LPOVERLAPPED);
static void test_lockfile(void)
{
    GP(T_LFX, p_LockFileEx); GP(T_ULFX, p_UnlockFileEx);
    char tmp[MAX_PATH], fn[MAX_PATH]; HANDLE a, b; OVERLAPPED o; DWORD w; BOOL r;
    LOG("[LockFileEx shared locks]\n");
    CHECK(p_LockFileEx && p_UnlockFileEx, "LockFileEx/UnlockFileEx exported");
    if (!p_LockFileEx || !p_UnlockFileEx) return;
    GetTempPathA(MAX_PATH, tmp); GetTempFileNameA(tmp, "kxl", 0, fn);
    a = CreateFileA(fn, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    b = CreateFileA(fn, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    { char z[1024] = { 0 }; WriteFile(a, z, sizeof(z), &w, NULL); }
    memset(&o, 0, sizeof(o)); o.Offset = 0x200;                       /* SQLite's SHARED range: 510 bytes */
    CHECK(p_LockFileEx(a, 1, 0, 510, 0, &o), "shared lock on handle A");
    CHECK(p_LockFileEx(b, 1, 0, 510, 0, &o), "a second shared lock on handle B (a clone connection)");
    {   /* build 132: SQLite WAL index - shared locks of ONE byte (the -shm DMS byte 0x80) on two handles. Uses the
         * kexnt.dll this process runs on (it recorded the file's path at CreateFile), not kextest's second copy. */
        OVERLAPPED o1; char sp[MAX_PATH]; HMODULE m = NULL; T_LFX p_LockFileEx_s = p_LockFileEx; T_ULFX p_UnlockFileEx_s = p_UnlockFileEx;
        if (GetWindowsDirectoryA(sp, MAX_PATH - 24)) { lstrcatA(sp, "\\KERNELEX\\KEXNT.DLL"); m = GetModuleHandleA(sp); }
        if (m) { p_LockFileEx_s = (T_LFX)(void *)GetProcAddress(m, "LockFileEx"); p_UnlockFileEx_s = (T_ULFX)(void *)GetProcAddress(m, "UnlockFileEx"); }
        if (!p_LockFileEx_s || !p_UnlockFileEx_s) { p_LockFileEx_s = p_LockFileEx; p_UnlockFileEx_s = p_UnlockFileEx; }
#define p_LockFileEx p_LockFileEx_s
#define p_UnlockFileEx p_UnlockFileEx_s
        memset(&o1, 0, sizeof(o1)); o1.Offset = 0x80;
        CHECK(p_LockFileEx(a, 1, 0, 1, 0, &o1), "1-byte shared lock on handle A");
        CHECK(p_LockFileEx(b, 1, 0, 1, 0, &o1), "1-byte shared lock on handle B as well (WAL: every connection)");
        CHECK(!p_LockFileEx(b, 3, 0, 1, 0, &o1), "exclusive lock refused while A holds it shared");
        CHECK(p_UnlockFileEx(a, 0, 1, 0, &o1) && p_UnlockFileEx(b, 0, 1, 0, &o1), "both 1-byte shared locks released");
        CHECK(p_LockFileEx(b, 3, 0, 1, 0, &o1), "exclusive lock after the shared holders left");
        p_UnlockFileEx(b, 0, 1, 0, &o1);
#undef p_LockFileEx
#undef p_UnlockFileEx
    }
    r = p_LockFileEx(b, 3, 0, 510, 0, &o);
    CHECK(!r, "exclusive lock on B fails while A and B read");
    CHECK(p_UnlockFileEx(a, 0, 510, 0, &o) && p_UnlockFileEx(b, 0, 510, 0, &o), "both shared locks released");
    CHECK(p_LockFileEx(b, 3, 0, 510, 0, &o), "exclusive lock on B once the readers are gone");
    CHECK(!p_LockFileEx(a, 1, 0, 510, 0, &o), "shared lock on A fails while B writes");
    CHECK(p_UnlockFileEx(b, 0, 510, 0, &o), "exclusive lock released");
    CloseHandle(a); CloseHandle(b); DeleteFileA(fn);
}

/* ---------------- directory handles (dirhandle_ext.c; Mozilla OS.File.stat on a folder) ---------------- */
typedef HANDLE (WINAPI *T_CFA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *T_GFIBH)(HANDLE, BY_HANDLE_FILE_INFORMATION *);
typedef BOOL (WINAPI *T_CH)(HANDLE);

/* information only (no pass/fail): does Windows 98's own gethostbyname answer in this program, and does
 * kexnt's DNS client? Mypal got WSAHOST_NOT_FOUND from the first in 2 ms (2026-11-02). Needs the network. */
static void test_dns(void)
{
    typedef int (WINAPI *T_ST)(WORD, void *);
    typedef struct { char *n; char **a; short t, l; char **list; } *(WINAPI *T_GH)(const char *);
    typedef int (WINAPI *T_GLE)(void);
    typedef DWORD (WINAPI *T_KL)(const char *);
    HMODULE w = LoadLibraryA("WSOCK32.DLL"); char wsa[512]; int k;
    static const char *names[] = { "google.com", "duckduckgo.com" };
    T_KL kl = (T_KL)(void *)GetProcAddress(kx, "KexDnsLookup");
    LOG("[DNS (information only, needs the network)]\n");
    if (!w) { LOG("    WSOCK32.DLL did not load\n"); return; }
    {
        T_ST st = (T_ST)(void *)GetProcAddress(w, (LPCSTR)115); T_GH gh = (T_GH)(void *)GetProcAddress(w, (LPCSTR)52);
        T_GLE gle = (T_GLE)(void *)GetProcAddress(w, (LPCSTR)111);
        if (!st || !gh || st(0x0101, wsa)) { LOG("    WSAStartup failed\n"); return; }
        {   /* the same clues kexnt logs inside Mypal: Winsock 2's name-space providers here */
            typedef int (WINAPI *T_ENS)(DWORD *, void *);
            HMODULE w2 = LoadLibraryA("WS2_32.DLL");
            T_ENS ens = w2 ? (T_ENS)(void *)GetProcAddress(w2, "WSAEnumNameSpaceProvidersA") : NULL;
            DWORD len = 0; int n = ens ? ens(&len, NULL) : -2;
            BYTE *b = len && len < 65536 ? (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len) : NULL;
            if (b) n = ens(&len, b);
            LOG("    Winsock 2 name-space providers: %d\n", n);
            if (b) { int i; for (i = 0; i < n && i < 8; i++) { DWORD *e = (DWORD *)(b + i * 32);
                LOG("      ns %lu active %lu \"%s\"\n", e[4], e[5], e[7] && !IsBadStringPtrA((char *)e[7], 64) ? (char *)e[7] : "?"); }
                HeapFree(GetProcessHeap(), 0, b); }
        }
        for (k = 0; k < 2; k++) {
            DWORD t = GetTickCount(); void *h = gh(names[k]); int e = h ? 0 : (gle ? gle() : -1);
            unsigned char *a = h ? (unsigned char *)((char ***)h)[3][0] : NULL;
            if (a) LOG("    Windows gethostbyname(%s): %u.%u.%u.%u (%lu ms)\n", names[k], a[0], a[1], a[2], a[3], GetTickCount() - t);
            else LOG("    Windows gethostbyname(%s): failed, error %d (%lu ms)\n", names[k], e, GetTickCount() - t);
            if (kl) { DWORD ip; t = GetTickCount(); ip = kl(names[k]);
                LOG("    kexnt DNS client(%s): %s%lu.%lu.%lu.%lu (%lu ms)\n", names[k], ip ? "" : "nothing ", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255, GetTickCount() - t); }
            else LOG("    kexnt has no KexDnsLookup export\n");
        }
    }
}

/* AddFontMemResourceEx really registers the font (KernelEx 4.5 faked it; Mypal drew web-font glyph numbers
 * as letters). Uses Arial from the Fonts folder as the "web font". 4 checks. */
static void test_fontmem(void)
{
    typedef HANDLE (WINAPI *T_AFM)(PVOID, DWORD, PVOID, DWORD *);
    typedef BOOL (WINAPI *T_RFM)(HANDLE);
    GP(T_AFM, p_AddFontMemResourceEx); GP(T_RFM, p_RemoveFontMemResourceEx);
    char path[MAX_PATH]; HANDLE f, h; DWORD size, rd = 0, n = 0; BYTE *buf;
    LOG("[web fonts]\n");
    CHECK(p_AddFontMemResourceEx && p_RemoveFontMemResourceEx, "AddFontMemResourceEx/RemoveFontMemResourceEx exported");
    if (!p_AddFontMemResourceEx || !p_RemoveFontMemResourceEx) return;
    GetWindowsDirectoryA(path, MAX_PATH); lstrcatA(path, "\\FONTS\\ARIAL.TTF");
    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { LOG("    %s not found - font checks skipped\n", path); return; }
    size = GetFileSize(f, NULL);
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size + 16);
    if (buf) ReadFile(f, buf, size, &rd, NULL);
    CloseHandle(f);
    if (!buf || rd != size) { LOG("    could not read %s\n", path); return; }
    h = p_AddFontMemResourceEx(buf, size, NULL, &n);
    CHECK(h != NULL && n >= 1, "AddFontMemResourceEx registers a TrueType font");
    CHECK(h && p_RemoveFontMemResourceEx(h), "RemoveFontMemResourceEx removes it");
    memcpy(buf, "OTTO", 4);
    h = p_AddFontMemResourceEx(buf, size, NULL, &n);
    CHECK(h == NULL, "CFF (OpenType/PostScript) font refused honestly");
    if (h) p_RemoveFontMemResourceEx(h);
    HeapFree(GetProcessHeap(), 0, buf);
}

/* the GDI guard (gdiguard_ext.c): the same call sequence cairo uses for an 8-bit surface. 3 checks. */
static int g_ew_n, g_ew_bad;
static BOOL CALLBACK ew_cb(HWND w, LPARAM p)
{
    typedef HDC (WINAPI *T_CCDC)(HDC);
    HDC dc = p ? ((T_CCDC)p)(NULL) : NULL;
    (void)w;
    static BOOL (WINAPI *ddc)(HDC);
    if (!ddc) { HMODULE g = LoadLibraryA("GDI32.DLL"); ddc = g ? (BOOL (WINAPI *)(HDC))(void *)GetProcAddress(g, "DeleteDC") : NULL; }
    if (!dc) g_ew_bad++; else if (ddc) ddc(dc);
    return ++g_ew_n < 40;
}
static void test_gdiguard(void)
{
    typedef HDC (WINAPI *T_CCDC)(HDC);
    typedef HBITMAP (WINAPI *T_CDIB)(HDC, const BITMAPINFO *, UINT, VOID **, HANDLE, DWORD);
    typedef BOOL (WINAPI *T_GF)(void);
    typedef HGDIOBJ (WINAPI *T_SO)(HDC, HGDIOBJ);
    GP(T_CCDC, p_CreateCompatibleDC); GP(T_CDIB, p_CreateDIBSection); GP(T_GF, p_GdiFlush); GP(T_SO, p_SelectObject);
    struct { BITMAPINFOHEADER h; RGBQUAD pal[256]; } bi; HDC dc; HBITMAP bm; HGDIOBJ old; void *bits = NULL; int i;
    volatile DWORD canary1 = 0x11223344, canary2 = 0x55667788;
    LOG("[GDI guard]\n");
    CHECK(p_CreateCompatibleDC && p_CreateDIBSection && p_GdiFlush && p_SelectObject, "CreateCompatibleDC/CreateDIBSection/GdiFlush/SelectObject exported");
    if (!p_CreateCompatibleDC || !p_CreateDIBSection || !p_GdiFlush || !p_SelectObject) return;
    memset(&bi, 0, sizeof(bi));
    bi.h.biSize = sizeof(bi.h); bi.h.biWidth = 86; bi.h.biHeight = -88; bi.h.biPlanes = 1; bi.h.biBitCount = 8; bi.h.biClrUsed = 256;
    for (i = 0; i < 256; i++) bi.pal[i].rgbRed = bi.pal[i].rgbGreen = bi.pal[i].rgbBlue = (BYTE)i;
    dc = p_CreateCompatibleDC(NULL);
    bm = dc ? p_CreateDIBSection(dc, (BITMAPINFO *)&bi, DIB_RGB_COLORS, &bits, NULL, 0) : NULL;
    p_GdiFlush();
    old = bm ? p_SelectObject(dc, bm) : NULL;
    CHECK(dc && bm && bits && old, "8-bit DIB section created and selected through the guard");
    {
        typedef BOOL (WINAPI *T_DO)(HGDIOBJ); typedef BOOL (WINAPI *T_DDC)(HDC);
        HMODULE g = LoadLibraryA("GDI32.DLL");
        T_DO dobj = g ? (T_DO)(void *)GetProcAddress(g, "DeleteObject") : NULL;
        T_DDC ddc = g ? (T_DDC)(void *)GetProcAddress(g, "DeleteDC") : NULL;
        if (old) p_SelectObject(dc, old);
        if (bm && dobj) dobj(bm);
        if (dc && ddc) ddc(dc);
    }
    CHECK(canary1 == 0x11223344 && canary2 == 0x55667788, "caller's stack intact after the guarded calls");
    {   /* USER32 and WINMM through the guard (2026-11-02), with guarded GDI calls nested inside a guarded callback */
        typedef HWND (WINAPI *T_GDW)(void); typedef BOOL (WINAPI *T_GWR)(HWND, LPRECT);
        typedef BOOL (WINAPI *T_EW)(WNDENUMPROC, LPARAM); typedef UINT (WINAPI *T_WNG)(void);
        T_GDW gdw = (T_GDW)(void *)GetProcAddress(kx, "GetDesktopWindow");
        T_GWR gwr = (T_GWR)(void *)GetProcAddress(kx, "GetWindowRect");
        T_EW ew = (T_EW)(void *)GetProcAddress(kx, "EnumWindows");
        T_WNG wng = (T_WNG)(void *)GetProcAddress(kx, "waveOutGetNumDevs");
        RECT r1, r2; HWND d = gdw ? gdw() : NULL; BOOL ok;
        memset(&r1, 0, sizeof(r1)); memset(&r2, 0, sizeof(r2));
        ok = d && d == GetDesktopWindow() && gwr && gwr(d, &r1) && GetWindowRect(d, &r2) && !memcmp(&r1, &r2, sizeof(r1));
        CHECK(ok, "USER32 GetDesktopWindow/GetWindowRect through the guard match Windows");
        g_ew_n = 0; g_ew_bad = 0;
        if (ew) ew(ew_cb, (LPARAM)p_CreateCompatibleDC);
        ok = ew && g_ew_n > 0 && !g_ew_bad;
        LOG("    EnumWindows through the guard: %d windows, a guarded CreateCompatibleDC in each callback\n", g_ew_n);
        CHECK(ok && canary1 == 0x11223344 && canary2 == 0x55667788, "guarded GDI calls nested inside a guarded USER32 callback");
        {   /* HWND_MESSAGE parent (Windows 2000+): a hidden top-level window on Windows 98 */
            typedef HWND (WINAPI *T_CWA)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
            typedef BOOL (WINAPI *T_DW)(HWND);
            T_CWA cwa = (T_CWA)(void *)GetProcAddress(kx, "CreateWindowExA");
            T_DW dw = (T_DW)(void *)GetProcAddress(GetModuleHandleA("USER32.DLL"), "DestroyWindow");
            HWND mw = cwa ? cwa(0, "STATIC", "kextest message-only", 0, 0, 0, 0, 0, (HWND)(LONG_PTR)-3, NULL, NULL, NULL) : NULL;
            LOG("    CreateWindowEx with parent HWND_MESSAGE: %p\n", (void *)mw);
            CHECK(mw != NULL, "message-only window (HWND_MESSAGE) can be created");
            if (mw && dw) dw(mw);
            {   /* EnumDisplaySettingsW: Windows 2000 display fields set (Chrome's screen rotation) */
                typedef BOOL (WINAPI *T_EDS)(LPCWSTR, DWORD, DEVMODEW *);
                T_EDS eds = (T_EDS)(void *)GetProcAddress(kx, "EnumDisplaySettingsW");
                DEVMODEW dm; BOOL ok;
                memset(&dm, 0xCC, sizeof(dm)); dm.dmSize = sizeof(dm); dm.dmDriverExtra = 0;
                ok = eds && eds(NULL, ENUM_CURRENT_SETTINGS, &dm);
                LOG("    EnumDisplaySettingsW %d: %lux%lu %lu bpp %lu Hz, orientation %lu fields %08lx\n", ok,
                    ok ? dm.dmPelsWidth : 0, ok ? dm.dmPelsHeight : 0, ok ? dm.dmBitsPerPel : 0, ok ? dm.dmDisplayFrequency : 0,
                    ok ? (unsigned long)dm.dmDisplayOrientation : 0, ok ? dm.dmFields : 0);
                CHECK(ok && dm.dmDisplayOrientation <= 3, "EnumDisplaySettingsW gives a valid display orientation");
            }
            {   /* a class registered by a DLL, then CreateWindowEx with hInstance NULL (Chrome's browser window) */
                typedef ATOM (WINAPI *T_RCA)(const WNDCLASSA *);
                typedef BOOL (WINAPI *T_UCA)(LPCSTR, HINSTANCE);
                T_RCA rca = (T_RCA)(void *)GetProcAddress(kx, "RegisterClassA");
                T_UCA uca = (T_UCA)(void *)GetProcAddress(GetModuleHandleA("USER32.DLL"), "UnregisterClassA");
                WNDCLASSA wc; ATOM at; HWND w2;
                memset(&wc, 0, sizeof(wc));
                wc.lpfnWndProc = (WNDPROC)(void *)GetProcAddress(GetModuleHandleA("USER32.DLL"), "DefWindowProcA");
                wc.hInstance = (HINSTANCE)kx; wc.lpszClassName = "KexTestDllClass";
                at = rca ? rca(&wc) : 0;
                w2 = (at && cwa) ? cwa(0, (LPCSTR)(ULONG_PTR)at, "kextest", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                       CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, NULL, NULL) : NULL;
                LOG("    window of a DLL's class, no instance given: atom %04x hwnd %p\n", (unsigned)at, (void *)w2);
                CHECK(w2 != NULL, "CreateWindowEx finds a DLL's window class when hInstance is NULL");
                if (w2 && dw) dw(w2);
                if (at && uca) uca("KexTestDllClass", (HINSTANCE)kx);
            }
        }
        {
            HMODULE wm = LoadLibraryA("WINMM.DLL");
            T_WNG nat = wm ? (T_WNG)(void *)GetProcAddress(wm, "waveOutGetNumDevs") : NULL;
            UINT a = wng ? wng() : 0xFFFF, b = nat ? nat() : 0xFFFE;
            LOG("    waveOutGetNumDevs: %u through the guard, %u from WINMM\n", a, b);
            CHECK(a == b, "WINMM waveOutGetNumDevs through the guard matches Windows");
        }
        {   /* build 128: screen capture with SRCCOPY|CAPTUREBLT (Chrome's GDI screen capturer). Windows 98 copied nothing */
            typedef BOOL (WINAPI *T_BB)(HDC, int, int, int, int, HDC, int, int, DWORD);
            T_BB bb = (T_BB)(void *)GetProcAddress(kx, "BitBlt");
            HDC sdc = GetDC(NULL), mdc = CreateCompatibleDC(sdc); BITMAPINFO bi; void *bits = NULL; HBITMAP hb; int i, nz = 0; BOOL ok;
            memset(&bi, 0, sizeof(bi)); bi.bmiHeader.biSize = sizeof(bi.bmiHeader); bi.bmiHeader.biWidth = 256; bi.bmiHeader.biHeight = -256;
            bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
            hb = CreateDIBSection(sdc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
            if (hb && bb) {
                HGDIOBJ old = SelectObject(mdc, hb);
                ok = bb(mdc, 0, 0, 256, 256, sdc, 0, 0, SRCCOPY | 0x40000000 /* CAPTUREBLT */);
                for (i = 0; i < 256 * 256; i++) if (((DWORD *)bits)[i] & 0xFFFFFF) nz++;
                LOG("    screen -> DIB with SRCCOPY|CAPTUREBLT through kexnt: %d, %d of 65536 pixels not black\n", ok, nz);
                CHECK(ok && nz > 0, "BitBlt with CAPTUREBLT copies the screen (%d pixels)", nz);
                SelectObject(mdc, old); DeleteObject(hb);
            } else CHECK(0, "BitBlt export / DIB section");
            DeleteDC(mdc); ReleaseDC(NULL, sdc);
        }
        {   /* build 42: ANGLE (Chromium's GL) needs WindowFromDC(GetDC(NULL)) != NULL and that window in its own process,
             * or it demands Direct3D interop. kexnt reports the desktop window as the caller's. */
            typedef HWND (WINAPI *T_WFDC)(HDC);
            typedef DWORD (WINAPI *T_GWTP)(HWND, LPDWORD);
            T_WFDC wf = (T_WFDC)(void *)GetProcAddress(kx, "WindowFromDC");
            T_GWTP gw = (T_GWTP)(void *)GetProcAddress(kx, "GetWindowThreadProcessId");
            HDC sdc = GetDC(NULL); HWND sw = wf && sdc ? wf(sdc) : NULL; DWORD pid = 0, tid = 0;
            if (gw && sw) tid = gw(sw, &pid);
            LOG("    screen DC -> window %p, its process %08lx thread %08lx (this process %08lx)\n", (void *)sw, pid, tid, GetCurrentProcessId());
            CHECK(sw != NULL, "WindowFromDC(screen DC) is a window (ANGLE's display check)");
            CHECK(pid == GetCurrentProcessId(), "the screen's window counts as this process's (ANGLE's OpenGL backend without Direct3D)");
            if (sdc) ReleaseDC(NULL, sdc);
        }
    }
    {   /* kexnt's TlsAlloc for programs: a working slot (KernelEx extended when available), native slots left free */
        typedef DWORD (WINAPI *T_TA)(void);
        T_TA ta = (T_TA)(void *)GetProcAddress(kx, "TlsAlloc");
        DWORD t = ta ? ta() : TLS_OUT_OF_INDEXES, nat = TlsAlloc();
        BOOL ok = t != TLS_OUT_OF_INDEXES && TlsSetValue(t, (LPVOID)0x5A5A1234) && TlsGetValue(t) == (LPVOID)0x5A5A1234;
        LOG("    kexnt TlsAlloc gave slot %lu (79 and up = KernelEx extended)\n", t);
        CHECK(ok, "TlsAlloc through kexnt gives a usable slot");
        if (t != TLS_OUT_OF_INDEXES) TlsFree(t);
        if (nat != TLS_OUT_OF_INDEXES) TlsFree(nat);
    }
}

static void test_dirhandle(void)
{
    GP(T_CFA, p_CreateFileA); GP(T_GFIBH, p_GetFileInformationByHandle); GP(T_CH, p_CloseHandle);
    char dir[MAX_PATH]; HANDLE h; BY_HANDLE_FILE_INFORMATION fi;
    LOG("[directory handles]\n");
    CHECK(p_CreateFileA && p_GetFileInformationByHandle && p_CloseHandle, "CreateFileA/GetFileInformationByHandle/CloseHandle exported");
    if (!p_CreateFileA || !p_GetFileInformationByHandle || !p_CloseHandle) return;
    GetWindowsDirectoryA(dir, MAX_PATH);
    h = p_CreateFileA(dir, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    CHECK(h != INVALID_HANDLE_VALUE, "CreateFile(%s, BACKUP_SEMANTICS) opens the folder", dir);
    if (h == INVALID_HANDLE_VALUE) return;
    memset(&fi, 0, sizeof(fi));
    CHECK(p_GetFileInformationByHandle(h, &fi) && (fi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY), "GetFileInformationByHandle says directory (attr %lx)", fi.dwFileAttributes);
    CHECK(fi.ftLastWriteTime.dwLowDateTime || fi.ftLastWriteTime.dwHighDateTime, "folder has a write time");
    CHECK(p_CloseHandle(h), "CloseHandle on the folder handle");
    h = p_CreateFileA(dir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(h == INVALID_HANDLE_VALUE, "without BACKUP_SEMANTICS a folder still does not open (as on NT)");
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}


/* [completion ports] (2026-11-10 build 20): kexnt's I/O completion ports with file association (iocp_ext.c),
 * the way Chromium's IO thread uses them (MessagePumpForIO::RegisterIOHandler); FILE_APPEND_DATA files
 * (Chromium's --log-file); GetProcAddress of kexnt functions published under PDH.DLL, which KernelEx loads
 * from its own folder (Chromium delay-loads PdhAddEnglishCounterW). */
typedef HANDLE (WINAPI *T_CICP)(HANDLE, HANDLE, ULONG_PTR, DWORD);
typedef BOOL (WINAPI *T_GQCS)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED *, DWORD);
typedef BOOL (WINAPI *T_PQCS)(HANDLE, DWORD, ULONG_PTR, LPOVERLAPPED);
typedef BOOL (WINAPI *T_SFCNM)(HANDLE, UCHAR);
typedef struct { ULONG_PTR key; LPOVERLAPPED ov; ULONG_PTR internal; DWORD bytes; } K_OVE;
typedef BOOL (WINAPI *T_GQCSX)(HANDLE, K_OVE *, ULONG, PULONG, DWORD, BOOL);
typedef FARPROC (WINAPI *T_GPA)(HMODULE, LPCSTR);
static void test_iocp(void)
{
    GP(T_CFA, p_CreateFileA); GP(T_CH, p_CloseHandle); GP(T_RF, p_ReadFile); GP(T_WF, p_WriteFile);
    GP(T_CICP, p_CreateIoCompletionPort); GP(T_GQCS, p_GetQueuedCompletionStatus); GP(T_PQCS, p_PostQueuedCompletionStatus);
    GP(T_SFCNM, p_SetFileCompletionNotificationModes); GP(T_GQCSX, p_GetQueuedCompletionStatusEx); GP(T_GPA, p_GetProcAddress);
    char path[MAX_PATH], buf[16]; HANDLE f, port; OVERLAPPED o, *got; DWORD n, sz; ULONG_PTR key; K_OVE e[4]; ULONG rem;
    LOG("[completion ports]\n");
    CHECK(p_CreateFileA && p_CloseHandle && p_ReadFile && p_WriteFile && p_CreateIoCompletionPort && p_GetQueuedCompletionStatus &&
          p_PostQueuedCompletionStatus && p_SetFileCompletionNotificationModes && p_GetQueuedCompletionStatusEx && p_GetProcAddress,
          "completion port functions exported");
    if (!p_CreateFileA || !p_CloseHandle || !p_ReadFile || !p_WriteFile || !p_CreateIoCompletionPort || !p_GetQueuedCompletionStatus ||
        !p_PostQueuedCompletionStatus || !p_SetFileCompletionNotificationModes || !p_GetQueuedCompletionStatusEx || !p_GetProcAddress) return;
    GetTempPathA(MAX_PATH - 20, path); lstrcatA(path, "kxiocp.tmp");
    f = p_CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
    CHECK(f != INVALID_HANDLE_VALUE, "overlapped file opens");
    if (f == INVALID_HANDLE_VALUE) return;
    port = p_CreateIoCompletionPort(f, NULL, 0x1234, 1);
    CHECK(port != NULL, "CreateIoCompletionPort(file) gives a port (error %lu)", GetLastError());
    if (port) {
        memset(&o, 0, sizeof(o));
        CHECK(p_WriteFile(f, "0123456789", 10, &n, &o) || GetLastError() == ERROR_IO_PENDING, "overlapped WriteFile");
        got = NULL; key = 0; n = 0;
        CHECK(p_GetQueuedCompletionStatus(port, &n, &key, &got, 2000) && key == 0x1234 && got == &o && n == 10,
              "write completion packet: key %lx overlapped ok %d bytes %lu", (unsigned long)key, got == &o, n);
        memset(&o, 0, sizeof(o)); o.Offset = 2; memset(buf, 0, sizeof(buf));
        CHECK(p_ReadFile(f, buf, 4, &n, &o) || GetLastError() == ERROR_IO_PENDING, "overlapped ReadFile");
        got = NULL;
        CHECK(p_GetQueuedCompletionStatus(port, &n, &key, &got, 2000) && got == &o && n == 4 && !memcmp(buf, "2345", 4),
              "read completion packet: %lu bytes \"%.4s\"", n, buf);
        got = &o;
        CHECK(!p_GetQueuedCompletionStatus(port, &n, &key, &got, 0) && GetLastError() == WAIT_TIMEOUT && got == NULL,
              "empty port: FALSE, WAIT_TIMEOUT, no OVERLAPPED");
        CHECK(p_PostQueuedCompletionStatus(port, 7, 99, (LPOVERLAPPED)(ULONG_PTR)0x100) && p_PostQueuedCompletionStatus(port, 8, 98, NULL),
              "PostQueuedCompletionStatus twice");
        rem = 0;
        CHECK(p_GetQueuedCompletionStatusEx(port, e, 4, &rem, 1000, FALSE) && rem == 2 && e[0].key == 99 && e[0].bytes == 7 && e[1].key == 98,
              "GetQueuedCompletionStatusEx takes both, in order (%lu)", rem);
        CHECK(p_SetFileCompletionNotificationModes(f, 1), "SetFileCompletionNotificationModes(SKIP_ON_SUCCESS)");
        memset(&o, 0, sizeof(o)); o.Offset = 10;
        CHECK(p_WriteFile(f, "ab", 2, &n, &o), "write completing at once");
        CHECK(!p_GetQueuedCompletionStatus(port, &n, &key, &got, 0), "... queues no packet when the handle skips them");
        CHECK(p_CloseHandle(port), "CloseHandle(port)");
    }
    p_CloseHandle(f);
    /* FILE_APPEND_DATA: write access, at the end */
    f = p_CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(f != INVALID_HANDLE_VALUE, "CreateFile(FILE_APPEND_DATA) opens");
    if (f != INVALID_HANDLE_VALUE) {
        CHECK(p_WriteFile(f, "XY", 2, &n, NULL) && n == 2, "append-only handle can write (error %lu)", GetLastError());
        sz = GetFileSize(f, NULL);
        CHECK(sz == 14, "appended at the end: size %lu (14)", sz);
        p_CloseHandle(f);
    }
    /* build 22: base::File::Lock's whole-file range (0, 2^64-1) on Win98 (leveldb LOCK files) */
    {
        typedef BOOL (WINAPI *T_LFE)(HANDLE, DWORD, DWORD, DWORD, DWORD, LPOVERLAPPED);
        typedef BOOL (WINAPI *T_UFE)(HANDLE, DWORD, DWORD, DWORD, LPOVERLAPPED);
        GP(T_LFE, p_LockFileEx); GP(T_UFE, p_UnlockFileEx);
        f = p_CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
        if (f != INVALID_HANDLE_VALUE && p_LockFileEx && p_UnlockFileEx) {
            memset(&o, 0, sizeof(o));
            CHECK(p_LockFileEx(f, 3, 0, MAXDWORD, MAXDWORD, &o), "LockFileEx(exclusive, whole file 2^64-1) (error %lu)", GetLastError());
            memset(&o, 0, sizeof(o));
            CHECK(p_UnlockFileEx(f, 0, MAXDWORD, MAXDWORD, &o), "UnlockFileEx(whole file) (error %lu)", GetLastError());
            memset(&o, 0, sizeof(o));
            CHECK(p_LockFileEx(f, 1, 0, MAXDWORD, MAXDWORD, &o) && p_UnlockFileEx(f, 0, MAXDWORD, MAXDWORD, &o), "shared whole-file lock and unlock");
        }
        if (f != INVALID_HANDLE_VALUE) p_CloseHandle(f);
        /* sockets cannot join a port (kexnt could never complete their I/O): refused like KernelEx 4.5 */
        {
            typedef int (WINAPI *T_WS)(WORD, void *); typedef UINT_PTR (WINAPI *T_SO)(int, int, int);
            typedef int (WINAPI *T_CS)(UINT_PTR); typedef int (WINAPI *T_WC)(void);
            HMODULE w = LoadLibraryA("WS2_32.DLL"); BYTE wd[512]; UINT_PTR sk;
            T_WS ws = w ? (T_WS)(void *)GetProcAddress(w, "WSAStartup") : NULL;
            T_SO so = w ? (T_SO)(void *)GetProcAddress(w, "socket") : NULL;
            T_CS cs = w ? (T_CS)(void *)GetProcAddress(w, "closesocket") : NULL;
            T_WC wc = w ? (T_WC)(void *)GetProcAddress(w, "WSACleanup") : NULL;
            if (ws && so && cs && wc && !ws(0x0202, wd)) {
                sk = so(2 /*AF_INET*/, 1 /*SOCK_STREAM*/, 0);
                if (sk != (UINT_PTR)~0) {
                    port = p_CreateIoCompletionPort((HANDLE)sk, NULL, 1, 1);
                    CHECK(port == NULL, "a socket is refused by CreateIoCompletionPort (error %lu)", GetLastError());
                    if (port) p_CloseHandle(port);
                    cs(sk);
                }
                {   /* build 27: Win98 has no IPv6; WSASocketW(AF_INET6) used to never return (Chromium's IPv6 probe) */
                    typedef UINT_PTR (WINAPI *T_WSW)(int, int, int, void *, UINT, DWORD);
                    T_WSW wsw = (T_WSW)(void *)GetProcAddress(w, "WSASocketW");
                    T_WC gle = (T_WC)(void *)GetProcAddress(w, "WSAGetLastError");
                    DWORD t0 = GetTickCount(); int e;
                    sk = so(23 /*AF_INET6*/, 2 /*SOCK_DGRAM*/, 17);
                    e = gle ? gle() : 0;
                    CHECK(sk == (UINT_PTR)~0 && e == 10047, "socket(AF_INET6) is refused with WSAEAFNOSUPPORT (got %lu, error %d)", (unsigned long)sk, e);
                    if (sk != (UINT_PTR)~0) cs(sk);
                    if (wsw) {
                        sk = wsw(23, 2, 17, NULL, 0, 1 /*WSA_FLAG_OVERLAPPED*/);
                        e = gle ? gle() : 0;
                        CHECK(sk == (UINT_PTR)~0 && e == 10047 && GetTickCount() - t0 < 2000,
                              "WSASocketW(AF_INET6) returns at once with WSAEAFNOSUPPORT (error %d)", e);
                        if (sk != (UINT_PTR)~0) cs(sk);
                        sk = wsw(2, 2, 17, NULL, 0, 1);
                        CHECK(sk != (UINT_PTR)~0, "WSASocketW(AF_INET, UDP) still works (error %d)", gle ? gle() : 0);
                        if (sk != (UINT_PTR)~0) cs(sk);
                    }
                }
                wc();
            }
        }
    }
    {   /* build 23: a read-only view of a file follows WriteFile on the same handle (SQLite memory-mapped I/O) */
        typedef HANDLE (WINAPI *T_CFMA2)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
        typedef LPVOID (WINAPI *T_MVOF2)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
        typedef BOOL (WINAPI *T_UVOF2)(LPCVOID);
        GP(T_CFMA2, p_CreateFileMappingA); GP(T_MVOF2, p_MapViewOfFile); GP(T_UVOF2, p_UnmapViewOfFile);
        static char blk[8192]; HANDLE m; char *v;
        f = p_CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
        if (f != INVALID_HANDLE_VALUE && p_CreateFileMappingA && p_MapViewOfFile && p_UnmapViewOfFile) {
            memset(blk, 'a', sizeof(blk));
            p_WriteFile(f, blk, sizeof(blk), &n, NULL);
            m = p_CreateFileMappingA(f, NULL, PAGE_READONLY, 0, 0, NULL);
            v = m ? (char *)p_MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0) : NULL;
            CHECK(v != NULL && v[0] == 'a' && v[8191] == 'a', "read-only view of a written file shows its content");
            if (v) {
                CHECK(!((ULONG_PTR)v & 0xFFFF), "... on a 64 KB boundary (%p)", v);
                memset(&o, 0, sizeof(o)); o.Offset = 4000;
                CHECK(p_WriteFile(f, "HELLO", 5, &n, &o) && !memcmp(v + 4000, "HELLO", 5), "WriteFile at an offset appears in the view (NT cache coherence)");
                SetFilePointer(f, 100, NULL, FILE_BEGIN);
                CHECK(p_WriteFile(f, "xyz", 3, &n, NULL) && !memcmp(v + 100, "xyz", 3) && v[99] == 'a' && v[103] == 'a', "WriteFile at the file position appears in the view");
                { typedef BOOL (WINAPI *T_FVOF)(LPCVOID, SIZE_T); GP(T_FVOF, p_FlushViewOfFile);
                  CHECK(p_FlushViewOfFile && p_FlushViewOfFile(v, 0), "FlushViewOfFile on that view (SQLite after each commit) (error %lu)", GetLastError()); }
                CHECK(p_UnmapViewOfFile(v), "UnmapViewOfFile of that view");
            }
            if (m) p_CloseHandle(m);
        }
        if (f != INVALID_HANDLE_VALUE) p_CloseHandle(f);
    }
    DeleteFileA(path);
    {
        HMODULE pdh = LoadLibraryA("PDH.DLL");
        char m[MAX_PATH] = "";
        if (!pdh) {                          /* kextest itself may run without KernelEx's KnownDLLs: KernelEx's own copy */
            HKEY k; DWORD t, n = MAX_PATH - 10;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx", 0, KEY_READ, &k) == ERROR_SUCCESS) {
                if (RegQueryValueExA(k, "InstallDir", NULL, &t, (BYTE *)m, &n) == ERROR_SUCCESS && t == REG_SZ) {
                    lstrcatA(m, "\\PDH.DLL"); pdh = LoadLibraryA(m);
                }
                RegCloseKey(k);
            }
            m[0] = 0;
        }
        if (pdh) GetModuleFileNameA(pdh, m, MAX_PATH);
        LOG("    PDH.DLL loaded from %s\n", pdh ? m : "(not loadable)");
        if (pdh) {
            FARPROC a = p_GetProcAddress(pdh, "PdhAddEnglishCounterW"), b = p_GetProcAddress(pdh, "PdhOpenQueryW");
            CHECK(a != NULL, "GetProcAddress(PDH, PdhAddEnglishCounterW) found (Chromium delay-loads it)");
            CHECK(b != NULL, "GetProcAddress(PDH, PdhOpenQueryW) still PDH's own");
        }
    }
    {   /* [build 21] ReadDirectoryChangesW: pending, aborted by CloseHandle with a completion packet */
        typedef BOOL (WINAPI *T_RDCW)(HANDLE, LPVOID, DWORD, BOOL, DWORD, LPDWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE);
        GP(T_RDCW, p_ReadDirectoryChangesW);
        char dir[MAX_PATH]; DWORD buf[256]; HANDLE d;
        CHECK(p_ReadDirectoryChangesW != NULL, "ReadDirectoryChangesW exported");
        GetTempPathA(MAX_PATH, dir);
        d = p_CreateFileA(dir, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
        if (p_ReadDirectoryChangesW && d != INVALID_HANDLE_VALUE) {
            port = p_CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
            CHECK(port && p_CreateIoCompletionPort(d, port, 77, 1) == port, "folder handle joins a port");
            memset(&o, 0, sizeof(o));
            CHECK(p_ReadDirectoryChangesW(d, buf, sizeof(buf), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME, NULL, &o, NULL), "ReadDirectoryChangesW(overlapped) accepted");
            CHECK(!p_GetQueuedCompletionStatus(port, &n, &key, &got, 0) && got == NULL, "... and pending");
            p_CloseHandle(d);
            got = NULL; key = 0;
            CHECK(!p_GetQueuedCompletionStatus(port, &n, &key, &got, 1000) && got == &o && key == 77 && GetLastError() == ERROR_OPERATION_ABORTED,
                  "closing the folder completes it: aborted (error %lu, key %lu)", GetLastError(), (unsigned long)key);
            if (port) p_CloseHandle(port);
        } else if (d != INVALID_HANDLE_VALUE) p_CloseHandle(d);
    }
    {   /* [build 21] CryptProtectData / CryptUnprotectData (Chromium os_crypt) */
        typedef struct { DWORD cb; BYTE *pb; } KB;
        typedef BOOL (WINAPI *T_CPD)(KB *, LPCWSTR, KB *, PVOID, PVOID, DWORD, KB *);
        typedef BOOL (WINAPI *T_CUD)(KB *, LPWSTR *, KB *, PVOID, PVOID, DWORD, KB *);
        GP(T_CPD, p_CryptProtectData); GP(T_CUD, p_CryptUnprotectData);
        KB in, out, back, ent; LPWSTR desc = NULL;
        LOG("[DPAPI]\n");
        CHECK(p_CryptProtectData && p_CryptUnprotectData, "CryptProtectData/CryptUnprotectData exported");
        if (p_CryptProtectData && p_CryptUnprotectData) {
            in.cb = 32; in.pb = (BYTE *)"0123456789abcdef0123456789ABCDEF";
            ent.cb = 4; ent.pb = (BYTE *)"salt";
            CHECK(p_CryptProtectData(&in, L"key", NULL, NULL, NULL, 1, &out) && out.cb > 32 && memcmp(out.pb + 18, in.pb, 32), "protect: %lu bytes", out.cb);
            CHECK(p_CryptUnprotectData(&out, &desc, NULL, NULL, NULL, 1, &back) && back.cb == 32 && !memcmp(back.pb, in.pb, 32), "unprotect gives the data back");
            if (back.pb) LocalFree(back.pb);
            if (desc) LocalFree(desc);
            out.pb[30] ^= 1; back.pb = NULL;
            CHECK(!p_CryptUnprotectData(&out, NULL, NULL, NULL, NULL, 1, &back), "a changed blob is refused");
            LocalFree(out.pb);
            CHECK(p_CryptProtectData(&in, NULL, &ent, NULL, NULL, 1, &out), "protect with entropy");
            back.pb = NULL;
            CHECK(!p_CryptUnprotectData(&out, NULL, NULL, NULL, NULL, 1, &back), "... needs the same entropy");
            CHECK(p_CryptUnprotectData(&out, NULL, &ent, NULL, NULL, 1, &back) && back.cb == 32, "... and opens with it");
            if (back.pb) LocalFree(back.pb);
            LocalFree(out.pb);
        }
    }
}

/* [system fonts] (build 20): SystemParametersInfoW(SPI_GETNONCLIENTMETRICS) with a real NONCLIENTMETRICSW
 * (Chromium's UI fonts, ui/gfx/system_fonts_win.cc). KernelEx passed the W buffer to the A function. */
typedef BOOL (WINAPI *T_SPIW)(UINT, UINT, PVOID, UINT);
static int face_ok(const WCHAR *f) { int i; if (!f[0]) return 0; for (i = 0; f[i]; i++) if (f[i] < 0x20 || f[i] > 0x7E) return 0; return i < LF_FACESIZE; }
/* build 29: UnregisterWaitEx(wait, event) must signal the event (Chromium's ObjectWatcher::StopWatching waits on it) */
static volatile LONG g_waitcb;
static VOID CALLBACK wait_cb(PVOID ctx, BOOLEAN fired) { (void)ctx; (void)fired; InterlockedIncrement(&g_waitcb); }
static void test_waits(void)
{
    typedef BOOL (WINAPI *T_RW)(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, ULONG, ULONG);
    typedef BOOL (WINAPI *T_UW)(HANDLE, HANDLE);
    HMODULE k = GetModuleHandleA("KERNEL32.DLL");
    T_RW rw = (T_RW)(void *)GetProcAddress(k, "RegisterWaitForSingleObject");
    T_UW uw = (T_UW)(void *)GetProcAddress(k, "UnregisterWaitEx");
    HANDLE obj = CreateEventA(NULL, TRUE, FALSE, NULL), done = CreateEventA(NULL, TRUE, FALSE, NULL), w = NULL;
    LOG("[thread-pool waits]\n");
    if (!rw || !uw) { CHECK(0, "RegisterWaitForSingleObject / UnregisterWaitEx present"); return; }
    /* never fired, run-in-wait-thread + once: what ObjectWatcher registers */
    CHECK(rw(&w, obj, wait_cb, NULL, INFINITE, 0x4 /*WT_EXECUTEINWAITTHREAD*/ | 0x8 /*WT_EXECUTEONLYONCE*/), "RegisterWaitForSingleObject (error %lu)", GetLastError());
    if (w) {
        BOOL r = uw(w, done); DWORD e = GetLastError();
        CHECK(r || e == ERROR_IO_PENDING, "UnregisterWaitEx(event) returns TRUE or ERROR_IO_PENDING (error %lu)", e);
        CHECK(WaitForSingleObject(done, 3000) == WAIT_OBJECT_0, "UnregisterWaitEx signals its completion event");
    }
    /* fired once already, then unregistered */
    ResetEvent(done); w = NULL; g_waitcb = 0;
    if (rw(&w, obj, wait_cb, NULL, INFINITE, 0x4 | 0x8)) {
        DWORD t0 = GetTickCount();
        SetEvent(obj);
        while (!g_waitcb && GetTickCount() - t0 < 3000) Sleep(10);
        CHECK(g_waitcb == 1, "the wait callback ran once (%ld)", g_waitcb);
        uw(w, done);
        CHECK(WaitForSingleObject(done, 3000) == WAIT_OBJECT_0, "UnregisterWaitEx after the callback signals its event");
    }
    {   /* timeout fires once with TRUE; an auto-reset event signalled before registering is not consumed by it */
        static volatile LONG timed; HANDLE ar = CreateEventA(NULL, FALSE, TRUE, NULL); DWORD t0 = GetTickCount();
        w = NULL; g_waitcb = 0;
        if (rw(&w, done, wait_cb, NULL, 100, 0x4 | 0x8)) {    /* "done" is not signalled now */
            ResetEvent(done);
            while (!g_waitcb && GetTickCount() - t0 < 3000) Sleep(10);
            CHECK(g_waitcb == 1, "a 100 ms wait times out and calls back once (%ld)", g_waitcb);
            uw(w, NULL);
        }
        w = NULL;
        if (rw(&w, obj, wait_cb, NULL, INFINITE, 0x4 | 0x8)) { ResetEvent(obj); uw(w, INVALID_HANDLE_VALUE); }
        CHECK(WaitForSingleObject(ar, 0) == WAIT_OBJECT_0, "registering a wait does not consume another event's signal");
        (void)timed; CloseHandle(ar);
    }
    CloseHandle(obj); CloseHandle(done);
}

/* build 35: UpdateLayeredWindow(ULW_ALPHA) - Windows 98 cannot blend, so kexnt shapes the window from the alpha
 * channel (Chromium's menus: transparent shadow pixels came out black) */
static void test_layered(void)
{
    typedef BOOL (WINAPI *T_ULW)(HWND, HDC, POINT *, SIZE *, HDC, POINT *, COLORREF, BLENDFUNCTION *, DWORD);
    T_ULW ulw = (T_ULW)(void *)GetProcAddress(GetModuleHandleA("USER32.DLL"), "UpdateLayeredWindow");
    BITMAPINFO bi; void *bits = NULL; HDC mem; HBITMAP bm, old; HWND w; int x, y, r; HRGN rgn;
    LOG("[layered windows]\n");
    if (!ulw) { CHECK(0, "UpdateLayeredWindow present"); return; }
    w = CreateWindowExA(0x00080000 /*WS_EX_LAYERED*/ | WS_EX_TOOLWINDOW, "STATIC", "", WS_POPUP, 10, 10, 64, 64, NULL, NULL, NULL, NULL);
    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(bi.bmiHeader); bi.bmiHeader.biWidth = 64; bi.bmiHeader.biHeight = -64;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
    mem = CreateCompatibleDC(NULL);
    bm = CreateDIBSection(mem, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    if (!w || !mem || !bm || !bits) { CHECK(0, "layered test setup (window %p dib %p)", (void *)w, bits); goto out; }
    old = (HBITMAP)SelectObject(mem, bm);
    for (y = 0; y < 64; y++) for (x = 0; x < 64; x++) {      /* opaque disc of radius 28, transparent outside */
        DWORD *p = (DWORD *)bits + y * 64 + x; int dx = x - 32, dy = y - 32;
        *p = (dx * dx + dy * dy <= 28 * 28) ? 0xFF4080C0UL : 0x00000000UL;
    }
    {
        POINT pt = {10, 10}, z = {0, 0}; SIZE sz = {64, 64}; BLENDFUNCTION bf = {AC_SRC_OVER, 0, 255, 1 /*AC_SRC_ALPHA*/};
        ShowWindow(w, SW_SHOWNOACTIVATE);
        ulw(w, NULL, &pt, &sz, mem, &z, 0, &bf, 2 /*ULW_ALPHA*/);
    }
    rgn = CreateRectRgn(0, 0, 0, 0);
    r = GetWindowRgn(w, rgn);
    CHECK(r == SIMPLEREGION || r == COMPLEXREGION, "per-pixel alpha shapes the window (GetWindowRgn %d)", r);
    CHECK(!PtInRegion(rgn, 1, 1) && !PtInRegion(rgn, 62, 62) && PtInRegion(rgn, 32, 32),
          "transparent corners cut out, opaque middle kept");
    DeleteObject(rgn);
    SelectObject(mem, old);
out:
    if (bm) DeleteObject(bm);
    if (mem) DeleteDC(mem);
    if (w) DestroyWindow(w);
}

/* build 132: UpdateLayeredWindow from a thread that does not own the window must not wait for the owner (Firefox's
 * Renderer thread vs. its main thread waiting in FlushRendering - deadlock at the first popup) */
static HWND g_lx_w; static HANDLE g_lx_ready, g_lx_go; static RECT g_lx_after;
static DWORD WINAPI lx_owner(LPVOID p)
{
    MSG m; DWORD t;
    (void)p;
    g_lx_w = CreateWindowExA(0x00080000 /*WS_EX_LAYERED*/ | WS_EX_TOOLWINDOW, "STATIC", "", WS_POPUP, 10, 10, 64, 64, NULL, NULL, NULL, NULL);
    if (g_lx_w) ShowWindow(g_lx_w, SW_SHOWNOACTIVATE);
    SetEvent(g_lx_ready);
    WaitForSingleObject(g_lx_go, 10000);                    /* blocked, no message loop - like Firefox's main thread */
    for (t = GetTickCount(); GetTickCount() - t < 500; Sleep(10)) while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) DispatchMessageA(&m);
    if (g_lx_w) { GetWindowRect(g_lx_w, &g_lx_after); DestroyWindow(g_lx_w); }
    return 0;
}
static void test_layered_xthread(void)
{
    typedef BOOL (WINAPI *T_ULW)(HWND, HDC, POINT *, SIZE *, HDC, POINT *, COLORREF, BLENDFUNCTION *, DWORD);
    T_ULW ulw = (T_ULW)(void *)GetProcAddress(GetModuleHandleA("USER32.DLL"), "UpdateLayeredWindow");
    BITMAPINFO bi; void *bits = NULL; HDC mem; HBITMAP bm, old; HANDLE th; DWORD t0, dt, tid;
    POINT pt = {30, 40}, z = {0, 0}; SIZE sz = {64, 64}; BLENDFUNCTION bf = {AC_SRC_OVER, 0, 255, 1};
    LOG("[layered window updated from another thread]\n");
    if (!ulw) { CHECK(0, "UpdateLayeredWindow present"); return; }
    g_lx_ready = CreateEventA(NULL, TRUE, FALSE, NULL); g_lx_go = CreateEventA(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, lx_owner, NULL, 0, &tid);
    WaitForSingleObject(g_lx_ready, 5000);
    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(bi.bmiHeader); bi.bmiHeader.biWidth = 64; bi.bmiHeader.biHeight = -64;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
    mem = CreateCompatibleDC(NULL); bm = CreateDIBSection(mem, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    if (!g_lx_w || !mem || !bm || !bits) { CHECK(0, "setup (window %p dib %p)", (void *)g_lx_w, bits); SetEvent(g_lx_go); goto out; }
    old = (HBITMAP)SelectObject(mem, bm);
    memset(bits, 0xFF, 64 * 64 * 4);
    t0 = GetTickCount(); ulw(g_lx_w, NULL, &pt, &sz, mem, &z, 0, &bf, 2); dt = GetTickCount() - t0;
    CHECK(dt < 2000, "returns while the owner thread waits (%lu ms)", dt);
    SetEvent(g_lx_go);
    WaitForSingleObject(th, 15000);
    CHECK(g_lx_after.left == 30 && g_lx_after.top == 40, "the move is done by the owner thread afterwards (%ld,%ld)", g_lx_after.left, g_lx_after.top);
    SelectObject(mem, old);
out:
    if (th) { WaitForSingleObject(th, 15000); CloseHandle(th); }
    if (bm) DeleteObject(bm);
    if (mem) DeleteDC(mem);
    CloseHandle(g_lx_ready); CloseHandle(g_lx_go);
}

/* build 132: CLSID_ApplicationAssociationRegistration (Firefox 115's URI fixup needs it, assoc_ext.c) */
static void test_assocreg(void)
{
    typedef HRESULT (WINAPI *T_CI)(LPVOID);
    typedef HRESULT (WINAPI *T_CCI)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID *);
    typedef void (WINAPI *T_CTMF)(LPVOID);
    static const GUID clsid = {0x591209c7,0x767b,0x42b2,{0x9f,0xba,0x44,0xee,0x46,0x15,0xf2,0xc7}};
    static const GUID iid   = {0x4e530b0a,0xe611,0x4c77,{0xa3,0xac,0x90,0x31,0xd0,0x22,0x28,0x1b}};
    typedef struct { void **vt; } OBJ;
    typedef HRESULT (WINAPI *T_QCD)(OBJ *, LPCWSTR, int, int, LPWSTR *);
    typedef ULONG (WINAPI *T_REL)(OBJ *);
    HMODULE ole = LoadLibraryA("OLE32.DLL");
    T_CI ci = ole ? (T_CI)(void *)GetProcAddress(ole, "CoInitialize") : NULL;
    T_CCI cci = ole ? (T_CCI)(void *)GetProcAddress(ole, "CoCreateInstance") : NULL;
    T_CTMF ctmf = ole ? (T_CTMF)(void *)GetProcAddress(ole, "CoTaskMemFree") : NULL;
    OBJ *o = NULL; HRESULT hr; LPWSTR s = NULL;
    LOG("[application association registration]\n");
    if (!ci || !cci) { CHECK(0, "OLE32 CoCreateInstance found"); return; }
    ci(NULL);
    hr = cci(&clsid, NULL, 1 /*CLSCTX_INPROC_SERVER*/, &iid, (void **)&o);
    CHECK(hr == S_OK && o, "CoCreateInstance(CLSID_ApplicationAssociationRegistration) %08lx", (unsigned long)hr);
    if (!o) return;
    hr = ((T_QCD)o->vt[3])(o, L"kexng-no-such-scheme", 1 /*AT_URLPROTOCOL*/, 1 /*AL_EFFECTIVE*/, &s);
    CHECK(hr == (HRESULT)0x80070483L && !s, "unknown protocol -> ERROR_NO_ASSOCIATION (%08lx)", (unsigned long)hr);
    hr = ((T_QCD)o->vt[3])(o, L".txt", 0 /*AT_FILEEXTENSION*/, 1, &s);
    CHECK(hr == S_OK && s && s[0], ".txt has a ProgID (%08lx)", (unsigned long)hr);
    if (s && ctmf) ctmf(s);
    ((T_REL)o->vt[2])(o);
}

static void test_spi(void)
{
    GP(T_SPIW, p_SystemParametersInfoW);
    NONCLIENTMETRICSW m; NONCLIENTMETRICSA a; LOGFONTW lf;
    LOG("[system fonts]\n");
    CHECK(p_SystemParametersInfoW != NULL, "SystemParametersInfoW exported");
    if (!p_SystemParametersInfoW) return;
    memset(&m, 0x5A, sizeof(m)); m.cbSize = sizeof(m);
    memset(&a, 0, sizeof(a)); a.cbSize = FIELD_OFFSET(NONCLIENTMETRICSA, iPaddedBorderWidth);   /* Win98's own size (340) */
    SystemParametersInfoA(SPI_GETNONCLIENTMETRICS, a.cbSize, &a, 0);
    CHECK(p_SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(m), &m, 0), "SPI_GETNONCLIENTMETRICS (W, %u bytes)", (unsigned)sizeof(m));
    LOG("    message font %ld \"%ls\", menu font %ld \"%ls\", caption %ld \"%ls\" (A: message %ld \"%s\")\n",
        m.lfMessageFont.lfHeight, m.lfMessageFont.lfFaceName, m.lfMenuFont.lfHeight, m.lfMenuFont.lfFaceName,
        m.lfCaptionFont.lfHeight, m.lfCaptionFont.lfFaceName, a.lfMessageFont.lfHeight, a.lfMessageFont.lfFaceName);
    CHECK(m.lfMessageFont.lfHeight == a.lfMessageFont.lfHeight && face_ok(m.lfMessageFont.lfFaceName), "message font matches the ANSI one");
    CHECK(m.lfMenuFont.lfHeight == a.lfMenuFont.lfHeight && face_ok(m.lfMenuFont.lfFaceName), "menu font matches the ANSI one");
    CHECK(m.lfStatusFont.lfHeight == a.lfStatusFont.lfHeight && face_ok(m.lfStatusFont.lfFaceName), "status font matches the ANSI one");
    CHECK(m.iMenuHeight == a.iMenuHeight && m.iCaptionHeight == a.iCaptionHeight, "metrics match");
    memset(&lf, 0, sizeof(lf));
    CHECK(p_SystemParametersInfoW(SPI_GETICONTITLELOGFONT, sizeof(lf), &lf, 0) && lf.lfHeight && face_ok(lf.lfFaceName), "SPI_GETICONTITLELOGFONT (W): %ld \"%ls\"", lf.lfHeight, lf.lfFaceName);
}

/* [DirectWrite] (2026-11-02): the user's own Windows 10 DWrite.dll (installed by KEXSETUP from the WIN10
 * folder) on top of KernelEx-NG. Factory, system font collection (from the NT font list kexnt keeps),
 * Arial's glyph ids, a text layout, and the glyph rasterizer Chrome's Skia uses (IDWriteGlyphRunAnalysis). */
#define COBJMACROS
#include <dwrite.h>
static const GUID kIID_IDWriteFactory = { 0xb859ee5a, 0xd838, 0x4b5b, { 0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48 } };
static void test_dwrite(void)
{
    typedef HRESULT (WINAPI *T_DCF)(DWRITE_FACTORY_TYPE, REFIID, IUnknown **);
    HMODULE h; T_DCF dcf; IDWriteFactory *f = NULL; IDWriteFontCollection *coll = NULL; IDWriteFontFamily *fam = NULL;
    IDWriteFont *font = NULL; IDWriteFontFace *face = NULL; IDWriteTextFormat *fmt = NULL; IDWriteTextLayout *lay = NULL;
    IDWriteGlyphRunAnalysis *ana = NULL; HRESULT hr; UINT32 idx = 0, nfam = 0; BOOL exists = FALSE; DWORD t0;
    char path[MAX_PATH];
    LOG("[DirectWrite]\n");
    GetSystemDirectoryA(path, sizeof(path) - 16);            /* the SYSTEM copy, not the placeholder next to kextest */
    lstrcatA(path, "\\DWRITE.DLL");
    h = LoadLibraryA(path);
    if (!h) { LOG("    no dwrite.dll (error %lu)\n", GetLastError()); CHECK(0, "dwrite.dll loads"); return; }
    GetModuleFileNameA(h, path, sizeof(path));
    dcf = (T_DCF)(void *)GetProcAddress(h, "DWriteCreateFactory");
    t0 = GetTickCount();
    hr = dcf ? dcf(DWRITE_FACTORY_TYPE_SHARED, &kIID_IDWriteFactory, (IUnknown **)&f) : E_FAIL;
    if (hr == E_NOTIMPL || hr == (HRESULT)0x80004001) {
        LOG("    %s is KernelEx-NG's placeholder - copy DWrite.dll and TextShaping.dll from your Windows 10\n"
            "    (C:\\Windows\\SysWOW64) next to KEXSETUP.EXE as DWRITE.W10 / TEXTSHAPING.W10 and run KEXSETUP again\n", path);
        return;
    }
    LOG("    %s: DWriteCreateFactory %08lx in %lu ms\n", path, (unsigned long)hr, GetTickCount() - t0);
    CHECK(SUCCEEDED(hr) && f, "DWriteCreateFactory(SHARED, IDWriteFactory)");
    if (!f) return;
    t0 = GetTickCount();
    hr = IDWriteFactory_GetSystemFontCollection(f, &coll, FALSE);
    if (coll) nfam = IDWriteFontCollection_GetFontFamilyCount(coll);
    LOG("    system font collection %08lx: %u families in %lu ms\n", (unsigned long)hr, nfam, GetTickCount() - t0);
    CHECK(SUCCEEDED(hr) && nfam > 0, "system font collection has fonts");
    if (coll) IDWriteFontCollection_FindFamilyName(coll, L"Arial", &idx, &exists);
    CHECK(exists, "Arial found in the system font collection");
    if (exists && SUCCEEDED(IDWriteFontCollection_GetFontFamily(coll, idx, &fam)) &&
        SUCCEEDED(IDWriteFontFamily_GetFirstMatchingFont(fam, DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STRETCH_NORMAL, DWRITE_FONT_STYLE_NORMAL, &font)))
        IDWriteFont_CreateFontFace(font, &face);
    {
        UINT32 cps[5] = { 'H', 'e', 'l', 'l', 'o' }; UINT16 gi[5] = { 0 };
        hr = face ? IDWriteFontFace_GetGlyphIndices(face, cps, 5, gi) : E_FAIL;
        LOG("    Arial glyph ids for \"Hello\": %u %u %u %u %u\n", gi[0], gi[1], gi[2], gi[3], gi[4]);
        CHECK(SUCCEEDED(hr) && gi[0] && gi[1] && gi[2] == gi[3], "glyph ids from the Arial font face");
        if (face && gi[0]) {
            DWRITE_GLYPH_RUN run; FLOAT adv[5] = { 10, 10, 10, 10, 10 }; RECT r = { 0, 0, 0, 0 };
            memset(&run, 0, sizeof(run));
            run.fontFace = face; run.fontEmSize = 24.0f; run.glyphCount = 5; run.glyphIndices = gi; run.glyphAdvances = adv;
            hr = IDWriteFactory_CreateGlyphRunAnalysis(f, &run, 1.0f, NULL, DWRITE_RENDERING_MODE_ALIASED, DWRITE_MEASURING_MODE_NATURAL, 0.0f, 24.0f, &ana);
            if (ana) hr = IDWriteGlyphRunAnalysis_GetAlphaTextureBounds(ana, DWRITE_TEXTURE_ALIASED_1x1, &r);
            if (ana && r.right > r.left && r.bottom > r.top) {
                UINT32 sz = (UINT32)((r.right - r.left) * (r.bottom - r.top)), on = 0, i;
                BYTE *px = (BYTE *)malloc(sz);
                if (px && SUCCEEDED(IDWriteGlyphRunAnalysis_CreateAlphaTexture(ana, DWRITE_TEXTURE_ALIASED_1x1, &r, px, sz)))
                    for (i = 0; i < sz; i++) on += px[i] != 0;
                LOG("    \"Hello\" at 24 px: %ldx%ld pixels, %u of them inked\n", r.right - r.left, r.bottom - r.top, on);
                CHECK(on > 20 && on < sz, "glyphs rasterized (IDWriteGlyphRunAnalysis)");
                free(px);
            } else CHECK(0, "glyph run analysis (hr %08lx)", (unsigned long)hr);
        }
    }
    hr = IDWriteFactory_CreateTextFormat(f, L"Arial", NULL, DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 16.0f, L"en-us", &fmt);
    if (fmt) hr = IDWriteFactory_CreateTextLayout(f, L"KernelEx-NG on Windows 98", 25, fmt, 400.0f, 100.0f, &lay);
    if (lay) {
        DWRITE_TEXT_METRICS m;
        hr = IDWriteTextLayout_GetMetrics(lay, &m);
        LOG("    text layout: %08lx, width %d.%02d px, %u line(s)\n", (unsigned long)hr, (int)m.width, (int)(m.width * 100) % 100, m.lineCount);
        CHECK(SUCCEEDED(hr) && m.width > 50.0f && m.width < 400.0f && m.lineCount == 1, "text layout measures a line");
    } else CHECK(0, "text format / layout (hr %08lx)", (unsigned long)hr);
    if (lay) IDWriteTextLayout_Release(lay);
    if (fmt) IDWriteTextFormat_Release(fmt);
    if (ana) IDWriteGlyphRunAnalysis_Release(ana);
    if (face) IDWriteFontFace_Release(face);
    if (font) IDWriteFont_Release(font);
    if (fam) IDWriteFontFamily_Release(fam);
    if (coll) IDWriteFontCollection_Release(coll);
    IDWriteFactory_Release(f);
}

static void test_tls_dll(void)
{
    STARTUPINFOA si; PROCESS_INFORMATION pi; char cmd[MAX_PATH + 16]; DWORD code = 99;
    LOG("[TLS DLL]\n");
    GetModuleFileNameA(NULL, cmd, MAX_PATH); strcat(cmd, " tlschild");
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) { CHECK(0, "CreateProcess(tlschild) %lu", GetLastError()); return; }
    WaitForSingleObject(pi.hProcess, 300000);     /* build 120: was 15 s - too short in an emulated VM (result 259) */
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    if (code == STILL_ACTIVE) LOG("    the child was still running after 300 s\n");
    if (code >= 1000 && code < 0x10000) LOG("    LoadLibrary(kextls.dll) FAILED, error %lu\n", code - 1000);
    else if (code == 4) LOG("    loaded, but the TLS variable was wrong (TLS not initialised)\n");
    else if (code == 5) LOG("    TLS works on the loading thread, but not on a thread that existed before the load\n");
    else if (code == 6) LOG("    TLS works on the loading thread, but not on a thread created later\n");
    else if (code == 7) LOG("    TLS works, but the DLL's TLS callback was not called\n");
    else if (code == 8) LOG("    threads share one TLS copy instead of one each\n");
    else if (code == 9) LOG("    TLS works after LoadLibrary, but not yet inside the DLL's DllMain (NT: before)\n");
    else if (code == 10) LOG("    TLS callback ran after DllMain (NT: before)\n");
    else if (code == 13) LOG("    kexnotls.dll missing next to kextest\n");
    else if (code == 15) {
        char tmp[MAX_PATH], why[MAX_PATH + 16], t[MAX_PATH + 160]; HANDLE f; DWORD r = 0;
        GetTempPathA(MAX_PATH, tmp); sprintf(why, "%skxtls.txt", tmp); t[0] = 0;
        if ((f = CreateFileA(why, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE) { ReadFile(f, t, sizeof(t) - 1, &r, NULL); t[r] = 0; CloseHandle(f); }
        LOG("    could not copy/load the 40 extra TLS DLLs in %%TEMP%%: %s\n", t[0] ? t : "(no detail)");
    }
    else if (code == 14) LOG("    (kextls.dll did not land at the freed kexnotls.dll address - address-reuse case not tested)\n");
    else if (code == 11) LOG("    after FreeLibrary + LoadLibrary again: TLS not set up inside DllMain\n");
    else if (code == 12) LOG("    after FreeLibrary + LoadLibrary again: TLS kept the old value instead of a fresh copy\n");
    else if (code == 0) LOG("    thread_local ok inside DllMain (also as the 41st TLS DLL, and at a reused address), on the loading thread, an older and a new thread, and after a reload; callbacks ran first\n");
    else if (code > 0x10000) LOG("    the child crashed (exception %08lx) - TLS not initialised\n", code);
    else LOG("    child result %lu\n", code);
    CHECK(code == 0 || code == 14, "LoadLibrary of a DLL with static TLS works (child result %lu)", code);
}

/* ---------------- stub DLLs installed by KEXSETUP (long names must survive) ---------------- */
static void test_stubs(void)
{
    char me[MAX_PATH], list[MAX_PATH], line[MAX_PATH], sys[MAX_PATH], path[MAX_PATH], *p; FILE *f; int n = 0;
    LOG("[stub DLLs]\n");
    GetModuleFileNameA(NULL, me, sizeof(me));
    if ((p = strrchr(me, '\\'))) *p = 0;
    sprintf(list, "%s\\stub_dlls.txt", me);
    if (!(f = fopen(list, "r"))) { LOG("    (stub_dlls.txt not next to kextest - skipped)\n"); return; }
    GetSystemDirectoryA(sys, sizeof(sys));
    while (fgets(line, sizeof(line), f)) {
        HMODULE h; DWORD a, e;
        if ((p = strpbrk(line, " \t\r\n"))) *p = 0;
        if (!line[0]) continue;
        sprintf(path, "%s\\%s", sys, line);
        a = GetFileAttributesA(path);
        CHECK(a != 0xFFFFFFFF, "%s missing in SYSTEM under its long name - run KEXSETUP again", line);
        if (a == 0xFFFFFFFF) continue;
        if (strstr(line, ".cpl")) { n++; continue; }
        {   /* build 131: a name KernelEx's KnownDLLs sends to a real Windows 10 DLL (KEXSETUP's Windows 10 DWrite.dll)
             * is not our stub any more - its presence is enough here (loading Windows 10 DWrite into kextest, which
             * holds a second kexnt.dll copy, hung Windows 98) */
            HKEY k; char nm[MAX_PATH], v[MAX_PATH], *d; DWORD sz = sizeof(v); LONG q = 1;
            lstrcpynA(nm, line, sizeof(nm)); if ((d = strrchr(nm, '.'))) *d = 0;
            if (RegOpenKeyA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KnownDLLs", &k) == ERROR_SUCCESS) {
                q = RegQueryValueExA(k, nm, NULL, NULL, (BYTE *)v, &sz); RegCloseKey(k); }
            if (q == ERROR_SUCCESS) { LOG("    %s: KernelEx KnownDLLs -> %s (the Windows 10 DLL) - not loaded here\n", line, v); n++; continue; }
        }
        SetLastError(0);
        h = LoadLibraryA(line); e = GetLastError();
        CHECK(h != NULL, "LoadLibrary(%s) error %lu", line, e);
        if (h) { FreeLibrary(h); n++; }
    }
    fclose(f);
    LOG("    %d stub DLL(s) present and loadable\n", n);
}

/* ---------------- child processes as Chromium launches them (procspawn_ext.c) ---------------- */
typedef BOOL (WINAPI *T_SHI)(HANDLE, DWORD, DWORD);
typedef BOOL (WINAPI *T_GHI)(HANDLE, LPDWORD);
typedef BOOL (WINAPI *T_CPW2)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                              LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef LONG (WINAPI *T_NQO)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef BOOL (WINAPI *T_DH2)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
/* the NT type name of a handle through kexnt's NtQueryObject, as Chromium's GetObjectTypeName asks */
static int nt_type_is(HANDLE h, const char *want)
{
    T_NQO q = kx ? (T_NQO)(void *)GetProcAddress(kx, "NtQueryObject") : NULL;
    BYTE buf[200]; ULONG got = 0; WORD n; const WCHAR *w; int i;
    if (!q || q(h, 2, buf, sizeof(buf), &got) != 0) return 0;
    n = *(WORD *)buf / 2; w = *(const WCHAR **)(buf + 4);
    for (i = 0; i < n && want[i]; i++) if (w[i] != (WCHAR)want[i]) return 0;
    return i == n && !want[i];
}
static int inh_child(const char *hs, const char *ss, const char *xs)
{
    HANDLE h = (HANDLE)(ULONG_PTR)strtoul(hs, NULL, 16); char v[16];
    if (!SetEvent(h)) return 2;                         /* the inherited handle has the same value here */
    if (GetEnvironmentVariableA("KEXINH", v, sizeof(v)) != 3 || strcmp(v, "yes")) return 3;
    if (xs && strtoul(xs, NULL, 16)) SetEvent((HANDLE)(ULONG_PTR)strtoul(xs, NULL, 16)); /* NOT in the handle list: must not reach the parent's event */
    if (ss && strtoul(ss, NULL, 16)) {                 /* an inherited read-only section, as Chromium passes them */
        HANDLE sh = (HANDLE)(ULONG_PTR)strtoul(ss, NULL, 16), w = NULL;
        char dllpath[MAX_PATH], *bs; T_DH2 dh;
        GetModuleFileNameA(NULL, dllpath, MAX_PATH);
        if ((bs = strrchr(dllpath, '\\'))) { bs[1] = 0; strcat(dllpath, "kexnt.dll"); }
        if (!(kx = LoadLibraryA(dllpath))) return 4;
        if (!nt_type_is(sh, "Section")) return 5;
        dh = (T_DH2)(void *)GetProcAddress(kx, "DuplicateHandle");
        if (!dh) return 6;
        if (dh(GetCurrentProcess(), sh, GetCurrentProcess(), &w, FILE_MAP_WRITE, FALSE, 0)) { CloseHandle(w); return 7; }
    }
    return 0;
}
static HANDLE g_ro_sec;
static void test_spawn(void)
{
    T_SHI shi = (T_SHI)(void *)GetProcAddress(kx, "SetHandleInformation");
    T_GHI ghi = (T_GHI)(void *)GetProcAddress(kx, "GetHandleInformation");
    T_CPW2 cpw = (T_CPW2)(void *)GetProcAddress(kx, "CreateProcessW");
    HANDLE ev, unl; DWORD fl = 99, fl2 = 99, code = 99; BOOL ok1, ok2, ok3;
    SECURITY_ATTRIBUTES isa = { sizeof(isa), NULL, TRUE };
    LOG("[child processes]\n");
    CHECK(shi && ghi && cpw, "kexnt exports SetHandleInformation / GetHandleInformation / CreateProcessW");
    if (!shi || !ghi || !cpw) return;
    ev = CreateEventA(NULL, TRUE, FALSE, NULL);          /* not inheritable */
    unl = CreateEventA(&isa, TRUE, FALSE, NULL);         /* inheritable but left out of the handle list */
    {   /* NtQueryObject type names (Chromium's GetObjectTypeName) */
        HANDLE sec = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, NULL);
        CHECK(nt_type_is(ev, "Event"), "NtQueryObject(event) type Event");
        CHECK(sec && nt_type_is(sec, "Section"), "NtQueryObject(mapping) type Section");
        CHECK(nt_type_is(GetCurrentProcess(), "Process"), "NtQueryObject(GetCurrentProcess()) type Process");
        if (sec) {
            T_DH2 dh = (T_DH2)(void *)GetProcAddress(kx, "DuplicateHandle");
            if (dh && dh(GetCurrentProcess(), sec, GetCurrentProcess(), &g_ro_sec, FILE_MAP_READ, TRUE, 0)) {
                LOG("    read-only section copy %p for the child\n", g_ro_sec);
            }
            CloseHandle(sec);
        }
    }
    ok1 = ghi(ev, &fl);
    ok2 = shi(ev, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    ok3 = ghi(ev, &fl2);
    LOG("    GetHandleInformation %d -> %lu, SetHandleInformation(INHERIT) %d (error %lu), then %lu\n",
        ok1, fl, ok2, ok2 ? 0 : GetLastError(), fl2);
    CHECK(ok1 && fl == 0, "new event not inheritable (%d, %lu)", ok1, fl);
    CHECK(ok2, "SetHandleInformation(HANDLE_FLAG_INHERIT) %lu", GetLastError());
    CHECK(ok3 && fl2 == HANDLE_FLAG_INHERIT, "inherit flag reported back (%lu)", fl2);
    {
        STARTUPINFOEXW si; PROCESS_INFORMATION pi; WCHAR cmd[MAX_PATH + 64]; char me[MAX_PATH], win[MAX_PATH];
        WCHAR env[600]; int n; SIZE_T asz = 0; BYTE attrs[256]; HANDLE list[2]; int nl = 1; BOOL r;
        GetModuleFileNameA(NULL, me, MAX_PATH);
        n = MultiByteToWideChar(CP_ACP, 0, me, -1, cmd, MAX_PATH) - 1;
        swprintf(cmd + n, 64, L" inhchild %lx %lx %lx", (unsigned long)(ULONG_PTR)ev, (unsigned long)(ULONG_PTR)g_ro_sec,
                 (unsigned long)(ULONG_PTR)unl);
        GetWindowsDirectoryA(win, MAX_PATH);
        n = swprintf(env, 600, L"KEXINH=yes") + 1;
        n += swprintf(env + n, 600 - n, L"windir=%hs", win) + 1;
        n += swprintf(env + n, 600 - n, L"PATH=%hs;%hs\\COMMAND", win, win) + 1;
        env[n] = 0;
        memset(&si, 0, sizeof(si)); si.StartupInfo.cb = sizeof(si);
        pInitializeProcThreadAttributeList(NULL, 1, 0, &asz);
        si.lpAttributeList = asz <= sizeof(attrs) ? (LPPROC_THREAD_ATTRIBUTE_LIST)attrs : NULL;
        list[0] = ev;
        if (g_ro_sec) list[nl++] = g_ro_sec;               /* Chromium lists every handle the child needs */
        if (si.lpAttributeList) {
            pInitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &asz);
            pUpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list, nl * sizeof(HANDLE), NULL, NULL);
        }
        si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW; si.StartupInfo.wShowWindow = SW_HIDE;
        si.StartupInfo.lpDesktop = (LPWSTR)L"";
        r = cpw(NULL, cmd, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | 0x01000000,
                env, NULL, &si.StartupInfo, &pi);
        CHECK(r, "CreateProcessW with STARTUPINFOEX + HANDLE_LIST + unicode environment: error %lu", r ? 0 : GetLastError());
        if (r) {
            DWORD w = WaitForSingleObject(ev, 10000);
            WaitForSingleObject(pi.hProcess, 10000);
            GetExitCodeProcess(pi.hProcess, &code);
            LOG("    child: signalled the inherited event %s, exit code %lu (0 ok, 2 handle not inherited, 3 environment, 5 section type, 7 read-only section writable)\n",
                w == WAIT_OBJECT_0 ? "yes" : "no", code);
            CHECK(w == WAIT_OBJECT_0 && code == 0, "child used the inherited handle value and saw the environment (%lu)", code);
            {   DWORD wu = unl ? WaitForSingleObject(unl, 0) : 99, fu = 99;
                ghi(unl, &fu);
                LOG("    handle left out of the list: reached the child %s, still inheritable in the parent afterwards %s\n",
                    wu == WAIT_OBJECT_0 ? "YES" : "no", fu == HANDLE_FLAG_INHERIT ? "yes" : "NO");
                CHECK(unl && wu == WAIT_TIMEOUT, "handle not in PROC_THREAD_ATTRIBUTE_HANDLE_LIST was inherited (%lu)", wu);
                CHECK(fu == HANDLE_FLAG_INHERIT, "parent's inherit flag restored after CreateProcess (%lu)", fu);
            }
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        }
        if (si.lpAttributeList) pDeleteProcThreadAttributeList(si.lpAttributeList);
    }
    if (g_ro_sec) CloseHandle(g_ro_sec);
    if (unl) CloseHandle(unl);
    CloseHandle(ev);
}

/* ---------------- shared memory as Chromium creates it (shm_ext.c) ---------------- */
typedef HANDLE (WINAPI *T_CFMW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef BOOL (WINAPI *T_IACL)(PACL, DWORD, DWORD);
typedef BOOL (WINAPI *T_ISD)(PSECURITY_DESCRIPTOR, DWORD);
typedef BOOL (WINAPI *T_SSDD)(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);

static void test_shm(void)
{
    GP(T_CFMW, p_CreateFileMappingW);
    HMODULE adv = GetModuleHandleA("ADVAPI32.DLL");
    T_IACL iacl = (T_IACL)(void *)GetProcAddress(adv, "InitializeAcl");
    T_ISD isd = (T_ISD)(void *)GetProcAddress(adv, "InitializeSecurityDescriptor");
    T_SSDD ssdd = (T_SSDD)(void *)GetProcAddress(adv, "SetSecurityDescriptorDacl");
    ACL acl; SECURITY_DESCRIPTOR sd; SECURITY_ATTRIBUTES sa; HANDLE h, h2 = NULL, n1, n2; DWORD e; BYTE *v;

    LOG("[shared memory (Chromium)]\n");
    CHECK(p_CreateFileMappingW != NULL, "CreateFileMappingW exported by kexnt");
    if (!p_CreateFileMappingW) return;

    /* what Win98 itself does (information only) */
    SetLastError(ERROR_ALREADY_EXISTS);
    h = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x8000, NULL);
    e = GetLastError();
    LOG("    native CreateFileMappingA: handle %p, last error left at %lu%s\n", h, e,
        e == ERROR_ALREADY_EXISTS ? " (stale - this is what broke Chromium)" : "");
    if (h) CloseHandle(h);
    memset(&acl, 0, sizeof(acl)); memset(&sd, 0, sizeof(sd));
    LOG("    ADVAPI32 as this program sees it: InitializeAcl %s, InitializeSecurityDescriptor %s, SetSecurityDescriptorDacl %s\n",
        iacl ? (iacl(&acl, sizeof(acl), ACL_REVISION) ? "ok" : "FALSE") : "missing",
        isd ? (isd(&sd, SECURITY_DESCRIPTOR_REVISION) ? "ok" : "FALSE") : "missing",
        ssdd ? (ssdd(&sd, TRUE, &acl, FALSE) ? "ok" : "FALSE") : "missing");

    {   /* where GetProcAddress points, the way chrome_elf's delay-load helper asks */
        HMODULE a2 = LoadLibraryExA("ADVAPI32.dll", NULL, 0);
        const char *fn[3] = { "InitializeAcl", "InitializeSecurityDescriptor", "SetSecurityDescriptorDacl" };
        int k;
        for (k = 0; k < 3; k++) {
            FARPROC f = GetProcAddress(a2, fn[k]); MEMORY_BASIC_INFORMATION m; char mod[MAX_PATH] = "?";
            if (f && VirtualQuery((LPCVOID)f, &m, sizeof(m)) && m.AllocationBase)
                GetModuleFileNameA((HMODULE)m.AllocationBase, mod, sizeof(mod));
            LOG("    GetProcAddress(ADVAPI32, %s) = %p in %s\n", fn[k], (void *)f, mod);
        }
    }

    {   /* kexnt's own versions (sec_ext.c), the ones routed under ADVAPI32 */
        GP(T_IACL, p_InitializeAcl);
        GP(T_ISD, p_InitializeSecurityDescriptor);
        GP(T_SSDD, p_SetSecurityDescriptorDacl);
        ACL a2; SECURITY_DESCRIPTOR s2;
        CHECK(p_InitializeAcl && p_InitializeSecurityDescriptor && p_SetSecurityDescriptorDacl, "kexnt security exports");
        if (p_InitializeAcl && p_InitializeSecurityDescriptor && p_SetSecurityDescriptorDacl) {
            CHECK(p_InitializeAcl(&a2, sizeof(a2), ACL_REVISION) && a2.AclRevision == ACL_REVISION && a2.AclSize == 8 && !a2.AceCount,
                  "kexnt InitializeAcl(8, ACL_REVISION)");
            CHECK(!p_InitializeAcl(&a2, 4, ACL_REVISION) && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "InitializeAcl(4) refused");
            CHECK(p_InitializeSecurityDescriptor(&s2, SECURITY_DESCRIPTOR_REVISION) && s2.Revision == 1 && !s2.Control,
                  "kexnt InitializeSecurityDescriptor");
            CHECK(p_SetSecurityDescriptorDacl(&s2, TRUE, &a2, FALSE) && (s2.Control & SE_DACL_PRESENT) && s2.Dacl == &a2,
                  "kexnt SetSecurityDescriptorDacl(empty DACL)");
        }
    }

    {   /* KernelEx token placeholder handle */
        typedef BOOL (WINAPI *T_CH)(HANDLE);
        T_CH ch = (T_CH)(void *)GetProcAddress(kx, "CloseHandle");
        CHECK(ch && ch((HANDLE)0xCAFE), "CloseHandle(token placeholder 0xCAFE) succeeds");
        CHECK(ch && !ch((HANDLE)0x12345678), "CloseHandle(bogus handle) still fails");
    }

    /* Chromium's sequence */
    sa.nLength = sizeof(sa); sa.lpSecurityDescriptor = &sd; sa.bInheritHandle = FALSE;
    SetLastError(ERROR_ALREADY_EXISTS);                                   /* stale value as in chrome */
    h = p_CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, 0x8000, NULL);
    e = GetLastError();
    CHECK(h != NULL, "CreateFileMappingW(anonymous, empty-DACL sa) error %lu", e);
    CHECK(e == 0, "last error after a new mapping is 0 (got %lu)", e);
    if (!h) return;
    CHECK(DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &h2, 0x20007, FALSE, 0) && h2,
          "DuplicateHandle(mapping, FILE_MAP_READ|WRITE|SECTION_QUERY) error %lu", GetLastError());
    CloseHandle(h);
    CHECK(GetLastError() != ERROR_ALREADY_EXISTS, "no ERROR_ALREADY_EXISTS after duplicate+close");
    if (h2) {
        v = MapViewOfFile(h2, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0x8000);
        CHECK(v != NULL, "MapViewOfFile(duplicate) error %lu", GetLastError());
        if (v) {
            MEMORY_BASIC_INFORMATION mbi; SIZE_T q; DWORD mapped;
            v[0] = 0x5A; v[0x7FFF] = 0xA5; CHECK(v[0] == 0x5A && v[0x7FFF] == 0xA5, "view read/write");
            memset(&mbi, 0xFF, sizeof(mbi));
            q = VirtualQuery(v, &mbi, sizeof(mbi));
            /* what Chromium computes (base/memory/platform_shared_memory_mapper_win.cc) */
            mapped = q ? (DWORD)((BYTE *)mbi.AllocationBase + mbi.RegionSize - v) : 0;
            LOG("    view %p: VirtualQuery ret %lu base %p allocbase %p size %08lx state %08lx protect %08lx type %08lx\n",
                v, (DWORD)q, mbi.BaseAddress, mbi.AllocationBase, (DWORD)mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type);
            CHECK(q == sizeof(mbi) && mapped >= 0x8000, "Chromium's mapped size %lu (needs >= 32768)", mapped);
            UnmapViewOfFile(v);
        }
        {   /* the same section mapped twice in one process (Chromium in-process users of one region) */
            typedef LPVOID (WINAPI *T_MV)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
            typedef BOOL (WINAPI *T_UV)(LPCVOID);
            T_MV mv = (T_MV)(void *)GetProcAddress(kx, "MapViewOfFile");
            T_UV uv = (T_UV)(void *)GetProcAddress(kx, "UnmapViewOfFile");
            if (mv && uv) {
                volatile BYTE *a = (volatile BYTE *)mv(h2, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0x8000);
                volatile BYTE *b = (volatile BYTE *)mv(h2, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0x8000);
                BOOL still = FALSE;
                BOOL both = FALSE;
                LOG("    same section twice: %p and %p (%s)\n", (void *)a, (void *)b,
                    a && b && a != b ? "two addresses - KEXALIAS.VXD alias" : "ONE address - KEXALIAS.VXD not working");
                if (a && b) {
                    {   /* what Chromium computes: RegionSize - (view - AllocationBase) must cover the request */
                        typedef SIZE_T (WINAPI *T_VQ)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
                        T_VQ vq = (T_VQ)(void *)GetProcAddress(kx, "VirtualQuery");
                        MEMORY_BASIC_INFORMATION q2; DWORD span = 0;
                        if (vq && b && vq((LPCVOID)b, &q2, sizeof(q2)))
                            span = (DWORD)(q2.RegionSize - ((BYTE *)b - (BYTE *)q2.AllocationBase));
                        CHECK(span >= 0x8000, "Chromium's size of the second view: %lu (needs >= 32768)", span);
                        if (span < 0x8000) {   /* build 41: how Windows describes the first view, region by region */
                            MEMORY_BASIC_INFORMATION r1; BYTE *p = (BYTE *)a; int k;
                            for (k = 0; k < 8 && VirtualQuery(p, &r1, sizeof(r1)) && r1.RegionSize && r1.AllocationBase == (void *)a; k++, p += r1.RegionSize)
                                LOG("      region %p size %08lx state %08lx protect %08lx\n", r1.BaseAddress, (DWORD)r1.RegionSize, r1.State, r1.Protect);
                        }
                    }
                    a[16] = 0x77;
                    both = b[16] == 0x77;
                    b[100] = 0x55; both = both && a[100] == 0x55;
                    uv((LPCVOID)a);
                    still = !IsBadReadPtr((const void *)b, 32) && b[16] == 0x77;
                    uv((LPCVOID)b);
                }
                CHECK(a && b && still, "second view still usable after the first is unmapped (%p %p %d)", (void *)a, (void *)b, still);
                CHECK(a && b && a != b, "second view of one section gets its own address (Chromium's data pipes need it)");
                CHECK(both, "the two views show the same memory");
                CHECK(!((DWORD)(ULONG_PTR)b & 0xFFFF), "the second view (alias) starts on a 64 KB boundary: %p", (void *)b);
            }
            if (mv && uv) {   /* build 33: Chromium unmaps AlignDown(view, 64 KB); small views share 64 KB windows on 9x.
                               * Each unmap must hit exactly its own view - the others keep their memory. */
                HANDLE sh[8]; volatile BYTE *sv[8]; int k, j, ok_all = 1, unal = 0, unm = 1;
                for (k = 0; k < 8; k++) {
                    sh[k] = p_CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, NULL);
                    sv[k] = sh[k] ? (volatile BYTE *)mv(sh[k], FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0) : NULL;
                    if (sv[k]) { sv[k][0] = (BYTE)(0xC0 + k); if ((DWORD)(ULONG_PTR)sv[k] & 0xFFFF) unal++; } else ok_all = 0;
                }
                for (k = 7; k >= 0 && ok_all; k--) {
                    LPCVOID al = (LPCVOID)((DWORD)(ULONG_PTR)sv[k] & ~0xFFFFUL);
                    if (!uv(al)) unm = 0;
                    for (j = 0; j < k; j++)
                        if (IsBadReadPtr((const void *)sv[j], 1) || sv[j][0] != (BYTE)(0xC0 + j)) ok_all = 0;
                }
                LOG("    8 small sections: %d views not 64 KB aligned\n", unal);
                CHECK(ok_all && unm, "unmapping AlignDown(view, 64 KB) releases exactly that view (all 8: %d, unmaps ok %d)", ok_all, unm);
                for (k = 0; k < 8; k++) if (sh[k]) CloseHandle(sh[k]);
            }
            if (mv && uv) {   /* build 38b: which step keeps a released section alive? 4 MB sections, shared-arena free
                               * space measured after each step (KB lost vs the start). N = Windows' own KERNEL32 (export
                               * table walked by hand, so nothing in between), K = through kexnt. */
                typedef BOOL (WINAPI *T_CH)(HANDLE);
                typedef HANDLE (WINAPI *T_CFM)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
                typedef LPVOID (WINAPI *T_MVN)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
                typedef BOOL (WINAPI *T_UVN)(LPCVOID);
                typedef LONG (WINAPI *T_RC)(void);
                T_CH ch = (T_CH)(void *)GetProcAddress(kx, "CloseHandle");
                T_RC rc = (T_RC)(void *)GetProcAddress(kx, "KexShmRefcounted");
                T_CFM ncfm = (T_CFM)native_k32("CreateFileMappingA");
                T_MVN nmv = (T_MVN)native_k32("MapViewOfFile");
                T_UVN nuv = (T_UVN)native_k32("UnmapViewOfFile");
                T_CH nch = (T_CH)native_k32("CloseHandle");
                DWORD f0; HANDLE s2; BYTE *x, *y; volatile BYTE *a2, *b2; long d1, d2, d3; BOOL r1, r2;
#define LOST() ((long)(f0 >> 10) - (long)(shared_free() >> 10))
                LOG("    kexnt: Windows counts views per process: %ld\n", rc ? rc() : -1L);
                {   /* build 39: Chromium maps tiny regions (8 bytes) twice - the alias must cover only committed pages */
                    HANDLE t8 = p_CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 8, NULL);
                    volatile BYTE *ta = t8 ? (volatile BYTE *)mv(t8, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 8) : NULL;
                    volatile BYTE *tb = t8 ? (volatile BYTE *)mv(t8, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 8) : NULL;
                    if (ta) ta[3] = 0x5C;
                    CHECK(ta && tb && ta != tb && tb[3] == 0x5C, "8-byte section mapped twice: second view %p of %p", (void *)tb, (void *)ta);
                    if (tb) uv((LPCVOID)tb);
                    if (ta) uv((LPCVOID)ta);
                    if (t8) { if (ch) ch(t8); else CloseHandle(t8); }
                }
                if (ncfm && nmv && nuv && nch) {
                    /* N1: one view */
                    f0 = shared_free(); s2 = ncfm(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x400000, NULL);
                    x = s2 ? (BYTE *)nmv(s2, FILE_MAP_WRITE, 0, 0, 0) : NULL; if (x) x[0] = 1;
                    if (x) nuv(x); if (s2) nch(s2);
                    LOG("    leak test N1 (native, map, unmap, close): %ld KB lost\n", LOST());
                    /* N2: map twice, unmap, unmap, close */
                    f0 = shared_free(); s2 = ncfm(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x400000, NULL);
                    x = s2 ? (BYTE *)nmv(s2, FILE_MAP_WRITE, 0, 0, 0) : NULL;
                    y = s2 ? (BYTE *)nmv(s2, FILE_MAP_WRITE, 0, 0, 0) : NULL;
                    r1 = x ? nuv(x) : 0; r2 = y ? nuv(y) : 0; d1 = LOST();
                    if (s2) nch(s2); d2 = LOST();
                    LOG("    leak test N2 (native, map x2 %p %p, unmap %d, unmap %d, close): %ld KB lost before close, %ld after\n",
                        x, y, r1, r2, d1, d2);
                    /* N3: map twice, unmap ONCE, close */
                    f0 = shared_free(); s2 = ncfm(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x400000, NULL);
                    x = s2 ? (BYTE *)nmv(s2, FILE_MAP_WRITE, 0, 0, 0) : NULL;
                    y = s2 ? (BYTE *)nmv(s2, FILE_MAP_WRITE, 0, 0, 0) : NULL;
                    r1 = x ? nuv(x) : 0; if (s2) nch(s2); d1 = LOST();
                    r2 = y ? nuv(y) : 0; d2 = LOST();
                    LOG("    leak test N3 (native, map x2, unmap %d, close): %ld KB lost; 2nd unmap %d: %ld KB lost\n", r1, d1, r2, d2);
                }
                /* K1: one view through kexnt */
                f0 = shared_free(); s2 = p_CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x400000, NULL);
                a2 = s2 ? (volatile BYTE *)mv(s2, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0) : NULL; if (a2) a2[0] = 1;
                if (a2) uv((LPCVOID)a2); if (s2) { if (ch) ch(s2); else CloseHandle(s2); }
                LOG("    leak test K1 (kexnt, 1 view %p): %ld KB lost\n", (void *)a2, LOST());
                /* K2: two views through kexnt, the alias unmapped first (Chromium's usual order) */
                f0 = shared_free(); s2 = p_CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x400000, NULL);
                a2 = s2 ? (volatile BYTE *)mv(s2, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0) : NULL;
                b2 = s2 ? (volatile BYTE *)mv(s2, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0) : NULL;
                if (a2) a2[0] = 1;
                r2 = b2 ? uv((LPCVOID)b2) : 0; d1 = LOST();
                r1 = a2 ? uv((LPCVOID)a2) : 0; d2 = LOST();
                if (s2) { if (ch) ch(s2); else CloseHandle(s2); }
                d3 = LOST();
                LOG("    leak test K2 (kexnt, 2 views %p %p): unmap 2nd %d -> %ld KB lost, unmap 1st %d -> %ld, close -> %ld\n",
                    (void *)a2, (void *)b2, r2, d1, r1, d2, d3);
                CHECK(a2 && b2 && d3 < 1024, "a section mapped twice is really freed after both unmaps and close (%ld KB lost)", d3);
                /* K3: two views, the real one unmapped first */
                f0 = shared_free(); s2 = p_CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x400000, NULL);
                a2 = s2 ? (volatile BYTE *)mv(s2, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0) : NULL;
                b2 = s2 ? (volatile BYTE *)mv(s2, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0) : NULL;
                r1 = a2 ? uv((LPCVOID)a2) : 0; d1 = LOST();
                r2 = b2 ? uv((LPCVOID)b2) : 0; d2 = LOST();
                if (s2) { if (ch) ch(s2); else CloseHandle(s2); }
                d3 = LOST();
                LOG("    leak test K3 (kexnt, 2 views %p %p): unmap 1st %d -> %ld KB lost, unmap 2nd %d -> %ld, close -> %ld\n",
                    (void *)a2, (void *)b2, r1, d1, r2, d2, d3);
#undef LOST
            }
        }
        CloseHandle(h2);
    }

    /* named objects + NT namespace prefix */
    n1 = p_CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE | SEC_COMMIT, 0, 4096, L"Local\\KexNgShmTest");
    e = GetLastError();
    CHECK(n1 && e == 0, "named mapping (Local\\, PAGE_EXECUTE_READWRITE) %p error %lu", n1, e);
    n2 = p_CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, L"KexNgShmTest");
    e = GetLastError();
    CHECK(n2 && e == ERROR_ALREADY_EXISTS, "same name again -> ERROR_ALREADY_EXISTS (%p, %lu)", n2, e);
    if (n1) CloseHandle(n1);
    if (n2) CloseHandle(n2);
}

/* ---------------- NT native registry (ntreg_ext.c) ---------------- */
typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } T_USTR;
typedef struct { ULONG Length; HANDLE Root; T_USTR *Name; ULONG Attr; PVOID Sd, Sqos; } T_OA;
typedef LONG (WINAPI *T_NTCK)(PHANDLE, ACCESS_MASK, T_OA *, ULONG, T_USTR *, ULONG, PULONG);
typedef LONG (WINAPI *T_NTOKX)(PHANDLE, ACCESS_MASK, T_OA *, ULONG);
typedef LONG (WINAPI *T_NTQVK)(HANDLE, T_USTR *, ULONG, PVOID, ULONG, PULONG);
typedef LONG (WINAPI *T_NTSVK)(HANDLE, T_USTR *, ULONG, ULONG, PVOID, ULONG);
typedef LONG (WINAPI *T_NTH)(HANDLE);
typedef LONG (WINAPI *T_FCU)(T_USTR *);
typedef VOID (WINAPI *T_FREEU)(T_USTR *);

static void us(T_USTR *u, const WCHAR *s) { USHORT n = 0; while (s[n]) n++; u->Buffer = (PWSTR)s; u->Length = n * 2; u->MaximumLength = n * 2 + 2; }
static void oa(T_OA *o, HANDLE root, T_USTR *n) { memset(o, 0, sizeof(*o)); o->Length = sizeof(*o); o->Root = root; o->Name = n; o->Attr = 0x40; }

static void test_ntreg(void)
{
    GP(T_NTCK, p_NtCreateKey);
    GP(T_NTOKX, p_NtOpenKeyEx);
    GP(T_NTQVK, p_NtQueryValueKey);
    GP(T_NTSVK, p_NtSetValueKey);
    GP(T_NTH, p_NtDeleteKey);
    GP(T_NTH, p_NtClose);
    GP(T_FCU, p_RtlFormatCurrentUserKeyPath);
    GP(T_FREEU, p_RtlFreeUnicodeString);
    T_USTR cu, n, v; T_OA o; HANDLE k = NULL, k2 = NULL, kc = NULL; ULONG disp = 0, need = 0; LONG s;
    WCHAR path[260]; BYTE buf[256]; HKEY hk; char sbuf[64]; DWORD t, sz;

    LOG("[NT registry]\n");
    CHECK(p_NtCreateKey && p_NtOpenKeyEx && p_NtQueryValueKey && p_NtSetValueKey && p_NtDeleteKey && p_NtClose &&
          p_RtlFormatCurrentUserKeyPath && p_RtlFreeUnicodeString, "NT registry exports present");
    if (!(p_NtCreateKey && p_NtOpenKeyEx && p_NtQueryValueKey && p_NtSetValueKey && p_NtDeleteKey && p_NtClose &&
          p_RtlFormatCurrentUserKeyPath && p_RtlFreeUnicodeString)) return;

    s = p_RtlFormatCurrentUserKeyPath(&cu);
    CHECK(s == 0 && cu.Buffer && cu.Length > 30, "RtlFormatCurrentUserKeyPath %08lx", s);
    if (s) return;
    memcpy(path, cu.Buffer, cu.Length); path[cu.Length / 2] = 0;
    p_RtlFreeUnicodeString(&cu);
    lstrcatW(path, L"\\Software\\KexNgTest");

    /* create \REGISTRY\USER\<sid>\Software\KexNgTest -> HKCU\Software\KexNgTest */
    us(&n, path); oa(&o, NULL, &n);
    s = p_NtCreateKey(&k, KEY_ALL_ACCESS, &o, 0, NULL, 0, &disp);
    CHECK(s == 0 && k, "NtCreateKey(HKCU path) %08lx", s);
    if (s) return;
    CHECK(disp == 1 || disp == 2, "NtCreateKey disposition %lu", disp);
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\KexNgTest", 0, KEY_READ, &hk) == 0) { g_pass++; RegCloseKey(hk); }
    else CHECK(0, "key visible as HKCU\\Software\\KexNgTest");

    /* string value round trip */
    us(&v, L"Str");
    s = p_NtSetValueKey(k, &v, 0, REG_SZ, (PVOID)L"hello", 12);
    CHECK(s == 0, "NtSetValueKey(REG_SZ) %08lx", s);
    sz = sizeof(sbuf); sbuf[0] = 0;
    CHECK(RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\KexNgTest", 0, KEY_READ, &hk) == 0 &&
          RegQueryValueExA(hk, "Str", NULL, &t, (BYTE *)sbuf, &sz) == 0 && t == REG_SZ && !lstrcmpA(sbuf, "hello"),
          "Win32 reads back \"%s\"", sbuf);
    RegCloseKey(hk);
    s = p_NtQueryValueKey(k, &v, 2, NULL, 0, &need);
    CHECK(s == (LONG)0xC0000023 && need == 12 + 12, "NtQueryValueKey(size probe) %08lx need %lu", s, need);
    s = p_NtQueryValueKey(k, &v, 2, buf, sizeof(buf), &need);
    CHECK(s == 0 && ((ULONG *)buf)[1] == REG_SZ && ((ULONG *)buf)[2] == 12 && !lstrcmpW((WCHAR *)(buf + 12), L"hello"),
          "KeyValuePartialInformation %08lx", s);
    s = p_NtQueryValueKey(k, &v, 1, buf, sizeof(buf), &need);
    CHECK(s == 0 && ((ULONG *)buf)[4] == 6 && ((ULONG *)buf)[3] == 12 &&
          !lstrcmpW((WCHAR *)(buf + ((ULONG *)buf)[2]), L"hello"), "KeyValueFullInformation %08lx", s);
    s = p_NtQueryValueKey(k, &v, 2, buf, 14, &need);
    CHECK(s == (LONG)0x80000005 && ((ULONG *)buf)[2] == 12, "short buffer -> STATUS_BUFFER_OVERFLOW %08lx", s);

    /* DWORD value + missing value */
    {
        DWORD d = 0x12345678; us(&v, L"Num");
        CHECK(p_NtSetValueKey(k, &v, 0, REG_DWORD, &d, 4) == 0, "NtSetValueKey(REG_DWORD)");
        s = p_NtQueryValueKey(k, &v, 2, buf, sizeof(buf), &need);
        CHECK(s == 0 && ((ULONG *)buf)[1] == REG_DWORD && *(DWORD *)(buf + 12) == 0x12345678, "DWORD read back %08lx", s);
        us(&v, L"NoSuchValue");
        s = p_NtQueryValueKey(k, &v, 2, buf, sizeof(buf), &need);
        CHECK(s == (LONG)0xC0000034, "missing value -> OBJECT_NAME_NOT_FOUND %08lx", s);
    }

    /* relative child, open via HKLM-style absolute path fails cleanly, parent delete refused */
    us(&n, L"Child"); oa(&o, k, &n);
    s = p_NtCreateKey(&kc, KEY_ALL_ACCESS, &o, 0, NULL, 0, &disp);
    CHECK(s == 0 && kc, "NtCreateKey(relative child) %08lx", s);
    s = p_NtDeleteKey(k);
    CHECK(s == (LONG)0xC0000121, "NtDeleteKey(with subkey) refused %08lx", s);
    if (kc) { CHECK(p_NtDeleteKey(kc) == 0, "NtDeleteKey(child)"); CHECK(p_NtClose(kc) == 0, "NtClose(child)"); }

    us(&n, L"\\Registry\\Machine\\Software\\KexNgNoSuchKey\\X"); oa(&o, NULL, &n);
    s = p_NtOpenKeyEx(&k2, KEY_READ, &o, 0);
    CHECK(s == (LONG)0xC0000034 && !k2, "NtOpenKeyEx(missing) %08lx", s);
    s = p_NtCreateKey(&k2, KEY_ALL_ACCESS, &o, 0, NULL, 0, &disp);
    CHECK(s == (LONG)0xC0000034 && !k2, "NtCreateKey(missing parent) %08lx", s);
    us(&n, L"\\Registry\\Machine\\Software\\Microsoft"); oa(&o, NULL, &n);
    s = p_NtOpenKeyEx(&k2, KEY_READ, &o, 0);
    CHECK(s == 0 && k2, "NtOpenKeyEx(HKLM\\Software\\Microsoft) %08lx", s);
    if (k2) CHECK(p_NtClose(k2) == 0, "NtClose(HKLM key)");

    CHECK(p_NtDeleteKey(k) == 0, "NtDeleteKey(test key)");
    CHECK(RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\KexNgTest", 0, KEY_READ, &hk) != 0, "test key gone");
    CHECK(p_NtClose(k) == 0, "NtClose(deleted key)");

    {   /* NtClose on ordinary kernel handles */
        HANDLE e = CreateEventA(NULL, FALSE, FALSE, NULL);
        CHECK(p_NtClose(e) == 0, "NtClose(event)");
        CHECK(p_NtClose(e) == (LONG)0xC0000008, "NtClose(closed handle) -> INVALID_HANDLE");
    }
}

static void test_versions(void)
{
    static const struct { DWORD maj, min, build; WORD sp; BYTE type; const char *name; } exp[] = {
        { 6, 1, 7601, 1, 1, "Windows 7 SP1" }, { 6, 1, 7601, 1, 3, "Server 2008 R2 SP1" },
        { 6, 2, 9200, 0, 1, "Windows 8" }, { 6, 2, 9200, 0, 3, "Server 2012" },
        { 6, 3, 9600, 0, 1, "Windows 8.1" }, { 6, 3, 9600, 0, 3, "Server 2012 R2" },
        { 10, 0, 10586, 0, 1, "Windows 10 1511" }, { 10, 0, 14393, 0, 1, "Windows 10 1607" },
        { 10, 0, 14393, 0, 3, "Server 2016" }, { 10, 0, 17763, 0, 1, "Windows 10 1809" },
        { 10, 0, 17763, 0, 3, "Server 2019" }, { 10, 0, 19044, 0, 1, "Windows 10 21H2" },
        { 10, 0, 20348, 0, 3, "Server 2022" }, { 10, 0, 26100, 0, 1, "Windows 11 24H2" },
        { 10, 0, 26100, 0, 3, "Server 2025" }, { 5, 1, 2600, 3, 1, "Windows XP SP3" } };
#define NEXP (sizeof(exp) / sizeof(exp[0]))
    typedef PVOID (WINAPI *pfnFunc)(DWORD, LPCSTR, LPCSTR);
    typedef DWORD (WINAPI *pfnCount)(void);
    char path[MAX_PATH], *bs;
    HMODULE kv;
    pfnFunc fn; pfnCount cnt;
    DWORD i;
    LOG("[version profiles]\n");
    GetModuleFileNameA(NULL, path, MAX_PATH);
    if ((bs = strrchr(path, '\\'))) bs[1] = 0; else path[0] = 0;
    strcat(path, "kexver.dll");
    kv = LoadLibraryA(path);
    CHECK(kv != NULL, "load %s", path);
    if (!kv) return;
    fn = (pfnFunc)GetProcAddress(kv, "KexVerProfileFunc");
    cnt = (pfnCount)GetProcAddress(kv, "KexVerProfileCount");
    CHECK(fn && cnt && cnt() == NEXP, "kexver has %u profiles", (unsigned)NEXP);
    if (!fn || !cnt) return;
    for (i = 0; i < NEXP; i++) {
        DWORD (WINAPI *gv)(void) = (DWORD (WINAPI *)(void))fn(i, "KERNEL32.DLL", "GetVersion");
        BOOL (WINAPI *gvw)(LPOSVERSIONINFOEXW) = (BOOL (WINAPI *)(LPOSVERSIONINFOEXW))fn(i, "KERNEL32.DLL", "GetVersionExW");
        BOOL (WINAPI *gva)(LPOSVERSIONINFOA) = (BOOL (WINAPI *)(LPOSVERSIONINFOA))fn(i, "KERNEL32.DLL", "GetVersionExA");
        BOOL (WINAPI *vvi)(LPOSVERSIONINFOEXW, DWORD, ULONGLONG) =
            (BOOL (WINAPI *)(LPOSVERSIONINFOEXW, DWORD, ULONGLONG))fn(i, "KERNEL32.DLL", "VerifyVersionInfoW");
        LONG (WINAPI *rgv)(LPOSVERSIONINFOEXW) = (LONG (WINAPI *)(LPOSVERSIONINFOEXW))fn(i, "NTDLL.DLL", "RtlGetVersion");
        VOID (WINAPI *rnv)(PDWORD, PDWORD, PDWORD) = (VOID (WINAPI *)(PDWORD, PDWORD, PDWORD))fn(i, "NTDLL.DLL", "RtlGetNtVersionNumbers");
        OSVERSIONINFOEXW w; OSVERSIONINFOA a; OSVERSIONINFOEXW q;
        DWORD v, M = 0, m = 0, b = 0;
        BOOL is7sp1, is8, is81, is10, isserver, is11;
        ULONGLONG mask;
        if (!gv || !gvw || !gva || !vvi || !rgv || !rnv) { CHECK(0, "profile %lu: missing functions", i); continue; }
        memset(&w, 0, sizeof(w)); w.dwOSVersionInfoSize = sizeof(w);
        a.dwOSVersionInfoSize = sizeof(a);
        v = gv();
        CHECK(gvw(&w) && w.dwMajorVersion == exp[i].maj && w.dwMinorVersion == exp[i].min && w.dwBuildNumber == exp[i].build
              && w.dwPlatformId == 2 && w.wProductType == exp[i].type, "%s: GetVersionExW", exp[i].name);
        CHECK(gva(&a) && a.dwMajorVersion == exp[i].maj && a.dwBuildNumber == exp[i].build, "%s: GetVersionExA", exp[i].name);
        CHECK(v == ((exp[i].build << 16) | (exp[i].min << 8) | exp[i].maj), "%s: GetVersion %08lx", exp[i].name, v);
        memset(&w, 0, sizeof(w)); w.dwOSVersionInfoSize = sizeof(w);
        CHECK(rgv(&w) == 0 && w.dwMajorVersion == exp[i].maj && w.dwBuildNumber == exp[i].build, "%s: RtlGetVersion", exp[i].name);
        rnv(&M, &m, &b);
        CHECK(M == exp[i].maj && m == exp[i].min && b == (exp[i].build | 0xF0000000UL), "%s: RtlGetNtVersionNumbers", exp[i].name);
#define ISVER(maj_, min_, sp_) (memset(&q, 0, sizeof(q)), q.dwOSVersionInfoSize = sizeof(q), q.dwMajorVersion = maj_, \
        q.dwMinorVersion = min_, q.wServicePackMajor = sp_, \
        mask = vscm(vscm(vscm(0, VER_MAJORVERSION, VER_GREATER_EQUAL), VER_MINORVERSION, VER_GREATER_EQUAL), VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL), \
        vvi(&q, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, mask))
        is7sp1 = ISVER(6, 1, 1); is8 = ISVER(6, 2, 0); is81 = ISVER(6, 3, 0); is10 = ISVER(10, 0, 0);
        memset(&q, 0, sizeof(q)); q.dwOSVersionInfoSize = sizeof(q); q.wProductType = VER_NT_WORKSTATION;
        isserver = !vvi(&q, VER_PRODUCT_TYPE, vscm(0, VER_PRODUCT_TYPE, VER_EQUAL));
        memset(&q, 0, sizeof(q)); q.dwOSVersionInfoSize = sizeof(q); q.dwBuildNumber = 22000;
        is11 = vvi(&q, VER_BUILDNUMBER, vscm(0, VER_BUILDNUMBER, VER_GREATER_EQUAL));
        {
#define VGE(a, b) (exp[i].maj > (a) || (exp[i].maj == (a) && exp[i].min >= (b)))
            BOOL e7 = VGE(6, 1), e8 = VGE(6, 2), e81 = VGE(6, 3), e10 = VGE(10, 0), e11 = exp[i].build >= 22000;
            CHECK(is7sp1 == e7 && is8 == e8 && is81 == e81 && is10 == e10 && isserver == (exp[i].type == 3) && is11 == e11,
                  "%s: IsWindows7SP1/8/8.1/10/Server/build>=22000 = %d%d%d%d%d%d", exp[i].name, is7sp1, is8, is81, is10, isserver, is11);
            if (!e11) CHECK(GetLastError() == ERROR_OLD_WIN_VERSION, "%s: failed check sets ERROR_OLD_WIN_VERSION", exp[i].name);
        }
    }
}


/* build 39: Core Audio (KEXAUDIO.DLL): enumerator -> default render endpoint -> IAudioClient in shared, event-driven
 * mode -> 0.6 s of a 440 Hz tone through IAudioRenderClient, play position from IAudioClock. Audible. */
#define COBJMACROS
#include <mmdeviceapi.h>
#include <audioclient.h>
static const GUID kt_CLSID_MMDE = {0xBCDE0395,0xE52F,0x467C,{0x8E,0x3D,0xC4,0x57,0x92,0x91,0x69,0x2E}};
static const GUID kt_IID_MMDE   = {0xA95664D2,0x9614,0x4F35,{0xA7,0x46,0xDE,0x8D,0xB6,0x36,0x17,0xE6}};
static const GUID kt_IID_AC     = {0x1CB9AD4C,0xDBFA,0x4C32,{0xB1,0x78,0xC2,0xF5,0x68,0xA7,0x03,0xB2}};
static const GUID kt_IID_ARC    = {0xF294ACFC,0x3146,0x4483,{0xA7,0xBF,0xAD,0xDC,0xA7,0xC2,0x60,0xE2}};
static const GUID kt_IID_ACK    = {0xCD63314F,0x3FBA,0x4A1B,{0x81,0x2C,0xEF,0x96,0x35,0x87,0x28,0xE7}};
static void test_coreaudio(void)
{
    IMMDeviceEnumerator *en = NULL; IMMDevice *dev = NULL; IAudioClient *cl = NULL; IAudioRenderClient *rc = NULL;
    IAudioClock *ck = NULL; WAVEFORMATEX *mix = NULL; HRESULT hr; HANDLE ev = NULL; LPWSTR id = NULL;
    REFERENCE_TIME defp = 0, minp = 0; UINT32 buf = 0, pad = 0, written = 0, goal; UINT64 freq = 0, pos = 0, qpc = 0;
    double ph = 0; int started = 0, k;
    LOG("[Core Audio]\n");
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    hr = CoCreateInstance(&kt_CLSID_MMDE, NULL, CLSCTX_INPROC_SERVER, &kt_IID_MMDE, (void **)&en);
    CHECK(SUCCEEDED(hr) && en, "CoCreateInstance(MMDeviceEnumerator) = %08lx (KEXAUDIO.DLL registered by KEXSETUP?)", hr);
    if (!en) return;
    hr = IMMDeviceEnumerator_GetDefaultAudioEndpoint(en, eRender, eConsole, &dev);
    CHECK(SUCCEEDED(hr) && dev, "default render endpoint: %08lx", hr);
    if (!dev) goto out;
    if (SUCCEEDED(IMMDevice_GetId(dev, &id)) && id) { char a[200]; WideCharToMultiByte(CP_ACP, 0, id, -1, a, 200, NULL, NULL); LOG("    endpoint id %s\n", a); CoTaskMemFree(id); }
    hr = IMMDevice_Activate(dev, &kt_IID_AC, CLSCTX_INPROC_SERVER, NULL, (void **)&cl);
    CHECK(SUCCEEDED(hr) && cl, "IMMDevice::Activate(IAudioClient) = %08lx", hr);
    if (!cl) goto out;
    hr = IAudioClient_GetMixFormat(cl, &mix);
    CHECK(SUCCEEDED(hr) && mix, "GetMixFormat = %08lx", hr);
    if (!mix) goto out;
    IAudioClient_GetDevicePeriod(cl, &defp, &minp);
    LOG("    mix format: %lu Hz, %u channels, %u bits, tag %04x; device period %lu us\n", mix->nSamplesPerSec, mix->nChannels,
        mix->wBitsPerSample, mix->wFormatTag, (DWORD)(defp / 10));
    hr = IAudioClient_Initialize(cl, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_EVENTCALLBACK, 0, 0, mix, NULL);
    CHECK(SUCCEEDED(hr), "IAudioClient::Initialize(shared, event) = %08lx", hr);
    if (FAILED(hr)) goto out;
    ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    CHECK(SUCCEEDED(IAudioClient_SetEventHandle(cl, ev)), "SetEventHandle");
    IAudioClient_GetBufferSize(cl, &buf);
    hr = IAudioClient_GetService(cl, &kt_IID_ARC, (void **)&rc);
    CHECK(SUCCEEDED(hr) && rc, "GetService(IAudioRenderClient) = %08lx", hr);
    hr = IAudioClient_GetService(cl, &kt_IID_ACK, (void **)&ck);
    CHECK(SUCCEEDED(hr) && ck, "GetService(IAudioClock) = %08lx", hr);
    if (!rc || !ck) goto out;
    IAudioClock_GetFrequency(ck, &freq);
    goal = mix->nSamplesPerSec * 6 / 10;                          /* 0.6 s */
    for (k = 0; k < 400 && written < goal; k++) {
        BYTE *d = NULL; UINT32 n, i, c;
        if (started) WaitForSingleObject(ev, 200);
        IAudioClient_GetCurrentPadding(cl, &pad);
        n = buf - pad; if (n > goal - written) n = goal - written;
        if (!n) continue;
        if (FAILED(IAudioRenderClient_GetBuffer(rc, n, &d)) || !d) break;
        for (i = 0; i < n; i++) {
            float v = (float)(ph < 0.5 ? 0.8 * ph - 0.2 : 0.6 - 0.8 * ph);   /* 440 Hz triangle (no libm: its sin uses SSE) */
            ph += 440.0 / mix->nSamplesPerSec; if (ph >= 1.0) ph -= 1.0;
            for (c = 0; c < mix->nChannels; c++) ((float *)d)[i * mix->nChannels + c] = v;
        }
        IAudioRenderClient_ReleaseBuffer(rc, n, 0);
        written += n;
        if (!started) { hr = IAudioClient_Start(cl); CHECK(SUCCEEDED(hr), "IAudioClient::Start = %08lx", hr); started = 1; }
    }
    for (k = 0; k < 50; k++) { IAudioClient_GetCurrentPadding(cl, &pad); if (!pad) break; Sleep(20); }
    Sleep(250);
    IAudioClock_GetPosition(ck, &pos, &qpc);
    LOG("    played %lu of %lu frames written (clock frequency %lu, buffer %lu frames) - you should have heard a short beep\n",
        (DWORD)pos, (DWORD)written, (DWORD)freq, (DWORD)buf);
    CHECK(written >= goal && pos >= goal / 2, "the tone was played (position %lu of %lu frames)", (DWORD)pos, (DWORD)written);
    IAudioClient_Stop(cl);
    CHECK(SUCCEEDED(IAudioClient_Reset(cl)), "IAudioClient::Reset");
    IAudioClient_GetCurrentPadding(cl, &pad);
    CHECK(pad == 0, "padding 0 after Reset (%lu)", (DWORD)pad);
out:
    if (ck) IAudioClock_Release(ck);
    if (rc) IAudioRenderClient_Release(rc);
    if (cl) IAudioClient_Release(cl);
    if (mix) CoTaskMemFree(mix);
    if (dev) IMMDevice_Release(dev);
    if (en) IMMDeviceEnumerator_Release(en);
    if (ev) CloseHandle(ev);
}


/* build 128: microphone (capture endpoint over waveIn), "what is playing" loopback (render endpoint + LOOPBACK, and
 * process loopback through MMDEVAPI.DLL #17 ActivateAudioInterfaceAsync), endpoint and stream volume interfaces. */
#include <endpointvolume.h>
static const GUID kt_IID_ACC  = {0xC8ADBD64,0xE71E,0x48A0,{0xA4,0xDE,0x18,0x5C,0x39,0x5C,0xD3,0x17}};
static const GUID kt_IID_SAV  = {0x87CE5498,0x68D6,0x44E5,{0x92,0x15,0x6D,0xA4,0x7E,0xF8,0x83,0xD8}};
static const GUID kt_IID_AEV  = {0x5CDF2C82,0x841E,0x4546,{0x97,0x22,0x0C,0xF7,0x40,0x78,0x22,0x9A}};
static const GUID kt_IID_AAH  = {0x41D949AB,0x9862,0x444A,{0x80,0xF6,0xC2,0x61,0x33,0x4D,0xA5,0xEB}};
typedef struct { void **vt; volatile LONG ref; HANDLE done; HRESULT hr; IUnknown *unk; } KT_AH;
static HRESULT STDMETHODCALLTYPE ah_qi(KT_AH *t, REFIID iid, void **pv) { *pv = t; InterlockedIncrement(&t->ref); return S_OK; }
static ULONG STDMETHODCALLTYPE ah_addref(KT_AH *t) { return InterlockedIncrement(&t->ref); }
static ULONG STDMETHODCALLTYPE ah_release(KT_AH *t) { return InterlockedDecrement(&t->ref); }
typedef struct { void **vt; } KT_OP;
static HRESULT STDMETHODCALLTYPE ah_done(KT_AH *t, KT_OP *op)
{
    typedef HRESULT (STDMETHODCALLTYPE *T_GR)(KT_OP *, HRESULT *, IUnknown **);
    ((T_GR)op->vt[3])(op, &t->hr, &t->unk);
    SetEvent(t->done);
    return S_OK;
}
static void *kt_ah_vt[] = { (void *)ah_qi, (void *)ah_addref, (void *)ah_release, (void *)ah_done };
/* level of n float samples */
static double kt_rms(const float *x, UINT32 n) { double s = 0; UINT32 i; for (i = 0; i < n; i++) s += (double)x[i] * x[i]; return n ? s / n : 0; }
/* play a tone on the render endpoint for ms while reading cap (a loopback client, polled); returns mean square of what
 * came back after the first 300 ms, and the frames read */
static double kt_tone_and_read(IMMDevice *rdev, IAudioClient *cap, int ms, DWORD *got)
{
    IAudioClient *rc = NULL; IAudioRenderClient *rr = NULL; IAudioCaptureClient *cc = NULL; WAVEFORMATEX *mix = NULL;
    UINT32 buf = 0, pad, i, c; double ph = 0, sum = 0; UINT32 nsum = 0; DWORD t0; HRESULT hr;
    *got = 0;
    if (FAILED(IMMDevice_Activate(rdev, &kt_IID_AC, CLSCTX_INPROC_SERVER, NULL, (void **)&rc)) || !rc) return -1;
    if (FAILED(IAudioClient_GetMixFormat(rc, &mix)) || FAILED(IAudioClient_Initialize(rc, AUDCLNT_SHAREMODE_SHARED, 0, 2000000, 0, mix, NULL)) ||
        FAILED(IAudioClient_GetService(rc, &kt_IID_ARC, (void **)&rr)) || FAILED(IAudioClient_GetService(cap, &kt_IID_ACC, (void **)&cc))) { sum = -2; goto out; }
    IAudioClient_GetBufferSize(rc, &buf);
    IAudioClient_Start(rc); hr = IAudioClient_Start(cap);
    CHECK(SUCCEEDED(hr), "loopback IAudioClient::Start = %08lx", hr);
    t0 = GetTickCount();
    while (GetTickCount() - t0 < (DWORD)ms) {
        BYTE *d = NULL; UINT32 n, fr = 0; DWORD fl = 0;
        IAudioClient_GetCurrentPadding(rc, &pad);
        n = buf - pad;
        if (n && SUCCEEDED(IAudioRenderClient_GetBuffer(rr, n, &d)) && d) {
            for (i = 0; i < n; i++) {
                float v = (float)(ph < 0.5 ? 0.8 * ph - 0.2 : 0.6 - 0.8 * ph);
                ph += 440.0 / mix->nSamplesPerSec; if (ph >= 1.0) ph -= 1.0;
                for (c = 0; c < mix->nChannels; c++) ((float *)d)[i * mix->nChannels + c] = v;
            }
            IAudioRenderClient_ReleaseBuffer(rr, n, 0);
        }
        while (IAudioCaptureClient_GetNextPacketSize(cc, &fr) == S_OK && fr) {
            if (IAudioCaptureClient_GetBuffer(cc, &d, &fr, &fl, NULL, NULL) != S_OK) break;
            if (GetTickCount() - t0 > 300) { sum += kt_rms((float *)d, fr * 2) * fr; nsum += fr; }
            *got += fr;
            IAudioCaptureClient_ReleaseBuffer(cc, fr);
        }
        Sleep(10);
    }
    IAudioClient_Stop(cap); IAudioClient_Stop(rc);
    sum = nsum ? sum / nsum : 0;
out:
    if (cc) IAudioCaptureClient_Release(cc);
    if (rr) IAudioRenderClient_Release(rr);
    if (rc) IAudioClient_Release(rc);
    if (mix) CoTaskMemFree(mix);
    return sum;
}
/* build 128: GetAdaptersAddresses through kexnt (was ERROR_NO_DATA: WebRTC had no network for ICE candidates) */
/* build 131: NT loader / memory / C-library names in NTDLL (ntldr_ext.c, ntcrt_ext.c) and PSAPI (psapi_ng.c) - what
 * Supermium 150's XP wrappers import or look up. Called through kexnt's exports and through GetProcAddress on the
 * system DLLs (the KernelEx resolver path a program takes). */
/* build 131: VirtualQuery reports a loaded module's pages as MEM_IMAGE (VCRUNTIME140 _except_handler3 needs it) */
static void test_vq_image(void)
{
    typedef SIZE_T (WINAPI *T_VQ)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
    T_VQ VQ = (T_VQ)(void *)GetProcAddress(kx, "VirtualQuery");
    MEMORY_BASIC_INFORMATION m; int local = 0; void *hp = HeapAlloc(GetProcessHeap(), 0, 64);
    static const char ro[] = "read-only data in this image";
    if (!VQ) { CHECK(0, "kexnt exports VirtualQuery"); return; }
    LOG("[VirtualQuery: MEM_IMAGE for module pages]\n");
    CHECK(VQ((void *)test_vq_image, &m, sizeof(m)) && m.Type == MEM_IMAGE, "code of this EXE: Type %08lx (MEM_IMAGE 01000000)", (unsigned long)m.Type);
    CHECK(VQ(ro, &m, sizeof(m)) && m.Type == MEM_IMAGE, "read-only data of this EXE: Type %08lx", (unsigned long)m.Type);
    CHECK(VQ((void *)GetModuleHandleA("KERNEL32.DLL"), &m, sizeof(m)) && m.Type == MEM_IMAGE, "KERNEL32 header: Type %08lx", (unsigned long)m.Type);
    CHECK(VQ(&local, &m, sizeof(m)) && m.Type != MEM_IMAGE, "stack: Type %08lx (not MEM_IMAGE)", (unsigned long)m.Type);
    CHECK(hp && VQ(hp, &m, sizeof(m)) && m.Type != MEM_IMAGE, "heap: Type %08lx (not MEM_IMAGE)", (unsigned long)m.Type);
    if (hp) HeapFree(GetProcessHeap(), 0, hp);
}

static void test_ntldr(void)
{
    typedef struct { USHORT l, m; PCHAR b; } AS; typedef struct { USHORT l, m; PWSTR b; } US;
    typedef LONG (WINAPI *T_LGPA)(HMODULE, AS *, ULONG, PVOID *);
    typedef LONG (WINAPI *T_LLD)(PWSTR, PULONG, US *, PVOID *);
    typedef SIZE_T (WINAPI *T_RCM)(const void *, const void *, SIZE_T);
    typedef ULONGLONG (WINAPI *T_VSCM)(ULONGLONG, DWORD, BYTE);
    typedef LONG (WINAPI *T_NAVM)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    typedef PVOID (WINAPI *T_PC2FH)(PVOID, PVOID *);
    typedef wchar_t *(__cdecl *T_WSTR)(const wchar_t *, const wchar_t *);
    typedef BOOL (WINAPI *T_GMI)(HANDLE, HMODULE, LPVOID, DWORD);
    typedef DWORD (WINAPI *T_GMFN)(HANDLE, LPVOID, LPWSTR, DWORD);
    HMODULE nt = LoadLibraryA("NTDLL.DLL"), ps;
    T_LGPA lgpa = (T_LGPA)(void *)GetProcAddress(nt, "LdrGetProcedureAddress");
    T_LLD lld = (T_LLD)(void *)GetProcAddress(nt, "LdrLoadDll");
    T_RCM rcm = (T_RCM)(void *)GetProcAddress(nt, "RtlCompareMemory");
    T_VSCM vscm = (T_VSCM)(void *)GetProcAddress(nt, "VerSetConditionMask");
    T_NAVM navm = (T_NAVM)(void *)GetProcAddress(nt, "NtAllocateVirtualMemory");
    T_PC2FH pc = (T_PC2FH)(void *)GetProcAddress(nt, "RtlPcToFileHeader");
    T_WSTR wss = (T_WSTR)(void *)GetProcAddress(nt, "wcsstr");
    LOG("[NTDLL loader / C library names, PSAPI additions]\n");
    CHECK(lgpa && lld && rcm && vscm && navm && pc && wss, "NTDLL exports through KernelEx: Ldr* %p %p RtlCompareMemory %p VerSetConditionMask %p NtAllocateVirtualMemory %p RtlPcToFileHeader %p wcsstr %p",
          (void *)lgpa, (void *)lld, (void *)rcm, (void *)vscm, (void *)navm, (void *)pc, (void *)wss);
    if (lld && lgpa) {
        WCHAR k32[] = L"kernel32.dll"; US u; AS a; PVOID h = NULL, p = NULL; LONG st;
        u.b = k32; u.l = sizeof(k32) - 2; u.m = sizeof(k32);
        st = lld(NULL, NULL, &u, &h);
        CHECK(st == 0 && h == (PVOID)GetModuleHandleA("KERNEL32.DLL"), "LdrLoadDll(kernel32) -> %08lx %p", (unsigned long)st, h);
        a.b = "GetTickCount"; a.l = 12; a.m = 13;
        st = lgpa((HMODULE)h, &a, 0, &p);
        CHECK(st == 0 && p != NULL, "LdrGetProcedureAddress(GetTickCount) -> %08lx %p", (unsigned long)st, p);
        a.b = "NoSuchFunctionHere"; a.l = 18; a.m = 19; p = (PVOID)1;
        st = lgpa((HMODULE)h, &a, 0, &p);
        CHECK(st == (LONG)0xC0000139 && p == NULL, "LdrGetProcedureAddress(missing) -> %08lx (STATUS_ENTRYPOINT_NOT_FOUND)", (unsigned long)st);
        a.b = "wcsstr"; a.l = 6; a.m = 7;
        st = lgpa(nt, &a, 0, &p);
        CHECK(st == 0 && p != NULL, "LdrGetProcedureAddress(ntdll, wcsstr) -> %08lx %p", (unsigned long)st, p);
    }
    if (wss) { static const wchar_t hay[] = L"C:\\x\\obs64.exe"; CHECK(wss(hay, L"obs64") == hay + 5, "NTDLL wcsstr"); }
    if (rcm) CHECK(rcm("abcdef", "abcxef", 6) == 3, "RtlCompareMemory counts the equal leading bytes");
    if (vscm) CHECK(vscm(0, VER_MAJORVERSION, VER_GREATER_EQUAL) == ((ULONGLONG)VER_GREATER_EQUAL << 3), "VerSetConditionMask(major, >=)");
    if (navm) {
        PVOID b = NULL; SIZE_T n = 5000; LONG st = navm(GetCurrentProcess(), &b, 0, &n, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        CHECK(st == 0 && b && n == 8192, "NtAllocateVirtualMemory 5000 bytes -> %08lx %p %lu", (unsigned long)st, b, (unsigned long)n);
        if (b) VirtualFree(b, 0, MEM_RELEASE);
    }
    if (pc) { PVOID base = NULL; PVOID r = pc((PVOID)test_ntldr, &base); CHECK(r == GetModuleHandleA(NULL) && base == r, "RtlPcToFileHeader(own code) = exe base"); }
    ps = LoadLibraryA("PSAPI.DLL");
    {   T_GMI gmi = ps ? (T_GMI)(void *)GetProcAddress(ps, "GetModuleInformation") : NULL;
        T_GMFN gmf = ps ? (T_GMFN)(void *)GetProcAddress(ps, "GetMappedFileNameW") : NULL;
        struct { LPVOID base; DWORD size; LPVOID entry; } mi = { 0, 0, 0 }; WCHAR w[MAX_PATH]; DWORD n;
        CHECK(gmi && gmf, "PSAPI.DLL GetModuleInformation %p GetMappedFileNameW %p (KernelEx-NG psapi)", (void *)gmi, (void *)gmf);
        if (gmi) CHECK(gmi(GetCurrentProcess(), GetModuleHandleA(NULL), &mi, sizeof(mi)) && mi.base == GetModuleHandleA(NULL) && mi.size, "GetModuleInformation(exe)");
        if (gmf) { n = gmf(GetCurrentProcess(), (LPVOID)test_ntldr, w, MAX_PATH);
                   CHECK(n > 8 && !memcmp(w, L"\\Device\\", 16), "GetMappedFileNameW(own code) = %ls", n ? w : L"(none)"); }
    }
}
/* build 131: thread-pool work and wait objects (tpwork_ext.c) - MSVCP140/CONCRT140 14.52 import them */
static volatile LONG g_tpw_runs; static volatile DWORD g_tpw_result = 0xFFFF;
static VOID CALLBACK tpw_cb(PVOID inst, PVOID ctx, PVOID w) { (void)inst; (void)w; InterlockedIncrement(&g_tpw_runs); InterlockedExchangeAdd((LONG *)ctx, 1); }
static VOID CALLBACK tpwait_cb(PVOID inst, PVOID ctx, PVOID w, DWORD r) { (void)inst; (void)ctx; (void)w; g_tpw_result = r; }
static void test_tpwork(void)
{
    typedef PVOID (WINAPI *T_CW)(PVOID, PVOID, PVOID); typedef VOID (WINAPI *T_SW)(PVOID); typedef VOID (WINAPI *T_WW)(PVOID, BOOL);
    typedef VOID (WINAPI *T_STW)(PVOID, HANDLE, const FILETIME *);
    T_CW cw = (T_CW)(void *)GetProcAddress(kx, "CreateThreadpoolWork"); T_SW sw = (T_SW)(void *)GetProcAddress(kx, "SubmitThreadpoolWork");
    T_WW ww = (T_WW)(void *)GetProcAddress(kx, "WaitForThreadpoolWorkCallbacks"); T_SW cl = (T_SW)(void *)GetProcAddress(kx, "CloseThreadpoolWork");
    T_CW cwt = (T_CW)(void *)GetProcAddress(kx, "CreateThreadpoolWait"); T_STW stw = (T_STW)(void *)GetProcAddress(kx, "SetThreadpoolWait");
    T_WW wwt = (T_WW)(void *)GetProcAddress(kx, "WaitForThreadpoolWaitCallbacks"); T_SW clt = (T_SW)(void *)GetProcAddress(kx, "CloseThreadpoolWait");
    LONG sum = 0; int i; PVOID w;
    LOG("[thread-pool work and wait objects]\n");
    if (!cw || !sw || !ww || !cl || !cwt || !stw || !wwt || !clt) { CHECK(0, "kexnt exports the thread-pool work/wait functions"); return; }
    w = cw((PVOID)tpw_cb, (PVOID)&sum, NULL);
    CHECK(w != NULL, "CreateThreadpoolWork");
    if (!w) return;
    for (i = 0; i < 10; i++) sw(w);
    ww(w, FALSE);
    CHECK(sum == 10, "10 submissions -> 10 callbacks before WaitForThreadpoolWorkCallbacks returns (%ld)", sum);
    cl(w);
    {   HANDLE e = CreateEventA(NULL, TRUE, FALSE, NULL); PVOID t = cwt((PVOID)tpwait_cb, NULL, NULL); FILETIME ft; LONGLONG rel = -2000000;  /* 200 ms */
        CHECK(t != NULL, "CreateThreadpoolWait");
        if (t) {
            stw(t, e, NULL); SetEvent(e); Sleep(300); wwt(t, FALSE);
            CHECK(g_tpw_result == WAIT_OBJECT_0, "wait callback on a signalled event: WAIT_OBJECT_0 (%lu)", g_tpw_result);
            ResetEvent(e); g_tpw_result = 0xFFFF;
            ft.dwLowDateTime = (DWORD)rel; ft.dwHighDateTime = (DWORD)(rel >> 32);
            stw(t, e, &ft); Sleep(800); wwt(t, FALSE);
            CHECK(g_tpw_result == WAIT_TIMEOUT, "wait callback after its timeout: WAIT_TIMEOUT (%lu)", g_tpw_result);
            clt(t);
        }
        CloseHandle(e);
    }
}
static void test_adapters(void)
{
    typedef ULONG (WINAPI *T_GAA)(ULONG, ULONG, PVOID, PVOID, PULONG);
    T_GAA gaa = (T_GAA)GetProcAddress(kx, "GetAdaptersAddresses"); ULONG sz = 0, r; BYTE *b; int n = 0;
    LOG("[network adapters]\n");
    if (!gaa) { CHECK(0, "kexnt GetAdaptersAddresses export"); return; }
    r = gaa(0 /* AF_UNSPEC */, 0x10 /* INCLUDE_PREFIX */ | 0x80 /* INCLUDE_GATEWAYS */, NULL, NULL, &sz);
    CHECK(r == ERROR_BUFFER_OVERFLOW && sz > 0, "GetAdaptersAddresses size query: %lu, %lu bytes", r, sz);
    if (r != ERROR_BUFFER_OVERFLOW || !(b = (BYTE *)HeapAlloc(GetProcessHeap(), 0, sz))) return;
    r = gaa(0, 0x90, NULL, b, &sz);
    CHECK(r == 0, "GetAdaptersAddresses = %lu", r);
    if (!r) {
        /* walk with the Vista layout offsets: Next +8, AdapterName +12, FirstUnicast +16, FirstDns +28, FriendlyName +40,
         * IfType +64, OperStatus +68, FirstGateway +164 */
        BYTE *a;
        for (a = b; a; a = *(BYTE **)(a + 8)) {
            BYTE *u = *(BYTE **)(a + 16); char ip[40] = "-", fr[80] = "";
            WideCharToMultiByte(CP_ACP, 0, *(WCHAR **)(a + 40), -1, fr, sizeof(fr), NULL, NULL);
            if (u) { struct { short fam; unsigned short port; BYTE a[4]; } *sa = *(void **)(u + 12);
                     wsprintfA(ip, "%u.%u.%u.%u/%u", sa->a[0], sa->a[1], sa->a[2], sa->a[3], u[44]); }
            LOG("    adapter %d: \"%s\" %s, type %lu, status %lu, gateway %s, DNS %s\n", n, fr, ip, *(DWORD *)(a + 64), *(DWORD *)(a + 68),
                *(void **)(a + 164) ? "yes" : "no", *(void **)(a + 28) ? "yes" : "no");
            CHECK(u && *(DWORD *)(a + 68) == 1, "adapter %d has an IPv4 address and is up", n);
            n++;
        }
        CHECK(n >= 1, "at least one network adapter (%d)", n);
    }
    HeapFree(GetProcessHeap(), 0, b);
}
static void test_capture(void)
{
    IMMDeviceEnumerator *en = NULL; IMMDevice *dev = NULL, *rdev = NULL; IAudioClient *cl = NULL; IAudioCaptureClient *cc = NULL;
    ISimpleAudioVolume *sv = NULL; IAudioEndpointVolume *epv = NULL; HRESULT hr; HANDLE ev = NULL; WAVEFORMATEX *mix = NULL;
    WAVEFORMATEX f; DWORD frames = 0, packets = 0, got; DWORD t0; double ms;
    LOG("[microphone and loopback]\n");
    hr = CoCreateInstance(&kt_CLSID_MMDE, NULL, CLSCTX_INPROC_SERVER, &kt_IID_MMDE, (void **)&en);
    if (!en) { CHECK(0, "MMDeviceEnumerator %08lx", hr); return; }
    hr = IMMDeviceEnumerator_GetDefaultAudioEndpoint(en, eCapture, eCommunications, &dev);
    {   typedef UINT (WINAPI *T_WIN)(void); T_WIN wn = (T_WIN)GetProcAddress(LoadLibraryA("WINMM.DLL"), "waveInGetNumDevs");
        if (!wn || wn() == 0) { LOG("    no waveIn device - capture part skipped\n"); goto loop; } }
    CHECK(SUCCEEDED(hr) && dev, "default capture endpoint: %08lx", hr);
    if (!dev) goto loop;
    hr = IMMDevice_Activate(dev, &kt_IID_AEV, CLSCTX_ALL, NULL, (void **)&epv);
    CHECK(SUCCEEDED(hr) && epv, "capture endpoint: IAudioEndpointVolume %08lx", hr);
    hr = IMMDevice_Activate(dev, &kt_IID_AC, CLSCTX_INPROC_SERVER, NULL, (void **)&cl);
    CHECK(SUCCEEDED(hr) && cl, "capture endpoint: IAudioClient %08lx", hr);
    if (!cl) goto loop;
    if (SUCCEEDED(IAudioClient_GetMixFormat(cl, &mix)) && mix) LOG("    capture mix format: %lu Hz, %u channels\n", mix->nSamplesPerSec, mix->nChannels);
    /* what Chrome asks for a microphone: 16-bit; here 16 kHz mono so the converter is used */
    f.wFormatTag = WAVE_FORMAT_PCM; f.nChannels = 1; f.nSamplesPerSec = 16000; f.wBitsPerSample = 16; f.nBlockAlign = 2; f.nAvgBytesPerSec = 32000; f.cbSize = 0;
    hr = IAudioClient_Initialize(cl, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_EVENTCALLBACK | AUDCLNT_STREAMFLAGS_NOPERSIST, 1000000, 0, &f, NULL);
    CHECK(SUCCEEDED(hr), "capture Initialize(16 kHz mono 16-bit, event) = %08lx", hr);
    if (FAILED(hr)) goto loop;
    ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    CHECK(SUCCEEDED(IAudioClient_SetEventHandle(cl, ev)), "capture SetEventHandle");
    CHECK(SUCCEEDED(IAudioClient_GetService(cl, &kt_IID_ACC, (void **)&cc)) && cc, "GetService(IAudioCaptureClient)");
    CHECK(SUCCEEDED(IAudioClient_GetService(cl, &kt_IID_SAV, (void **)&sv)) && sv, "GetService(ISimpleAudioVolume)");
    if (!cc) goto loop;
    hr = IAudioClient_Start(cl);
    CHECK(SUCCEEDED(hr), "capture Start = %08lx", hr);
    t0 = GetTickCount();
    while (GetTickCount() - t0 < 1500) {
        BYTE *d; UINT32 n; DWORD fl; UINT64 dp, qp;
        WaitForSingleObject(ev, 200);
        while (IAudioCaptureClient_GetBuffer(cc, &d, &n, &fl, &dp, &qp) == S_OK) { frames += n; packets++; IAudioCaptureClient_ReleaseBuffer(cc, n); }
    }
    ms = (GetTickCount() - t0);
    IAudioClient_Stop(cl);
    LOG("    captured %lu frames in %lu packets in %.0f ms (expected about %.0f)\n", frames, packets, ms, ms * 16.0);
    CHECK(frames > ms * 16.0 * 0.6 && frames < ms * 16.0 * 1.3, "microphone delivers 16 kHz (%lu frames in %.0f ms)", frames, ms);
loop:
    if (sv) { ISimpleAudioVolume_Release(sv); sv = NULL; }
    if (cc) { IAudioCaptureClient_Release(cc); cc = NULL; }
    if (cl) { IAudioClient_Release(cl); cl = NULL; }
    if (mix) { CoTaskMemFree(mix); mix = NULL; }
    /* endpoint loopback: render endpoint, LOOPBACK flag, polled */
    if (FAILED(IMMDeviceEnumerator_GetDefaultAudioEndpoint(en, eRender, eConsole, &rdev)) || !rdev) { LOG("    no render endpoint - loopback skipped\n"); goto out; }
    if (SUCCEEDED(IMMDevice_Activate(rdev, &kt_IID_AC, CLSCTX_INPROC_SERVER, NULL, (void **)&cl)) && cl && SUCCEEDED(IAudioClient_GetMixFormat(cl, &mix))) {
        double e;
        hr = IAudioClient_Initialize(cl, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK, 1000000, 0, mix, NULL);
        CHECK(SUCCEEDED(hr), "render endpoint + LOOPBACK: Initialize = %08lx", hr);
        if (SUCCEEDED(hr)) {
            e = kt_tone_and_read(rdev, cl, 1200, &got);
            LOG("    loopback while a tone plays: %lu frames, level %.4f (mean square)\n", got, e);
            CHECK(got > mix->nSamplesPerSec / 2 && e > 0.005, "loopback hears the tone this process plays (%lu frames, level %.4f)", got, e);
        }
        IAudioClient_Release(cl); cl = NULL; CoTaskMemFree(mix); mix = NULL;
    }
    {   /* process loopback through MMDEVAPI.DLL #17: this process's tree -> hears it; all but this tree -> silence */
        typedef HRESULT (WINAPI *T_AAIA)(LPCWSTR, REFIID, PROPVARIANT *, void *, void **);
        HMODULE mm = LoadLibraryA("MMDEVAPI.DLL"); T_AAIA aaia = mm ? (T_AAIA)GetProcAddress(mm, (LPCSTR)17) : NULL; int mode;
        CHECK(aaia != NULL, "MMDEVAPI.DLL ordinal 17 (ActivateAudioInterfaceAsync) present");
        for (mode = 0; aaia && mode < 2; mode++) {
            DWORD prm[3]; PROPVARIANT pv; KT_AH h; void *op = NULL; double e;
            prm[0] = 1; prm[1] = GetCurrentProcessId(); prm[2] = mode;
            memset(&pv, 0, sizeof(pv)); pv.vt = VT_BLOB; pv.blob.cbSize = 12; pv.blob.pBlobData = (BYTE *)prm;
            h.vt = kt_ah_vt; h.ref = 1; h.done = CreateEventA(NULL, TRUE, FALSE, NULL); h.hr = E_FAIL; h.unk = NULL;
            hr = aaia(L"VAD\\Process_Loopback", &kt_IID_AC, &pv, &h, &op);
            CHECK(SUCCEEDED(hr) && WaitForSingleObject(h.done, 2000) == WAIT_OBJECT_0 && SUCCEEDED(h.hr) && h.unk,
                  "process loopback (%s this process): activated %08lx / %08lx", mode ? "excluding" : "including", hr, h.hr);
            if (h.unk) {
                IAudioClient *pl = NULL; WAVEFORMATEX pf;
                h.unk->lpVtbl->QueryInterface(h.unk, &kt_IID_AC, (void **)&pl); h.unk->lpVtbl->Release(h.unk);
                pf.wFormatTag = WAVE_FORMAT_IEEE_FLOAT; pf.nChannels = 2; pf.nSamplesPerSec = 48000; pf.wBitsPerSample = 32; pf.nBlockAlign = 8; pf.nAvgBytesPerSec = 384000; pf.cbSize = 0;
                if (pl && SUCCEEDED(IAudioClient_Initialize(pl, AUDCLNT_SHAREMODE_SHARED, 0, 1000000, 0, &pf, NULL))) {
                    e = kt_tone_and_read(rdev, pl, 1200, &got);
                    LOG("    process loopback %s this process: %lu frames at 48 kHz, level %.4f\n", mode ? "excluding" : "including", got, e);
                    if (!mode) CHECK(got > 24000 && e > 0.005, "process loopback including this process hears its tone (%lu, %.4f)", got, e);
                    else CHECK(got > 24000 && e < 0.0001, "process loopback excluding this process: silence (%lu, %.6f)", got, e);
                } else CHECK(0, "process loopback Initialize(48 kHz float)");
                if (pl) IAudioClient_Release(pl);
            }
            if (op) ((IUnknown *)op)->lpVtbl->Release((IUnknown *)op);
            CloseHandle(h.done);
        }
    }
out:
    if (epv) IAudioEndpointVolume_Release(epv);
    if (rdev) IMMDevice_Release(rdev);
    if (dev) IMMDevice_Release(dev);
    if (en) IMMDeviceEnumerator_Release(en);
    if (ev) CloseHandle(ev);
}

/* build 40: OpenGL as a program sees it (SoftGPU / any ICD): pixel format, legacy context, version strings,
 * WGL extensions, a 3.x context through wglCreateContextAttribsARB (what Chromium's ANGLE "gl" backend needs),
 * and a short clear+swap loop to tell a hardware path (VMware SVGA3D) from software rendering. Information only. */
typedef const unsigned char *(WINAPI *T_GLGS)(unsigned int);
typedef HGLRC (WINAPI *T_WCC)(HDC);
typedef BOOL (WINAPI *T_WMC)(HDC, HGLRC);
typedef BOOL (WINAPI *T_WDC)(HGLRC);
typedef PROC (WINAPI *T_WGPA)(LPCSTR);
typedef const char *(WINAPI *T_WGES)(HDC);
typedef HGLRC (WINAPI *T_WCCA)(HDC, HGLRC, const int *);
typedef void (WINAPI *T_GLCC)(float, float, float, float);
typedef void (WINAPI *T_GLC)(unsigned int);
typedef void (WINAPI *T_GLF)(void);
static LRESULT CALLBACK gl_wndproc(HWND h, UINT m, WPARAM w, LPARAM l) { return DefWindowProcA(h, m, w, l); }
static void gl_info(T_GLGS gs, const char *what)
{
    const char *v = (const char *)gs(0x1F00), *r = (const char *)gs(0x1F01), *ver = (const char *)gs(0x1F02);
    LOG("    %s: vendor \"%s\", renderer \"%s\", version \"%s\"\n", what, v ? v : "?", r ? r : "?", ver ? ver : "?");
}
static void test_opengl(void)
{
    HMODULE gl = LoadLibraryA("OPENGL32.DLL");
    WNDCLASSA wc; HWND w; HDC dc; PIXELFORMATDESCRIPTOR pfd; int pf; HGLRC rc = NULL, rc3 = NULL;
    T_WCC wcc; T_WMC wmc; T_WDC wdc; T_WGPA wgpa; T_GLGS gs;
    LOG("[OpenGL]\n");
    if (!gl) { LOG("    OPENGL32.DLL not loadable (error %lu) - skipped\n", GetLastError()); return; }
    wcc = (T_WCC)(void *)GetProcAddress(gl, "wglCreateContext"); wmc = (T_WMC)(void *)GetProcAddress(gl, "wglMakeCurrent");
    wdc = (T_WDC)(void *)GetProcAddress(gl, "wglDeleteContext"); wgpa = (T_WGPA)(void *)GetProcAddress(gl, "wglGetProcAddress");
    gs = (T_GLGS)(void *)GetProcAddress(gl, "glGetString");
    if (!wcc || !wmc || !wdc || !wgpa || !gs) { LOG("    OPENGL32.DLL lacks wgl/gl entry points - skipped\n"); return; }
    memset(&wc, 0, sizeof(wc)); wc.lpfnWndProc = gl_wndproc; wc.hInstance = GetModuleHandleA(NULL); wc.lpszClassName = "KexGlTest";
    RegisterClassA(&wc);
    w = CreateWindowA("KexGlTest", "kextest OpenGL", WS_POPUP | WS_VISIBLE, 0, 0, 256, 256, NULL, NULL, wc.hInstance, NULL);
    dc = w ? GetDC(w) : NULL;
    if (!dc) { LOG("    no window/DC - skipped\n"); return; }
    memset(&pfd, 0, sizeof(pfd)); pfd.nSize = sizeof(pfd); pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER; pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 32; pfd.cDepthBits = 24; pfd.cStencilBits = 8; pfd.iLayerType = PFD_MAIN_PLANE;
    pf = ChoosePixelFormat(dc, &pfd);
    CHECK(pf > 0 && SetPixelFormat(dc, pf, &pfd), "OpenGL pixel format (ChoosePixelFormat %d, error %lu)", pf, GetLastError());
    if (pf > 0) {
        PIXELFORMATDESCRIPTOR d; DescribePixelFormat(dc, pf, sizeof(d), &d);
        LOG("    pixel format %d: color %u, depth %u, stencil %u, flags %08lx%s\n", pf, d.cColorBits, d.cDepthBits, d.cStencilBits, d.dwFlags,
            (d.dwFlags & PFD_GENERIC_FORMAT) ? " (GENERIC = Microsoft software OpenGL)" : " (ICD)");
    }
    rc = wcc(dc);
    CHECK(rc && wmc(dc, rc), "wglCreateContext + wglMakeCurrent (error %lu)", GetLastError());
    if (!rc) goto out;
    gl_info(gs, "legacy context");
    {
        T_WGES ges = (T_WGES)(void *)wgpa("wglGetExtensionsStringARB");
        const char *ex = ges ? ges(dc) : NULL, *glx = (const char *)gs(0x1F03);
        LOG("    WGL extensions: %s\n", ex ? ex : "(wglGetExtensionsStringARB missing)");
        LOG("    GL extensions: %u characters\n", glx ? (unsigned)strlen(glx) : 0);
    }
    {
        T_WCCA cca = (T_WCCA)(void *)wgpa("wglCreateContextAttribsARB");
        static const int core33[] = { 0x2091, 3, 0x2092, 3, 0x9126, 1, 0 };          /* 3.3 core */
        static const int compat32[] = { 0x2091, 3, 0x2092, 2, 0x9126, 2, 0 };        /* 3.2 compatibility */
        LOG("    wglCreateContextAttribsARB: %s\n", cca ? "present" : "MISSING (ANGLE's GL backend needs it)");
        if (cca) {
            const char *how = "3.3 core";
            rc3 = cca(dc, NULL, core33);
            if (!rc3) { how = "3.2 compatibility"; rc3 = cca(dc, NULL, compat32); }
            if (rc3 && wmc(dc, rc3)) gl_info(gs, how);
            else LOG("    no 3.x context (error %lu)\n", GetLastError());
        }
    }
    {   /* 120 frames of clear + SwapBuffers on a 256x256 window */
        T_GLCC cc = (T_GLCC)(void *)GetProcAddress(gl, "glClearColor"); T_GLC clr = (T_GLC)(void *)GetProcAddress(gl, "glClear");
        T_GLF fin = (T_GLF)(void *)GetProcAddress(gl, "glFinish");
        if (cc && clr && fin) {
            DWORD t0 = GetTickCount(), t; int i;
            for (i = 0; i < 120; i++) { cc((float)(i & 1), 0.3f, 0.6f, 1.0f); clr(0x4000); SwapBuffers(dc); }
            fin(); t = GetTickCount() - t0;
            LOG("    120 clear+swap frames (256x256): %lu ms (%lu fps)\n", t, t ? 120000 / t : 0);
        }
    }
out:
    wmc(NULL, NULL);
    if (rc3) wdc(rc3);
    if (rc) wdc(rc);
    ReleaseDC(w, dc); DestroyWindow(w);
}

/* build 41: how fast a full frame reaches the screen - the 2D path every program uses today (Chromium's software
 * compositor: a DIB section BitBlt'ed to the window, or SetDIBitsToDevice / StretchDIBits) against the OpenGL path
 * (upload the frame as a texture, draw it, SwapBuffers - what GPU compositing does). 800x600, 32 bpp. Run once with
 * VMware "Accelerate 3D graphics" off and once on to see what each costs. Information only. */
typedef void (WINAPI *T_GLGT)(int, unsigned int *);
typedef void (WINAPI *T_GLBT)(unsigned int, unsigned int);
typedef void (WINAPI *T_GLTPI)(unsigned int, unsigned int, int);
typedef void (WINAPI *T_GLTI)(unsigned int, int, int, int, int, int, unsigned int, unsigned int, const void *);
typedef void (WINAPI *T_GLTSI)(unsigned int, int, int, int, int, int, unsigned int, unsigned int, const void *);
typedef void (WINAPI *T_GLE)(unsigned int);
typedef void (WINAPI *T_GL2F)(float, float);
typedef void (WINAPI *T_GLVP)(int, int, int, int);
typedef void (WINAPI *T_GLRP)(int, int, int, int, unsigned int, unsigned int, void *);
typedef unsigned int (WINAPI *T_GLGE)(void);
#define BW 800
#define BH 600
static void pump(void) { MSG m; while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) DispatchMessageA(&m); }
static void bench_line(const char *what, int frames, DWORD ms)
{
    DWORD mbs = ms ? (DWORD)((unsigned __int64)frames * BW * BH * 4 / 1024 * 1000 / 1024 / ms) : 0;
    LOG("    %-44s %3d frames in %5lu ms = %4lu fps (%lu MB/s)\n", what, frames, ms, ms ? (DWORD)(frames * 1000UL / ms) : 0, mbs);
}
static void test_draw_speed(void)
{
    WNDCLASSA wc; HWND w; HDC dc, mdc; BITMAPINFO bi; void *bits = NULL; HBITMAP dib, old; DWORD *px, t0; int i, y;
    LOG("[drawing speed]\n");
    memset(&wc, 0, sizeof(wc)); wc.lpfnWndProc = gl_wndproc; wc.hInstance = GetModuleHandleA(NULL); wc.lpszClassName = "KexDrawTest";
    RegisterClassA(&wc);
    {
        HDC sdc = GetDC(NULL);
        LOG("    screen %dx%d, %d bits per pixel\n", GetDeviceCaps(sdc, HORZRES), GetDeviceCaps(sdc, VERTRES), GetDeviceCaps(sdc, BITSPIXEL) * GetDeviceCaps(sdc, PLANES));
        ReleaseDC(NULL, sdc);
    }
    /* --- 2D (GDI) */
    w = CreateWindowA("KexDrawTest", "kextest 2D", WS_POPUP | WS_VISIBLE, 0, 0, BW, BH, NULL, NULL, wc.hInstance, NULL);
    dc = w ? GetDC(w) : NULL;
    if (!dc) { LOG("    no window - skipped\n"); return; }
    pump();
    memset(&bi, 0, sizeof(bi)); bi.bmiHeader.biSize = sizeof(bi.bmiHeader); bi.bmiHeader.biWidth = BW; bi.bmiHeader.biHeight = -BH;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
    dib = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    mdc = CreateCompatibleDC(dc);
    if (!dib || !mdc || !bits) { LOG("    no DIB section - skipped\n"); goto out2d; }
    old = (HBITMAP)SelectObject(mdc, dib);
    px = (DWORD *)bits;
    for (y = 0; y < BH; y++) for (i = 0; i < BW; i++) px[y * BW + i] = (DWORD)((i * 255 / BW) << 16 | (y * 255 / BH) << 8 | 0x40);
    t0 = GetTickCount();
    for (i = 0; i < 60; i++) { px[(i * 7 % BH) * BW] ^= 0xFFFFFF; BitBlt(dc, 0, 0, BW, BH, mdc, 0, 0, SRCCOPY); GdiFlush(); }
    bench_line("2D: DIB section -> window (BitBlt)", 60, GetTickCount() - t0);
    t0 = GetTickCount();
    for (i = 0; i < 60; i++) { px[(i * 7 % BH) * BW] ^= 0xFFFFFF; SetDIBitsToDevice(dc, 0, 0, BW, BH, 0, 0, 0, BH, bits, &bi, DIB_RGB_COLORS); GdiFlush(); }
    bench_line("2D: memory -> window (SetDIBitsToDevice)", 60, GetTickCount() - t0);
    t0 = GetTickCount();
    for (i = 0; i < 60; i++) { px[(i * 7 % BH) * BW] ^= 0xFFFFFF; StretchDIBits(dc, 0, 0, BW, BH, 0, 0, BW, BH, bits, &bi, DIB_RGB_COLORS, SRCCOPY); GdiFlush(); }
    bench_line("2D: memory -> window (StretchDIBits 1:1)", 60, GetTickCount() - t0);
    t0 = GetTickCount();
    for (i = 0; i < 60; i++) { BitBlt(mdc, 0, 0, BW, BH, dc, 0, 0, SRCCOPY); GdiFlush(); }
    bench_line("2D: window -> memory (BitBlt, read back)", 60, GetTickCount() - t0);
    SelectObject(mdc, old);
out2d:
    if (mdc) DeleteDC(mdc);
    if (dib) DeleteObject(dib);
    ReleaseDC(w, dc); DestroyWindow(w);

    /* --- OpenGL: texture upload + textured quad + SwapBuffers */
    {
        HMODULE gl = LoadLibraryA("OPENGL32.DLL");
        PIXELFORMATDESCRIPTOR pfd; int pf; HGLRC rc = NULL; unsigned int tex = 0; DWORD *buf;
        T_WCC wcc; T_WMC wmc; T_WDC wdc; T_GLGT gt; T_GLBT bt; T_GLTPI tpi; T_GLTI ti; T_GLTSI tsi; T_GLE en, beg; T_GLF end, fin;
        T_GL2F tc, vx; T_GLVP vp; T_GLRP rp; T_GLGE ge;
        if (!gl) { LOG("    OpenGL: OPENGL32.DLL not loadable - skipped\n"); return; }
        wcc = (T_WCC)(void *)GetProcAddress(gl, "wglCreateContext"); wmc = (T_WMC)(void *)GetProcAddress(gl, "wglMakeCurrent");
        wdc = (T_WDC)(void *)GetProcAddress(gl, "wglDeleteContext");
        gt = (T_GLGT)(void *)GetProcAddress(gl, "glGenTextures"); bt = (T_GLBT)(void *)GetProcAddress(gl, "glBindTexture");
        tpi = (T_GLTPI)(void *)GetProcAddress(gl, "glTexParameteri"); ti = (T_GLTI)(void *)GetProcAddress(gl, "glTexImage2D");
        tsi = (T_GLTSI)(void *)GetProcAddress(gl, "glTexSubImage2D"); en = (T_GLE)(void *)GetProcAddress(gl, "glEnable");
        beg = (T_GLE)(void *)GetProcAddress(gl, "glBegin"); end = (T_GLF)(void *)GetProcAddress(gl, "glEnd");
        fin = (T_GLF)(void *)GetProcAddress(gl, "glFinish"); tc = (T_GL2F)(void *)GetProcAddress(gl, "glTexCoord2f");
        vx = (T_GL2F)(void *)GetProcAddress(gl, "glVertex2f"); vp = (T_GLVP)(void *)GetProcAddress(gl, "glViewport");
        rp = (T_GLRP)(void *)GetProcAddress(gl, "glReadPixels"); ge = (T_GLGE)(void *)GetProcAddress(gl, "glGetError");
        if (!wcc || !wmc || !wdc || !gt || !bt || !tpi || !ti || !tsi || !en || !beg || !end || !fin || !tc || !vx || !vp || !rp || !ge) {
            LOG("    OpenGL: entry points missing - skipped\n"); return;
        }
        if (!(buf = (DWORD *)malloc(BW * BH * 4))) return;
        for (y = 0; y < BH; y++) for (i = 0; i < BW; i++) buf[y * BW + i] = 0xFF000000u | (DWORD)((i * 255 / BW) << 16 | (y * 255 / BH) << 8 | 0x40);
        w = CreateWindowA("KexDrawTest", "kextest GL", WS_POPUP | WS_VISIBLE, 0, 0, BW, BH, NULL, NULL, wc.hInstance, NULL);
        dc = w ? GetDC(w) : NULL;
        if (!dc) { free(buf); return; }
        pump();
        memset(&pfd, 0, sizeof(pfd)); pfd.nSize = sizeof(pfd); pfd.nVersion = 1;
        pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER; pfd.iPixelType = PFD_TYPE_RGBA; pfd.cColorBits = 32;
        pf = ChoosePixelFormat(dc, &pfd);
        if (pf > 0 && SetPixelFormat(dc, pf, &pfd) && (rc = wcc(dc)) != NULL && wmc(dc, rc)) {
            unsigned char c[4] = {0, 0, 0, 0}; unsigned int err;
            vp(0, 0, BW, BH);
            gt(1, &tex); bt(0x0DE1, tex);
            tpi(0x0DE1, 0x2801, 0x2600); tpi(0x0DE1, 0x2800, 0x2600);       /* MIN/MAG filter NEAREST */
            ti(0x0DE1, 0, 0x8058 /* RGBA8 */, BW, BH, 0, 0x80E1 /* BGRA */, 0x1401, buf);
            en(0x0DE1);
#define QUAD() do { beg(7 /* GL_QUADS */); tc(0, 1); vx(-1, -1); tc(1, 1); vx(1, -1); tc(1, 0); vx(1, 1); tc(0, 0); vx(-1, 1); end(); } while (0)
            QUAD(); fin();
            rp(BW / 2, BH / 2, 1, 1, 0x80E1, 0x1401, c);
            err = ge();
            LOG("    OpenGL: frame drawn as a texture, centre pixel %02x%02x%02x (expected about %02x%02x%02x), GL error %u\n",
                c[2], c[1], c[0], 0x7f, 0x7f, 0x40, err);
            CHECK(err == 0, "OpenGL texture upload + draw without a GL error (%u)", err);
            t0 = GetTickCount();
            for (i = 0; i < 60; i++) { QUAD(); SwapBuffers(dc); }
            fin();
            bench_line("GL: draw the same texture + SwapBuffers", 60, GetTickCount() - t0);
            t0 = GetTickCount();
            for (i = 0; i < 60; i++) { buf[(i * 7 % BH) * BW] ^= 0xFFFFFF; tsi(0x0DE1, 0, 0, 0, BW, BH, 0x80E1, 0x1401, buf); QUAD(); SwapBuffers(dc); }
            fin();
            bench_line("GL: upload whole frame + draw + SwapBuffers", 60, GetTickCount() - t0);
            t0 = GetTickCount();
            for (i = 0; i < 60; i++) { buf[(i * 7 % BH) * BW] ^= 0xFFFFFF; tsi(0x0DE1, 0, 0, i * 7 % BH, BW, 1, 0x80E1, 0x1401, buf + (i * 7 % BH) * BW); QUAD(); SwapBuffers(dc); }
            fin();
            bench_line("GL: upload 1 row + draw + SwapBuffers", 60, GetTickCount() - t0);
            t0 = GetTickCount();
            for (i = 0; i < 20; i++) rp(0, 0, BW, BH, 0x80E1, 0x1401, buf);
            bench_line("GL: read the frame back (glReadPixels)", 20, GetTickCount() - t0);
#undef QUAD
        } else LOG("    OpenGL: no context on the 800x600 window (error %lu) - skipped\n", GetLastError());
        wmc(NULL, NULL);
        if (rc) wdc(rc);
        ReleaseDC(w, dc); DestroyWindow(w); free(buf);
    }
}

/* build 45: a "sheet of glass" OpenGL window (DwmExtendFrameIntoClientArea all -1, as Chromium's menus with GPU
 * compositing) gets shaped from its alpha at SwapBuffers: left half transparent -> window region = right half. */
/* build 50: delete-on-close by handle (Chromium downloads/cache) and the path of a handle */
/* build 58: IFileSaveDialog / IFileOpenDialog from kexnt (Chrome's Save As), SHCreateItemFromParsingName.
 * Only the object is tested (no dialog is shown). */
/* build 59: Chromium saw "critical" memory pressure all the time (Windows 98 counts the disk cache as used) */
/* build 106: everything needed to name the owner of the big RAM blocks of the shared arena, without guessing:
 * machine/VM, display adapter and its driver, SoftGPU/vmdisp9x settings, static and loaded VxDs, running programs,
 * per block: physically contiguous or not, its first bytes, and every DWORD in the system arena (VxD memory, via
 * KEXALIAS.VXD 6) or in the shared arena that points into it - the owner keeps such a pointer. */
static DWORD g_memblk[8][2]; static int g_nbig;
#include <tlhelp32.h>
static void reg_dump(HKEY root, const char *path, int depth, const char *indent)
{
    HKEY k; DWORD i; char ind[32];
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &k) != ERROR_SUCCESS) return;
    LOG("%s[%s]\n", indent, path);
    for (i = 0; i < 64; i++) {
        char n[128]; BYTE v[260]; DWORD nl = sizeof(n), vl = sizeof(v) - 2, t;
        LONG r = RegEnumValueA(k, i, n, &nl, NULL, &t, v, &vl);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        if (t == REG_SZ || t == REG_EXPAND_SZ) { v[vl < sizeof(v) - 1 ? vl : sizeof(v) - 1] = 0; LOG("%s  %s = \"%s\"\n", indent, n[0] ? n : "(default)", (char *)v); }
        else if (vl == 4) LOG("%s  %s = %lu (0x%lx)\n", indent, n, *(DWORD *)v, *(DWORD *)v);
        else { DWORD j; LOG("%s  %s = (%lu bytes)", indent, n, vl); for (j = 0; j < vl && j < 16; j++) LOG(" %02x", v[j]); LOG("\n"); }
    }
    if (depth > 0) {
        lstrcpynA(ind, indent, 28); lstrcatA(ind, "  ");
        for (i = 0; i < 48; i++) {
            char sub[128], full[400]; DWORD sl = sizeof(sub); FILETIME ft;
            if (RegEnumKeyExA(k, i, sub, &sl, NULL, NULL, NULL, &ft) != ERROR_SUCCESS) break;
            if (lstrlenA(path) + lstrlenA(sub) + 2 >= (int)sizeof(full)) continue;
            lstrcpyA(full, path); lstrcatA(full, "\\"); lstrcatA(full, sub);
            reg_dump(root, full, depth - 1, ind);
        }
    }
    RegCloseKey(k);
}
typedef struct { DWORD ddb, ctl; char name[9]; } VXDI;
static VXDI g_vx[512]; static int g_nvx;
static const char *near_vxd(DWORD a, DWORD *dist)
{
    int i, best = -1; DWORD bd = 0xFFFFFFFF;
    for (i = 0; i < g_nvx; i++) {
        DWORD c[2]; int j; c[0] = g_vx[i].ddb; c[1] = g_vx[i].ctl;
        for (j = 0; j < 2; j++) if (c[j] && c[j] <= a && a - c[j] < bd) { bd = a - c[j]; best = i; }
    }
    *dist = bd;
    return best >= 0 && bd < (1u << 20) ? g_vx[best].name : "(none within 1 MB - VMM/heap memory)";
}
static void who_owns(DWORD total_phys)
{
    HANDLE d = CreateFileA("\\\\.\\KEXALIAS.VXD", 0, 0, NULL, 0, 0, NULL), sn;
    DWORD ver = 0, got = 0, i; int b;
    LOG("[who holds the memory]\n");
    {   unsigned int r[4] = { 0 }; char vend[13] = { 0 };
        __asm__ volatile ("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(1), "c"(0));
        if (r[2] & 0x80000000u) {
            __asm__ volatile ("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(0x40000000), "c"(0));
            memcpy(vend, &r[1], 4); memcpy(vend + 4, &r[2], 4); memcpy(vend + 8, &r[3], 4);
            LOG("    hypervisor (CPUID 40000000h): \"%s\"\n", vend);
        } else LOG("    CPUID says: no hypervisor bit\n");
    }
    LOG("    display adapter and driver (registry):\n");
    reg_dump(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\Class\\Display", 2, "      ");
    LOG("    PCI devices:\n");
    {   HKEY k; if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Enum\\PCI", 0, KEY_READ, &k) == ERROR_SUCCESS) {
            for (i = 0; i < 64; i++) {
                char sub[128], path[300], inst[128], desc[200]; DWORD sl = sizeof(sub), il = sizeof(inst), dl = sizeof(desc), t; FILETIME ft; HKEY k2, k3;
                if (RegEnumKeyExA(k, i, sub, &sl, NULL, NULL, NULL, &ft) != ERROR_SUCCESS) break;
                desc[0] = 0;
                wsprintfA(path, "Enum\\PCI\\%s", sub);
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &k2) == ERROR_SUCCESS) {
                    if (RegEnumKeyExA(k2, 0, inst, &il, NULL, NULL, NULL, &ft) == ERROR_SUCCESS && RegOpenKeyExA(k2, inst, 0, KEY_READ, &k3) == ERROR_SUCCESS) {
                        if (RegQueryValueExA(k3, "DeviceDesc", NULL, &t, (BYTE *)desc, &dl) != ERROR_SUCCESS) desc[0] = 0;
                        RegCloseKey(k3);
                    }
                    RegCloseKey(k2);
                }
                LOG("      %s  \"%s\"\n", sub, desc);
            }
            RegCloseKey(k);
        } }
    LOG("    display/3D driver settings (registry):\n");
    reg_dump(HKEY_LOCAL_MACHINE, "Software\\VMWSVGA", 2, "      ");
    reg_dump(HKEY_LOCAL_MACHINE, "Software\\vmdisp9x", 2, "      ");
    reg_dump(HKEY_LOCAL_MACHINE, "Software\\SoftGPU", 2, "      ");
    reg_dump(HKEY_LOCAL_MACHINE, "Software\\VBox", 1, "      ");
    LOG("    VxDs started from the registry (Services\\VxD, StaticVxD):\n");
    {   HKEY k; if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\VxD", 0, KEY_READ, &k) == ERROR_SUCCESS) {
            for (i = 0; i < 200; i++) {
                char sub[128], v[260]; DWORD sl = sizeof(sub), vl = sizeof(v), t; FILETIME ft; HKEY k2;
                if (RegEnumKeyExA(k, i, sub, &sl, NULL, NULL, NULL, &ft) != ERROR_SUCCESS) break;
                if (RegOpenKeyExA(k, sub, 0, KEY_READ, &k2) != ERROR_SUCCESS) continue;
                if (RegQueryValueExA(k2, "StaticVxD", NULL, &t, (BYTE *)v, &vl) == ERROR_SUCCESS) LOG("      %-12s %s\n", sub, v);
                RegCloseKey(k2);
            }
            RegCloseKey(k);
        } }
    if (d != INVALID_HANDLE_VALUE) DeviceIoControl(d, 3, NULL, 0, &ver, 4, &got, NULL);
    if (ver >= 6) {
        static DWORD buf[4 + 512 * 6];
        if (DeviceIoControl(d, 5, NULL, 0, buf, sizeof(buf), &got, NULL)) {
            DWORD n = buf[0], *o = buf + 1;
            LOG("    VxDs loaded now (%lu; DDB, control procedure, init order, device id):\n", n);
            for (i = 0; i < n && g_nvx < 512; i++, o += 6) {
                VXDI *v = &g_vx[g_nvx++];
                v->ddb = o[0]; v->ctl = o[3]; memcpy(v->name, &o[1], 8); v->name[8] = 0;
                { int j; for (j = 7; j >= 0 && (v->name[j] == ' ' || !v->name[j]); j--) v->name[j] = 0; for (j = 0; v->name[j]; j++) if (v->name[j] < 32 || v->name[j] > 126) v->name[j] = '?'; }
                LOG("      %-8s DDB %08lx  control %08lx  order %08lx  id %04lx\n", v->name, o[0], o[3], o[4], o[5]);
            }
        } else LOG("    VxD list: KEXALIAS.VXD refused (error %lu)\n", GetLastError());
    } else LOG("    VxD list / pointer search need KEXALIAS.VXD 6 (loaded: %lu) - did KEXSETUP + restart run?\n", ver);
    LOG("    programs running now:\n");
    sn = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (sn != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        if (Process32First(sn, &pe)) do { LOG("      %08lx  threads %2lu  %s\n", pe.th32ProcessID, pe.cntThreads, pe.szExeFile); pe.dwSize = sizeof(pe); } while (Process32Next(sn, &pe));
        CloseHandle(sn);
    }
    for (b = 0; b < g_nbig; b++) {
        DWORD base = g_memblk[b][0], size = g_memblk[b][1], runs = 0, prev = 0, np = 0, pg, first = 0, last = 0;
        LOG("    block %08lx (%lu MB):\n", base, size >> 20);
        if (ver >= 5) {
            for (pg = 0; pg < size >> 12; pg += 64) {
                DWORD in[2], pt[64], k, cnt = (size >> 12) - pg < 64 ? (size >> 12) - pg : 64;
                in[0] = base + (pg << 12); in[1] = cnt;
                if (!DeviceIoControl(d, 4, in, 8, pt, cnt * 4, &got, NULL)) break;
                for (k = 0; k < cnt; k++) {
                    DWORD ph = pt[k] & 0xFFFFF000UL;
                    if (!(pt[k] & 1)) { np++; prev = 0; continue; }
                    if (!first) first = ph;
                    if (!prev || ph != prev + 0x1000) runs++;
                    prev = ph; last = ph;
                }
            }
            LOG("      physical pages: %lu separate run(s)%s, %lu not present, physical %08lx ... %08lx\n", runs,
                runs == 1 ? " = ONE physically contiguous block (allocated in one piece, typical of a driver buffer)" : "", np, first, last);
        }
        if (!IsBadReadPtr((void *)(ULONG_PTR)base, 4096)) {
            BYTE *p = (BYTE *)(ULONG_PTR)base; int j, run = 0; char str[80];
            LOG("      first bytes:"); for (j = 0; j < 64; j++) LOG("%s%02x", (j % 16) ? " " : "\n        ", p[j]); LOG("\n");
            LOG("      text in its first 64 KB:");
            for (j = 0; j < 65536 && !IsBadReadPtr(p + j, 1); j++) {
                if (p[j] >= 32 && p[j] < 127) { if (run < 79) str[run] = (char)p[j]; run++; }
                else { if (run >= 6) { str[run < 79 ? run : 79] = 0; LOG(" \"%s\"", str); } run = 0; }
            }
            LOG("\n");
        }
        if (ver >= 6) {   /* build 107: exact values only - the block's own address, the addresses in its header,
                           * its first physical address (what a driver gives the virtual GPU) */
            DWORD vals[6], nv = 0, v, a, j; static DWORD out[2 + 128];
            vals[nv++] = base;
            if (!IsBadReadPtr((void *)(ULONG_PTR)base, 8)) { vals[nv++] = ((DWORD *)(ULONG_PTR)base)[0]; vals[nv++] = ((DWORD *)(ULONG_PTR)base)[1]; }
            {   DWORD in[2], pt = 0; in[0] = base; in[1] = 1;
                if (DeviceIoControl(d, 4, in, 8, &pt, 4, &got, NULL) && (pt & 1)) { vals[nv++] = pt & 0xFFFFF000UL; vals[nv++] = (pt & 0xFFFFF000UL) >> 12; } }
            for (v = 0; v < nv; v++) {
                DWORD hits = 0;
                if (!vals[v]) continue;
                for (j = 0; j < v; j++) if (vals[j] == vals[v]) break;
                if (j < v) continue;
                LOG("      exact value %08lx stored at:\n", vals[v]);
                for (a = 0xC0000000UL; a >= 0xC0000000UL; a += 0x04000000UL) {
                    DWORD in[5]; in[0] = vals[v]; in[1] = vals[v] + 1; in[2] = a; in[3] = a >= 0xFC000000UL ? 0xFFFFF000UL : a + 0x04000000UL; in[4] = total_phys + (16u << 20);
                    if (DeviceIoControl(d, 6, in, 20, out, sizeof(out), &got, NULL))
                        for (i = 0; i < out[1] && i < 64; i++, hits++) if (hits < 24) {
                            DWORD dist; const char *nm = near_vxd(out[2 + i * 2], &dist);
                            LOG("        %08lx  (VxD with its DDB/code just below: %s, %lu KB further)\n", out[2 + i * 2], nm, dist >> 10);
                        }
                    if (a >= 0xFC000000UL) break;
                }
                for (a = 0x80000000UL; a < 0xC0000000UL; ) {
                    MEMORY_BASIC_INFORMATION m; DWORD next, x;
                    if (!VirtualQuery((LPCVOID)(ULONG_PTR)a, &m, sizeof(m)) || !m.RegionSize) break;
                    next = a + (DWORD)m.RegionSize;
                    if (m.State == MEM_COMMIT && !(m.Protect & (PAGE_NOACCESS | PAGE_GUARD)) && m.RegionSize <= (64u << 20))
                        for (x = a; x < next; x += 4096) {
                            DWORD *q = (DWORD *)(ULONG_PTR)x, k;
                            if (IsBadReadPtr(q, 4096)) continue;
                            for (k = 0; k < 1024; k++) if (q[k] == vals[v] && (DWORD *)&vals[v] != q + k) {
                                if (hits < 24) LOG("        %08lx  (shared arena, region %08lx)\n", x + k * 4, (DWORD)(ULONG_PTR)m.AllocationBase);
                                hits++;
                            }
                        }
                    if (next <= a) break;
                    a = next;
                }
                LOG("        %lu place(s)\n", hits);
            }
        }
        if (0) {
            DWORD a, total_hits = 0, pages = 0;
            static DWORD out[2 + 128];
            LOG("      pointers into it from Windows' system area (VxDs):\n");
            for (a = 0xC0000000UL; a >= 0xC0000000UL && a < 0xFFFFF000UL; a += 0x04000000UL) {
                DWORD in[5]; in[0] = base; in[1] = base + size; in[2] = a; in[3] = a >= 0xFC000000UL ? 0xFFFFF000UL : a + 0x04000000UL; in[4] = total_phys + (16u << 20);
                if (!DeviceIoControl(d, 6, in, 20, out, sizeof(out), &got, NULL)) { LOG("        %08lx: refused (%lu)\n", a, GetLastError()); continue; }
                pages += out[0];
                for (i = 0; i < out[1] && i < 64 && total_hits + i < 40; i++) {
                    DWORD dist; const char *nm = near_vxd(out[2 + i * 2], &dist);
                    LOG("        at %08lx value %08lx  (nearest VxD below: %s, %lu KB further)\n", out[2 + i * 2], out[3 + i * 2], nm, dist >> 10);
                }
                total_hits += out[1];
                if (a + 0x04000000UL < a) break;
            }
            LOG("        %lu pointer(s) found in %lu MB of system memory read\n", total_hits, pages >> 8);
        }
        if (0) {   DWORD a, hits = 0;
            LOG("      pointers into it from the shared arena (16-bit Windows, shared DLL data, other blocks):\n");
            for (a = 0x80000000UL; a < 0xC0000000UL; ) {
                MEMORY_BASIC_INFORMATION m; DWORD next, x;
                if (!VirtualQuery((LPCVOID)(ULONG_PTR)a, &m, sizeof(m)) || !m.RegionSize) break;
                next = a + (DWORD)m.RegionSize;
                if (m.State == MEM_COMMIT && !(a >= base && a < base + size) && !(m.Protect & (PAGE_NOACCESS | PAGE_GUARD)) && m.RegionSize <= (64u << 20)) {
                    for (x = a; x < next; x += 4096) {
                        DWORD *q = (DWORD *)(ULONG_PTR)x, k;
                        if (IsBadReadPtr(q, 4096)) continue;
                        for (k = 0; k < 1024; k++) if (q[k] - base < size) {
                            if (hits < 20) { char mod[MAX_PATH] = ""; GetModuleFileNameA((HMODULE)m.AllocationBase, mod, sizeof(mod));
                                LOG("        at %08lx value %08lx  (region %08lx %s)\n", x + k * 4, q[k], (DWORD)(ULONG_PTR)m.AllocationBase, mod); }
                            hits++;
                        }
                    }
                }
                if (next <= a) break;
                a = next;
            }
            LOG("        %lu pointer(s) found\n", hits);
        }
    }
    if (d != INVALID_HANDLE_VALUE) CloseHandle(d);
}

/* build 105: where the RAM is before any program runs. Windows 98's memory-manager counters (bytes; System Monitor
 * names), and every big committed block of the shared arena 80000000-BFFFFFFF (the same in every process): a sample
 * of its pages is looked up in the page tables through KEXALIAS.VXD (IOCTL 4) - physical address inside the RAM
 * size = it uses RAM, beyond it = device memory (e.g. the video card's), not present = swapped out / not touched.
 * Information only (the build 104 Chrome run: ~590 MB of 1 GB was already in use when Chrome started). */
static void mem_where(DWORD total_phys)
{
    HKEY k; DWORD i, a, ver = 0, got = 0, sh_commit = 0;
    HANDLE d = CreateFileA("\\\\.\\KEXALIAS.VXD", 0, 0, NULL, 0, 0, NULL);
    if (RegOpenKeyExA(HKEY_DYN_DATA, "PerfStats\\StatData", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        LOG("    Windows 98 memory manager (System Monitor):");
        for (i = 0; i < 200; i++) {
            char nm[64]; DWORD nl = sizeof(nm), t, v = 0, vl = sizeof(v);
            LONG r = RegEnumValueA(k, i, nm, &nl, NULL, &t, (BYTE *)&v, &vl);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS || vl != 4 || memcmp(nm, "VMM\\cpg", 7)) continue;
            LOG("%s %s %lu MB", (got++ % 4) ? "," : "\n     ", nm + 4, v >> 20);
        }
        LOG("\n");
        RegCloseKey(k);
    }
    if (d != INVALID_HANDLE_VALUE) DeviceIoControl(d, 3, NULL, 0, &ver, 4, &got, NULL);
    LOG("    shared arena blocks of 4 MB or more (base, size, of 64 sampled pages: in RAM / device memory / not present, first physical address)%s\n",
        ver >= 5 ? "" : " - KEXALIAS.VXD older than 5, no page lookup");
    for (a = 0x80000000UL; a < 0xC0000000UL; ) {
        MEMORY_BASIC_INFORMATION m; DWORD base, size = 0, next;
        if (!VirtualQuery((LPCVOID)(ULONG_PTR)a, &m, sizeof(m)) || !m.RegionSize) break;
        base = (DWORD)(ULONG_PTR)m.AllocationBase;
        if (m.State != MEM_COMMIT) { next = a + (DWORD)m.RegionSize; if (next <= a) break; a = next; continue; }
        /* one allocation: all regions with the same allocation base, committed part only */
        next = a;
        for (;;) {
            if (!VirtualQuery((LPCVOID)(ULONG_PTR)next, &m, sizeof(m)) || !m.RegionSize || (DWORD)(ULONG_PTR)m.AllocationBase != base || m.State == MEM_FREE) break;
            if (m.State == MEM_COMMIT) size += (DWORD)m.RegionSize;
            if (next + (DWORD)m.RegionSize <= next || next + (DWORD)m.RegionSize >= 0xC0000000UL) { next = 0xC0000000UL; break; }
            next += (DWORD)m.RegionSize;
        }
        sh_commit += size;
        if (size >= (4u << 20)) {
            DWORD ram = 0, dev = 0, np = 0, first = 0xFFFFFFFF, j;
            if (ver >= 5)
                for (j = 0; j < 64; j++) {
                    DWORD in[2], pte = 0, ret = 0, pa = a + (DWORD)(((unsigned __int64)size * j / 64) & ~0xFFFUL);
                    MEMORY_BASIC_INFORMATION q;
                    if (!VirtualQuery((LPCVOID)(ULONG_PTR)pa, &q, sizeof(q)) || q.State != MEM_COMMIT) continue;
                    in[0] = pa; in[1] = 1;
                    if (!DeviceIoControl(d, 4, in, 8, &pte, 4, &ret, NULL)) continue;
                    if (!(pte & 1)) { np++; continue; }
                    if (first == 0xFFFFFFFF) first = pte & 0xFFFFF000UL;
                    if ((pte & 0xFFFFF000UL) < total_phys + (16u << 20)) ram++; else dev++;
                }
            LOG("      %08lx %5lu MB: RAM %2lu, device %2lu, not present %2lu, first physical %08lx\n", a, size >> 20, ram, dev, np, first);
            if (size >= (16u << 20) && ram >= 48 && g_nbig < 8) { g_memblk[g_nbig][0] = a; g_memblk[g_nbig][1] = size; g_nbig++; }
        }
        if (next <= a) break;
        a = next;
    }
    LOG("    shared arena committed in all: %lu MB\n", sh_commit >> 20);
    if (d != INVALID_HANDLE_VALUE) CloseHandle(d);
    who_owns(total_phys);
}

static void test_memory_status(void)
{
    typedef struct { DWORD len, load; unsigned __int64 tp, ap, tpf, apf, tv, av, ax; } MSX;
    typedef BOOL (WINAPI *T_G)(MSX *);
    T_G g = (T_G)(void *)GetProcAddress(kx, "GlobalMemoryStatusEx");
    MEMORYSTATUS n; MSX m; HKEY k; DWORD v, t, sz; int i;
    static const char *const names[6] = { "VCACHE\\cCurPages", "VCACHE\\cMinPages", "VCACHE\\cMacPages", "VMM\\cpgDiskcache", "VMM\\cpgDiskcacheMin", "VMM\\cpgFree" };
    LOG("[memory status]\n");
    n.dwLength = sizeof(n); GlobalMemoryStatus(&n);
    LOG("    Windows 98: total %lu MB, available %lu MB, load %lu%%\n", n.dwTotalPhys >> 20, n.dwAvailPhys >> 20, n.dwMemoryLoad);
    {   /* build 116: what limits the swap file (Chrome ran out of commit with "page file free 0 of 1024 MB") */
        static const char *keys[] = { "PagingDrive", "PagingFile", "MinPagingFileSize", "MaxPagingFileSize", "ConservativeSwapfileUsage", "LocalLoadHigh", NULL };
        char v[128]; int q;
        LOG("    page file as GlobalMemoryStatus reports it: total %lu MB, free %lu MB\n", (unsigned long)(n.dwTotalPageFile >> 20), (unsigned long)(n.dwAvailPageFile >> 20));
        for (q = 0; keys[q]; q++) {
            GetPrivateProfileStringA("386Enh", keys[q], "(not set)", v, sizeof(v), "SYSTEM.INI");
            LOG("    SYSTEM.INI [386Enh] %s = %s\n", keys[q], v);
        }
        GetPrivateProfileStringA("vcache", "MaxFileCache", "(not set)", v, sizeof(v), "SYSTEM.INI");
        LOG("    SYSTEM.INI [vcache] MaxFileCache = %s\n", v);
        {   /* build 130: build 129 run - MinPagingFileSize=4096000 set, yet the swap file was 112 MB at start and
             * stopped growing at 1432-1452 MB while Chrome ran out of commit. Say what Windows really has. */
            DWORD mink = GetPrivateProfileIntA("386Enh", "MinPagingFileSize", 0, "SYSTEM.INI"), cur = 0, ty, cb = sizeof(cur); HKEY hk;
            if (RegOpenKeyExA(HKEY_DYN_DATA, "PerfStats\\StartStat", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
                RegQueryValueExA(hk, "VMM\\cpgSwapfile", NULL, &ty, (BYTE *)&cur, &cb); RegCloseKey(hk); }
            cur = 0; cb = sizeof(cur);
            if (RegOpenKeyExA(HKEY_DYN_DATA, "PerfStats\\StatData", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
                RegQueryValueExA(hk, "VMM\\cpgSwapfile", NULL, &ty, (BYTE *)&cur, &cb); RegCloseKey(hk); }
            LOG("    swap file now (VMM\\cpgSwapfile): %lu MB; MinPagingFileSize asks for %lu MB\n", (unsigned long)(cur >> 20), (unsigned long)(mink >> 10));
            if (mink && cur && (cur >> 10) + (16u << 10) < mink)
                LOG("    NOTE: Windows did NOT apply MinPagingFileSize (swap file smaller than the minimum set) - set the size in Control Panel >"
                    " System > Performance > Virtual Memory instead (2000 MB, minimum = maximum) and run kextest again\n");
        }
    }
    if (RegOpenKeyExA(HKEY_DYN_DATA, "PerfStats\\StartStat", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        for (i = 0; i < 6; i++) { sz = sizeof(v); RegQueryValueExA(k, names[i], NULL, &t, (BYTE *)&v, &sz); }
        RegCloseKey(k);
    }
    if (RegOpenKeyExA(HKEY_DYN_DATA, "PerfStats\\StatData", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        LOG("    counters:");
        for (i = 0; i < 6; i++) { sz = sizeof(v); v = 0; if (RegQueryValueExA(k, names[i], NULL, &t, (BYTE *)&v, &sz) == ERROR_SUCCESS) LOG(" %s=%lu", names[i], v); else LOG(" %s=(none)", names[i]); }
        LOG("\n");
        RegCloseKey(k);
    } else LOG("    HKEY_DYN_DATA\\PerfStats\\StatData not readable\n");
    mem_where(n.dwTotalPhys);
    if (!g) { CHECK(0, "kexnt exports GlobalMemoryStatusEx"); return; }
    memset(&m, 0, sizeof(m)); m.len = sizeof(m);
    CHECK(g(&m), "GlobalMemoryStatusEx through kexnt");
    LOG("    kexnt: total %lu MB, available %lu MB (disk cache above its minimum counted), load %lu%%\n",
        (DWORD)(m.tp >> 20), (DWORD)(m.ap >> 20), m.load);
    CHECK(m.ap + (4u << 20) >= n.dwAvailPhys && m.ap <= m.tp, "available memory: at least Windows 98's figure, at most the total");
    {   /* build 60: Windows 98's SwitchToThread is a stub that yields nothing */
        typedef BOOL (WINAPI *T_S)(void); T_S sw = (T_S)(void *)GetProcAddress(kx, "SwitchToThread");
        DWORD t0 = GetTickCount(); int i, ok = 1;
        if (!sw) { CHECK(0, "kexnt exports SwitchToThread"); return; }
        for (i = 0; i < 1000; i++) if (!sw()) ok = 0;
        LOG("    [yield] 1000 x SwitchToThread through kexnt: %lu ms\n", GetTickCount() - t0);
        CHECK(ok, "SwitchToThread returns TRUE (it yields now)");
    }
    {   /* build 61: cached timeGetTime must never go backwards and must keep pace with the clock */
        typedef DWORD (WINAPI *T_T)(void); T_T tg = (T_T)(void *)GetProcAddress(kx, "timeGetTime");
        DWORD a, b, prev, v, g0, g1; long n = 0; int back = 0;
        if (!tg) { CHECK(0, "kexnt exports timeGetTime"); return; }
        g0 = GetTickCount(); a = prev = tg();
        while (GetTickCount() - g0 < 2500) { v = tg(); if ((LONG)(v - prev) < 0) back++; prev = v; n++; }
        b = tg(); g1 = GetTickCount();
        LOG("    [timeGetTime] %ld calls in 2.5 s through kexnt, went backwards %d times, %lu ms vs GetTickCount %lu ms\n",
            n, back, b - a, g1 - g0);
        CHECK(back == 0, "cached timeGetTime never goes backwards");
        CHECK((LONG)((b - a) - (g1 - g0)) < 60 && (LONG)((g1 - g0) - (b - a)) < 60, "cached timeGetTime keeps pace with GetTickCount");
    }
}

/* build 63: Chromium's COM threads wait with MsgWaitForMultipleObjectsEx(1, &event, t, QS_ALLINPUT = 0x1CFF, 0) */
typedef DWORD (WINAPI *T_MWX)(DWORD, const HANDLE *, DWORD, DWORD, DWORD);
static HANDLE g_mw_ev; static T_MWX g_mw_fn; static DWORD g_mw_mask, g_mw_res, g_mw_ms;
static DWORD WINAPI mw_thread(LPVOID p)
{
    MSG m; DWORD t0;
    PeekMessageA(&m, NULL, 0, 0, PM_NOREMOVE);          /* give the thread a message queue, as COM does */
    t0 = GetTickCount();
    g_mw_res = g_mw_fn(1, &g_mw_ev, 3000, g_mw_mask, 0);
    g_mw_ms = GetTickCount() - t0;
    return 0;
}
static void mw_try(const char *who, T_MWX fn, DWORD mask)
{
    HANDLE th; DWORD tid;
    g_mw_ev = CreateEventA(NULL, FALSE, FALSE, NULL); g_mw_fn = fn; g_mw_mask = mask; g_mw_res = 0xDEAD; g_mw_ms = 0;
    th = CreateThread(NULL, 0, mw_thread, NULL, 0, &tid);
    Sleep(200); SetEvent(g_mw_ev);
    WaitForSingleObject(th, 5000); CloseHandle(th); CloseHandle(g_mw_ev);
    LOG("    MsgWaitForMultipleObjectsEx(1 event, mask %04lx) %s: result %08lx after %lu ms (event set at 200 ms)\n", mask, who, g_mw_res, g_mw_ms);
}
static void test_msgwait(void)
{
    T_MWX k = (T_MWX)(void *)GetProcAddress(kx, "MsgWaitForMultipleObjectsEx");
    T_MWX n = (T_MWX)(void *)GetProcAddress(GetModuleHandleA("USER32.DLL"), "MsgWaitForMultipleObjectsEx");
    LOG("[message waits]\n");
    if (n) { mw_try("Windows 98", n, 0x04FF); mw_try("Windows 98", n, 0x1CFF); }
    if (!k) { CHECK(0, "kexnt exports MsgWaitForMultipleObjectsEx"); return; }
    mw_try("kexnt", k, 0x1CFF);
    CHECK(g_mw_res == WAIT_OBJECT_0 && g_mw_ms < 1500, "a thread waiting with Windows 10's QS_ALLINPUT wakes when its event is set");
}

static void test_file_dialog(void)
{
    typedef HRESULT (WINAPI *T_CCI)(const GUID *, void *, DWORD, const GUID *, void **);
    typedef HRESULT (WINAPI *T_SCI)(LPCWSTR, void *, const GUID *, void **);
    static const GUID clsid_save = {0xC0B4E2F3,0xBA21,0x4773,{0x8D,0xBA,0x33,0x5E,0xC9,0x46,0xEB,0x8B}};
    static const GUID iid_save = {0x84BCCD23,0x5FDE,0x4CDB,{0xAE,0xA4,0xAF,0x64,0xB8,0x3D,0x78,0xAB}};
    static const GUID iid_item = {0x43826D1E,0xE718,0x42EE,{0xBC,0x55,0xA1,0xE2,0x61,0xC3,0x7B,0xFE}};
    T_CCI cci = (T_CCI)(void *)GetProcAddress(kx, "CoCreateInstance");
    T_SCI sci = (T_SCI)(void *)GetProcAddress(kx, "SHCreateItemFromParsingName");
    void *dlg = NULL, *item = NULL; HRESULT hr; DWORD opts = 0; WCHAR *name = NULL, *path = NULL;
    LOG("[file dialog]\n");
    if (!cci || !sci) { CHECK(0, "kexnt exports CoCreateInstance and SHCreateItemFromParsingName"); return; }
    hr = cci(&clsid_save, NULL, 1, &iid_save, &dlg);
    CHECK(hr == 0 && dlg, "CoCreateInstance(CLSID_FileSaveDialog) gives an IFileSaveDialog");
    if (dlg) {
        void **vt = *(void ***)dlg;
        ((HRESULT (WINAPI *)(void *, DWORD *))vt[10])(dlg, &opts);                       /* GetOptions */
        CHECK(opts & 2, "save dialog defaults include FOS_OVERWRITEPROMPT");
        ((HRESULT (WINAPI *)(void *, LPCWSTR))vt[15])(dlg, L"report.txt");               /* SetFileName */
        hr = ((HRESULT (WINAPI *)(void *, WCHAR **))vt[16])(dlg, &name);                 /* GetFileName */
        CHECK(hr == 0 && name && !lstrcmpW(name, L"report.txt"), "SetFileName / GetFileName round trip");
        if (name) CoTaskMemFree(name);
        ((ULONG (WINAPI *)(void *))vt[2])(dlg);
    }
    hr = sci(L"C:\\WINDOWS", NULL, &iid_item, &item);
    CHECK(hr == 0 && item, "SHCreateItemFromParsingName(C:\\WINDOWS)");
    if (item) {
        void **vt = *(void ***)item;
        hr = ((HRESULT (WINAPI *)(void *, DWORD, WCHAR **))vt[5])(item, 0x80058000, &path);   /* GetDisplayName(FILESYSPATH) */
        CHECK(hr == 0 && path && !lstrcmpiW(path, L"C:\\WINDOWS"), "IShellItem::GetDisplayName gives the path back");
        if (path) CoTaskMemFree(path);
        ((ULONG (WINAPI *)(void *))vt[2])(item);
    }
}

/* build 69: closes the Save dialog test_file_dialog2 opens, after reading what its name box shows */
static char g_dlg_name[128]; static volatile LONG g_dlg_seen;
static BOOL CALLBACK dlg_find(HWND w, LPARAM lp)
{
    char cls[32]; DWORD pid = 0;
    GetWindowThreadProcessId(w, &pid);
    if (pid != GetCurrentProcessId() || !IsWindowVisible(w)) return TRUE;
    cls[0] = 0; GetClassNameA(w, cls, sizeof(cls));
    if (lstrcmpA(cls, "#32770")) return TRUE;
    *(HWND *)lp = w; return FALSE;
}
static DWORD WINAPI dlg_closer(LPVOID p)
{
    int i;
    for (i = 0; i < 100; i++) {                       /* up to 10 s */
        HWND d = NULL; Sleep(100);
        EnumWindows(dlg_find, (LPARAM)&d);
        if (d) {
            Sleep(300);
            if (!g_dlg_seen) { g_dlg_name[0] = 0; GetDlgItemTextA(d, 0x480 /* edt1 */, g_dlg_name, sizeof(g_dlg_name)); g_dlg_seen = 1; }
            PostMessageA(d, WM_COMMAND, IDCANCEL, 0);
        } else if (g_dlg_seen) break;
    }
    return 0;
}
static void test_file_dialog2(void)
{
    typedef HRESULT (WINAPI *T_CCI)(const GUID *, void *, DWORD, const GUID *, void **);
    typedef HRESULT (WINAPI *T_SCI)(LPCWSTR, void *, const GUID *, void **);
    static const GUID clsid_save = {0xC0B4E2F3,0xBA21,0x4773,{0x8D,0xBA,0x33,0x5E,0xC9,0x46,0xEB,0x8B}};
    static const GUID iid_save = {0x84BCCD23,0x5FDE,0x4CDB,{0xAE,0xA4,0xAF,0x64,0xB8,0x3D,0x78,0xAB}};
    static const GUID iid_item = {0x43826D1E,0xE718,0x42EE,{0xBC,0x55,0xA1,0xE2,0x61,0xC3,0x7B,0xFE}};
    static const GUID clsid_fop = {0x3AD05575,0x8857,0x4850,{0x92,0x77,0x11,0xB8,0x5B,0xDB,0x8E,0x09}};
    static const GUID iid_fop = {0x947AAB5F,0x0A5C,0x4C13,{0xB4,0xD6,0x4B,0xF7,0x83,0x6F,0xC9,0xF8}};
    T_CCI cci = (T_CCI)(void *)GetProcAddress(kx, "CoCreateInstance");
    T_SCI sci = (T_SCI)(void *)GetProcAddress(kx, "SHCreateItemFromParsingName");
    void *dlg = NULL, *fop = NULL, *src = NULL, *dir = NULL; HRESULT hr; HANDLE th, f; DWORD n;
    char tmp[MAX_PATH], a[MAX_PATH], b[MAX_PATH]; WCHAR wa[MAX_PATH], wt[MAX_PATH]; BOOL ab = TRUE;
    if (!cci || !sci) return;
    /* 1. the Save dialog really shown (closed again by a helper thread): does the suggested name appear? */
    hr = cci(&clsid_save, NULL, 1, &iid_save, &dlg);
    if (hr == 0 && dlg) {
        void **vt = *(void ***)dlg;
        ((HRESULT (WINAPI *)(void *, LPCWSTR))vt[15])(dlg, L"kextest picture.jpg");      /* SetFileName */
        ((HRESULT (WINAPI *)(void *, LPCWSTR))vt[22])(dlg, L"");                         /* SetDefaultExtension "" as Chrome */
        {   /* build 74: like Chrome - file types and a start folder (Chrome's name box came up empty) */
            static const WCHAR *spec[4] = { L"JPEG Image", L"*.jpg;*.jpeg;*.jpe;*.jfif", L"All Files", L"*.*" };
            void *fold = NULL;
            ((HRESULT (WINAPI *)(void *, UINT, const void *))vt[4])(dlg, 2, spec);           /* SetFileTypes */
            ((HRESULT (WINAPI *)(void *, UINT))vt[5])(dlg, 1);                                 /* SetFileTypeIndex */
            if (sci(L"C:\\WINDOWS\\Desktop", NULL, &iid_item, &fold) == 0 && fold) {
                ((HRESULT (WINAPI *)(void *, void *))vt[12])(dlg, fold);                       /* SetFolder */
                ((ULONG (WINAPI *)(void *))(*(void ***)fold)[2])(fold);
            }
        }
        th = CreateThread(NULL, 0, dlg_closer, NULL, 0, &n);
        hr = ((HRESULT (WINAPI *)(void *, HWND))vt[3])(dlg, NULL);                       /* Show */
        if (th) { WaitForSingleObject(th, 12000); CloseHandle(th); }
        LOG("    Save dialog shown and cancelled: result %08lx, name box held \"%s\"\n", (unsigned long)hr, g_dlg_seen ? g_dlg_name : "(dialog not seen)");
        CHECK(hr == (HRESULT)0x800704C7L, "Save dialog: Cancel gives ERROR_CANCELLED");
        CHECK(g_dlg_seen && !lstrcmpiA(g_dlg_name, "kextest picture.jpg"), "Save dialog shows the suggested file name");
        ((ULONG (WINAPI *)(void *))vt[2])(dlg);
    }
    /* 2. IFileOperation: move a file to another name, the way Chromium finishes a download */
    GetTempPathA(MAX_PATH, tmp); n = lstrlenA(tmp); if (n > 3 && tmp[n - 1] == '\\') tmp[n - 1] = 0;
    wsprintfA(a, "%s\\kxfop1.tmp", tmp); wsprintfA(b, "%s\\kxfop picture.jpg", tmp);
    DeleteFileA(b);
    f = CreateFileA(a, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) { WriteFile(f, "abc", 3, &n, NULL); CloseHandle(f); }
    MultiByteToWideChar(CP_ACP, 0, a, -1, wa, MAX_PATH); MultiByteToWideChar(CP_ACP, 0, tmp, -1, wt, MAX_PATH);
    hr = cci(&clsid_fop, NULL, 1, &iid_fop, &fop);
    CHECK(hr == 0 && fop, "CoCreateInstance(CLSID_FileOperation) gives an IFileOperation");
    if (fop) {
        void **vt = *(void ***)fop;
        sci(wa, NULL, &iid_item, &src); sci(wt, NULL, &iid_item, &dir);
        ((HRESULT (WINAPI *)(void *, DWORD))vt[5])(fop, 0x0614);                          /* SetOperationFlags */
        hr = ((HRESULT (WINAPI *)(void *, void *, void *, LPCWSTR, void *))vt[14])(fop, src, dir, L"kxfop picture.jpg", NULL);   /* MoveItem */
        CHECK(hr == 0, "IFileOperation::MoveItem queued");
        hr = ((HRESULT (WINAPI *)(void *))vt[21])(fop);                                   /* PerformOperations */
        ((HRESULT (WINAPI *)(void *, BOOL *))vt[22])(fop, &ab);                           /* GetAnyOperationsAborted */
        CHECK(hr == 0 && !ab, "IFileOperation::PerformOperations succeeded, nothing aborted");
        CHECK(GetFileAttributesA(b) != 0xFFFFFFFF && GetFileAttributesA(a) == 0xFFFFFFFF, "the file is at its new name, the old one is gone");
        if (src) ((ULONG (WINAPI *)(void *))(*(void ***)src)[2])(src);
        if (dir) ((ULONG (WINAPI *)(void *))(*(void ***)dir)[2])(dir);
        ((ULONG (WINAPI *)(void *))vt[2])(fop);
    }
    DeleteFileA(a); DeleteFileA(b);
}

static void test_handle_path(void)
{
    typedef HANDLE (WINAPI *T_CFW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL (WINAPI *T_SFIBH)(HANDLE, int, LPVOID, DWORD); typedef BOOL (WINAPI *T_CH)(HANDLE);
    typedef DWORD (WINAPI *T_GFPN)(HANDLE, LPWSTR, DWORD, DWORD);
    T_CFW cfw = (T_CFW)(void *)GetProcAddress(kx, "CreateFileW");
    T_SFIBH sfi = (T_SFIBH)(void *)GetProcAddress(kx, "SetFileInformationByHandle");
    T_CH ch = (T_CH)(void *)GetProcAddress(kx, "CloseHandle");
    T_GFPN gfp = (T_GFPN)(void *)GetProcAddress(kx, "GetFinalPathNameByHandleW");
    char tmp[MAX_PATH], pa[MAX_PATH]; WCHAR pw[MAX_PATH], got[MAX_PATH + 8]; HANDLE h; BYTE yes = 1, no = 0; DWORD n;
    LOG("[file handles]\n");
    if (!cfw || !sfi || !ch || !gfp) { CHECK(0, "kexnt CreateFileW / SetFileInformationByHandle / CloseHandle / GetFinalPathNameByHandleW exported"); return; }
    GetTempPathA(MAX_PATH, tmp); sprintf(pa, "%skxdel.tmp", tmp);
    MultiByteToWideChar(CP_ACP, 0, pa, -1, pw, MAX_PATH);
    h = cfw(pw, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    CHECK(h != INVALID_HANDLE_VALUE, "CreateFileW %s", pa);
    if (h == INVALID_HANDLE_VALUE) return;
    n = gfp(h, got, MAX_PATH + 8, 0);
    LOG("    GetFinalPathNameByHandleW: %lu, \"%ls\"\n", n, n ? got : L"");
    CHECK(n > 4 && !lstrcmpiW(got + 4, pw), "GetFinalPathNameByHandleW gives the file's path (\\\\?\\ + path)");
    CHECK(sfi(h, 4, &yes, 1), "SetFileInformationByHandle(FileDispositionInfo, delete) accepted");
    CHECK(sfi(h, 4, &no, 1) && sfi(h, 4, &yes, 1), "delete flag can be cleared and set again");
    ch(h);
    CHECK(GetFileAttributesA(pa) == 0xFFFFFFFF, "file marked delete-on-close is gone after CloseHandle");
    h = cfw(pw, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) { sfi(h, 4, &yes, 1); sfi(h, 4, &no, 1); ch(h); }
    CHECK(GetFileAttributesA(pa) != 0xFFFFFFFF, "file whose delete flag was cleared again is kept");
    DeleteFileA(pa);
}

static BOOL CALLBACK dres_cb(HMODULE m, LPCWSTR t, LPWSTR n, LONG_PTR lp)
{
    struct { ULONG_PTR name; int n; } *c = (void *)lp;
    if (!c->n++) c->name = (ULONG_PTR)n;
    return TRUE;
}

/* build 85: positional file I/O (OVERLAPPED offset) from several threads on ONE handle. Windows 98 has no
 * positional I/O for disk files; kexnt seeks and reads - that pair must not be split by another thread
 * (Chrome: scripts read back with bytes from the wrong place -> "SyntaxError: Invalid or unexpected token"). */
typedef BOOL (WINAPI *T_RFP)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static char g_pwhy[200]; static T_RFP g_prf, g_pwf; static HANDLE g_pfile, g_pdup; static volatile LONG g_pbad, g_pdone;
#define PIO_SIZE (512 * 1024)
static DWORD WINAPI pio_reader(LPVOID arg)
{
    DWORD seed = (DWORD)(ULONG_PTR)arg * 2654435761u + 1, i, k; static DWORD bufs[8][1024]; DWORD *buf = bufs[(ULONG_PTR)arg & 7];
    for (i = 0; i < 1500; i++) {
        OVERLAPPED ov; DWORD got = 0, off, n;
        seed = seed * 1103515245u + 12345u; off = ((seed >> 8) % (PIO_SIZE / 4 - 1024)) * 4;
        seed = seed * 1103515245u + 12345u; n = (((seed >> 8) % 1024) + 1) * 4;
        ZeroMemory(&ov, sizeof(ov)); ov.Offset = off;
        {   HANDLE fh = ((ULONG_PTR)arg & 1) && g_pdup ? g_pdup : g_pfile; BOOL ok = g_prf(fh, buf, n, &got, &ov); DWORD le = GetLastError();
            if (!ok || got != n) {
                if (InterlockedIncrement(&g_pbad) == 1) sprintf(g_pwhy, "read %s: ok %d error %lu, got %lu of %lu at %lu", fh == g_pfile ? "handle" : "duplicate", ok, le, got, n, off);
                continue;
            }
        }
        for (k = 0; k < n / 4; k++) if (buf[k] != off + k * 4) {
            if (InterlockedIncrement(&g_pbad) == 1) sprintf(g_pwhy, "read at %lu (%lu bytes): word %lu holds %lu (that is offset %lu), expected %lu", off, n, k, buf[k], buf[k], off + k * 4);
            break;
        }
    }
    InterlockedIncrement(&g_pdone);
    return 0;
}
static DWORD WINAPI pio_writer(LPVOID arg)
{
    DWORD t = (DWORD)(ULONG_PTR)arg, b, k; static DWORD bufs[4][1024]; DWORD *buf = bufs[t & 3];
    for (b = t; b < PIO_SIZE / 4096; b += 4) {
        OVERLAPPED ov; DWORD put = 0;
        for (k = 0; k < 1024; k++) buf[k] = b * 4096 + k * 4;
        ZeroMemory(&ov, sizeof(ov)); ov.Offset = b * 4096;
        if (!g_pwf(g_pfile, buf, 4096, &put, &ov) || put != 4096) InterlockedIncrement(&g_pbad);
    }
    InterlockedIncrement(&g_pdone);
    return 0;
}
static void test_positional_io(void)
{
    char tmp[MAX_PATH], pa[MAX_PATH]; HANDLE th[8]; DWORD i, tid, bad_w, k, got; static DWORD chk[1024];
    LOG("[positional file I/O from several threads]\n");
    g_prf = (T_RFP)(void *)GetProcAddress(kx, "ReadFile"); g_pwf = (T_RFP)(void *)GetProcAddress(kx, "WriteFile");
    if (!g_prf || !g_pwf) { CHECK(0, "kexnt ReadFile / WriteFile exported"); return; }
    GetTempPathA(MAX_PATH, tmp); sprintf(pa, "%skxpio.tmp", tmp);
    g_pfile = CreateFileA(pa, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    CHECK(g_pfile != INVALID_HANDLE_VALUE, "create %s", pa);
    if (g_pfile == INVALID_HANDLE_VALUE) return;
    g_pbad = 0; g_pdone = 0;                         /* 4 threads write interleaved 4 KB blocks at their offsets */
    for (i = 0; i < 4; i++) th[i] = CreateThread(NULL, 0, pio_writer, (LPVOID)(ULONG_PTR)i, 0, &tid);
    WaitForMultipleObjects(4, th, TRUE, 60000);
    for (i = 0; i < 4; i++) CloseHandle(th[i]);
    bad_w = 0;
    SetFilePointer(g_pfile, 0, NULL, FILE_BEGIN);
    for (i = 0; i < PIO_SIZE / 4096; i++) {
        if (!ReadFile(g_pfile, chk, 4096, &got, NULL) || got != 4096) { bad_w++; continue; }
        for (k = 0; k < 1024; k++) if (chk[k] != i * 4096 + k * 4) { bad_w++; break; }
    }
    LOG("    4 threads wrote 128 blocks at their offsets: %lu write errors, %lu blocks with wrong content\n", (DWORD)g_pbad, bad_w);
    CHECK(!g_pbad && !bad_w, "positional writes from 4 threads land at their own offsets (%ld errors, %lu bad blocks)", (long)g_pbad, bad_w);
    g_pbad = 0; g_pdone = 0;                         /* 6 threads read random ranges and check every value */
    for (i = 0; i < 6; i++) th[i] = CreateThread(NULL, 0, pio_reader, (LPVOID)(ULONG_PTR)i, 0, &tid);
    WaitForMultipleObjects(6, th, TRUE, 120000);
    for (i = 0; i < 6; i++) CloseHandle(th[i]);
    LOG("    6 threads x 1500 reads at random offsets: %ld wrong or short\n", (long)g_pbad);
    if (g_pbad) LOG("      first one: %s\n", g_pwhy);
    CHECK(!g_pbad, "positional reads from 6 threads return the bytes at their own offsets (%ld wrong)", (long)g_pbad);
    /* build 99: half the threads read through a DuplicateHandle copy - the same Windows 98 file object and so the
     * same file pointer (Chromium's base::File::Duplicate); the seek+read lock has to cover both handles */
    if (DuplicateHandle(GetCurrentProcess(), g_pfile, GetCurrentProcess(), &g_pdup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        g_pbad = 0; g_pdone = 0; g_pwhy[0] = 0;
        for (i = 0; i < 6; i++) th[i] = CreateThread(NULL, 0, pio_reader, (LPVOID)(ULONG_PTR)(i + 8), 0, &tid);
        WaitForMultipleObjects(6, th, TRUE, 120000);
        for (i = 0; i < 6; i++) CloseHandle(th[i]);
        LOG("    6 threads x 1500 reads, half through a duplicated handle: %ld wrong or short\n", (long)g_pbad);
        if (g_pbad) LOG("      first one: %s\n", g_pwhy);
        CHECK(!g_pbad, "positional reads through a handle and its duplicate return the right bytes (%ld wrong)", (long)g_pbad);
        CloseHandle(g_pdup); g_pdup = NULL;
    } else CHECK(0, "DuplicateHandle of a file");
    CloseHandle(g_pfile); DeleteFileA(pa);
}

/* build 92: a file grown past its end reads back zeros in the new part (NT does that; Windows 98 leaves old disk
 * contents there - Chromium's metrics files and disk cache entries came back with garbage in them) */
static int zero_range(HANDLE f, DWORD from, DWORD to)
{
    static BYTE b[8192]; DWORD got, k, pos = from;
    SetFilePointer(f, (LONG)from, NULL, FILE_BEGIN);
    while (pos < to) {
        DWORD want = to - pos > sizeof(b) ? sizeof(b) : to - pos;
        if (!ReadFile(f, b, want, &got, NULL) || got != want) return 0;
        for (k = 0; k < got; k++) if (b[k]) return 0;
        pos += got;
    }
    return 1;
}
static void test_zero_grow(void)
{
    typedef BOOL (WINAPI *T_SEOF)(HANDLE); typedef HANDLE (WINAPI *T_CFMA)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
    T_SEOF seof = (T_SEOF)(void *)GetProcAddress(kx, "SetEndOfFile");
    T_CFMA cfm = (T_CFMA)(void *)GetProcAddress(kx, "CreateFileMappingA");
    T_RFP wf = (T_RFP)(void *)GetProcAddress(kx, "WriteFile");
    char tmp[MAX_PATH], pa[MAX_PATH], pj[MAX_PATH]; HANDLE f, m; DWORD put, i; OVERLAPPED ov; BYTE one = 0x5A;
    static BYTE junk[65536]; int raw;
    LOG("[file grown past its end: new part is zeros]\n");
    if (!seof || !cfm || !wf) { CHECK(0, "kexnt SetEndOfFile / CreateFileMappingA / WriteFile exported"); return; }
    GetTempPathA(MAX_PATH, tmp); sprintf(pa, "%skxzero.tmp", tmp); sprintf(pj, "%skxjunk.tmp", tmp);
    /* leave non-zero data in free disk space first, so a grown file would pick it up on plain Windows 98 */
    memset(junk, 0xA5, sizeof(junk));
    f = CreateFileA(pj, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) { for (i = 0; i < 64; i++) WriteFile(f, junk, sizeof(junk), &put, NULL); CloseHandle(f); }
    DeleteFileA(pj);
    f = CreateFileA(pa, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    CHECK(f != INVALID_HANDLE_VALUE, "create %s", pa);
    if (f == INVALID_HANDLE_VALUE) return;
    WriteFile(f, "0123456789", 10, &put, NULL);
    /* what Windows itself does (information only) */
    SetFilePointer(f, 300000, NULL, FILE_BEGIN); SetEndOfFile(f);
    raw = zero_range(f, 10, 300000);
    LOG("    Windows' own SetEndOfFile: new part %s\n", raw ? "zeros" : "NOT zeros (old disk contents)");
    SetFilePointer(f, 10, NULL, FILE_BEGIN); SetEndOfFile(f);
    /* 1: seek past the end, write */
    SetFilePointer(f, 200000, NULL, FILE_BEGIN);
    CHECK(wf(f, &one, 1, &put, NULL) && put == 1, "write 1 byte at 200000 after a seek past the end");
    CHECK(zero_range(f, 10, 200000), "the bytes from the old end (10) to 200000 read back as zeros");
    /* 2: write at an offset (OVERLAPPED) past the end */
    memset(&ov, 0, sizeof(ov)); ov.Offset = 400000;
    CHECK(wf(f, &one, 1, &put, &ov), "write at offset 400000 (OVERLAPPED) past the end");
    CHECK(zero_range(f, 200001, 400000), "the bytes from 200001 to 400000 read back as zeros");
    /* 3: SetEndOfFile further out */
    SetFilePointer(f, 700000, NULL, FILE_BEGIN);
    CHECK(seof(f), "SetEndOfFile at 700000");
    CHECK(GetFileSize(f, NULL) == 700000 && zero_range(f, 400001, 700000), "file is 700000 bytes, new part zeros");
    /* 4: a writable mapping bigger than the file */
    m = cfm(f, NULL, PAGE_READWRITE, 0, 1000000, NULL);
    CHECK(m != NULL, "CreateFileMapping 1000000 bytes on a 700000-byte file");
    if (m) {
        BYTE *v = (BYTE *)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0); int ok = v != NULL;
        if (v) { for (i = 700000; i < 1000000; i++) if (v[i]) { ok = 0; break; } UnmapViewOfFile(v); }
        CloseHandle(m);
        CHECK(ok, "the mapping's part past the old end is zeros");
    }
    CloseHandle(f); DeleteFileA(pa);
}

/* build 85: resources of a module loaded as a data file (Chrome's download-icon reader crashed in KERNEL32) */
static void test_datafile_res(void)
{
    typedef BOOL (WINAPI *T_ERNW)(HMODULE, LPCWSTR, ENUMRESNAMEPROCW, LONG_PTR);
    typedef HRSRC (WINAPI *T_FRW)(HMODULE, LPCWSTR, LPCWSTR);
    typedef HGLOBAL (WINAPI *T_LR)(HMODULE, HRSRC); typedef DWORD (WINAPI *T_SR)(HMODULE, HRSRC);
    typedef LPVOID (WINAPI *T_LKR)(HGLOBAL); typedef HANDLE (WINAPI *T_LIW)(HINSTANCE, LPCWSTR, UINT, int, int, UINT);
    T_ERNW ern = (T_ERNW)(void *)GetProcAddress(kx, "EnumResourceNamesW");
    T_FRW frw = (T_FRW)(void *)GetProcAddress(kx, "FindResourceW");
    T_LR lr = (T_LR)(void *)GetProcAddress(kx, "LoadResource"); T_SR sr = (T_SR)(void *)GetProcAddress(kx, "SizeofResource");
    T_LKR lkr = (T_LKR)(void *)GetProcAddress(kx, "LockResource"); T_LIW liw = (T_LIW)(void *)GetProcAddress(kx, "LoadImageW");
    char path[MAX_PATH]; HMODULE h; HRSRC r; HGLOBAL g; BYTE *p; DWORD sz; HANDLE ic;
    struct ctx { ULONG_PTR name; int n; } c = { 0, 0 };
    LOG("[resources of a data-file module]\n");
    if (!ern || !frw || !lr || !sr || !lkr || !liw) { CHECK(0, "kexnt resource functions / LoadImageW exported"); return; }
    GetWindowsDirectoryA(path, MAX_PATH); lstrcatA(path, "\\NOTEPAD.EXE");
    h = LoadLibraryExA(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    LOG("    LoadLibraryEx(%s, AS_DATAFILE) = %p\n", path, (void *)h);
    CHECK(h != NULL, "NOTEPAD.EXE loads as a data file");
    if (!h) return;
    c.n = 0;
    CHECK(ern(h, (LPCWSTR)RT_GROUP_ICON, dres_cb, (LONG_PTR)&c), "EnumResourceNamesW(RT_GROUP_ICON) on the data-file module");
    LOG("    icon groups: %d, first %s%lu\n", c.n, c.name >= 0x10000 ? "(named) " : "#", (DWORD)(c.name >= 0x10000 ? 0 : c.name));
    CHECK(c.n > 0, "NOTEPAD.EXE has an icon group");
    if (c.n > 0 && c.name < 0x10000) {
        r = frw(h, (LPCWSTR)c.name, (LPCWSTR)RT_GROUP_ICON);
        g = r ? lr(h, r) : NULL; sz = r ? sr(h, r) : 0; p = g ? (BYTE *)lkr(g) : NULL;
        LOG("    FindResourceW %p, LoadResource %p, SizeofResource %lu, first words %04x %04x %04x\n", (void *)r, (void *)g, sz,
            p ? ((WORD *)p)[0] : 0, p ? ((WORD *)p)[1] : 0, p ? ((WORD *)p)[2] : 0);
        CHECK(p && sz >= 6 && ((WORD *)p)[0] == 0 && ((WORD *)p)[1] == 1 && ((WORD *)p)[2] >= 1 && sz >= 6u + 14u * ((WORD *)p)[2],
              "the icon group read back is a valid GRPICONDIR");
        ic = liw(h, (LPCWSTR)c.name, IMAGE_ICON, 32, 32, 0);
        LOG("    LoadImageW(data-file module, icon, 32x32) = %p\n", ic);
        CHECK(ic != NULL, "LoadImageW gives the icon of a data-file module");
        if (ic) DestroyIcon((HICON)ic);
    }
    CHECK(liw(h, (LPCWSTR)(ULONG_PTR)0x7FFF, IMAGE_ICON, 32, 32, 0) == NULL, "LoadImageW of a missing icon returns NULL (no crash)");
    FreeLibrary(h);
}


/* build 86: a read-only mapping of a big read-only file is one mapping object for every process (Win98 made a
 * new copy in the 1 GB shared arena per CreateFileMapping: resources.pak + icudtl.dat = 34 MB per Chrome process) */
static void test_ro_share(void)
{
    typedef HANDLE (WINAPI *T_CFW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef HANDLE (WINAPI *T_CFMW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
    typedef LPVOID (WINAPI *T_MV)(HANDLE, DWORD, DWORD, DWORD, SIZE_T); typedef BOOL (WINAPI *T_UV)(LPCVOID);
    T_CFW cfw = (T_CFW)(void *)GetProcAddress(kx, "CreateFileW");
    T_CFMW cfm = (T_CFMW)(void *)GetProcAddress(kx, "CreateFileMappingW");
    T_MV mv = (T_MV)(void *)GetProcAddress(kx, "MapViewOfFile"); T_UV uv = (T_UV)(void *)GetProcAddress(kx, "UnmapViewOfFile");
    char tmp[MAX_PATH], pa[MAX_PATH]; WCHAR pw[MAX_PATH]; HANDLE f, f1, f2, m1, m2; BYTE *v1, *v2; DWORD i, w, e2; static BYTE blk[65536];
    MEMORY_BASIC_INFORMATION q1, q2;
    LOG("[read-only file mappings shared]\n");
    if (!cfw || !cfm || !mv || !uv) { CHECK(0, "kexnt CreateFileW / CreateFileMappingW / MapViewOfFile exported"); return; }
    GetTempPathA(MAX_PATH, tmp); sprintf(pa, "%skxroshr.tmp", tmp);
    f = CreateFileA(pa, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { CHECK(0, "create %s", pa); return; }
    for (i = 0; i < 32; i++) { DWORD k; for (k = 0; k < sizeof(blk); k++) blk[k] = (BYTE)(i * 7 + k); WriteFile(f, blk, sizeof(blk), &w, NULL); }
    CloseHandle(f);
    MultiByteToWideChar(CP_ACP, 0, pa, -1, pw, MAX_PATH);
    f1 = cfw(pw, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    f2 = cfw(pw, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    m1 = f1 != INVALID_HANDLE_VALUE ? cfm(f1, NULL, PAGE_READONLY, 0, 0, NULL) : NULL;
    m2 = f2 != INVALID_HANDLE_VALUE ? cfm(f2, NULL, PAGE_READONLY, 0, 0, NULL) : NULL; e2 = GetLastError();
    v1 = m1 ? (BYTE *)mv(m1, FILE_MAP_READ, 0, 0, 0) : NULL;
    v2 = m2 ? (BYTE *)mv(m2, FILE_MAP_READ, 0, 0, 0) : NULL;
    ZeroMemory(&q1, sizeof(q1)); ZeroMemory(&q2, sizeof(q2));
    if (v1) VirtualQuery(v1, &q1, sizeof(q1));
    if (v2) VirtualQuery(v2, &q2, sizeof(q2));
    LOG("    two read-only mappings of one 2 MB file: views %p %p, last error after the 2nd %lu\n", (void *)v1, (void *)v2, e2);
    CHECK(m1 && m2 && v1 && v2, "two read-only mappings of the same file map");
    CHECK(e2 == 0, "an unnamed mapping never reports ERROR_ALREADY_EXISTS (%lu)", e2);
    CHECK(v1 && v2 && !memcmp(v1, v2, 2u << 20) && v1[65536 * 5 + 3] == (BYTE)(5 * 7 + 3), "both views show the file's bytes");
    if (v1) uv(v1); if (v2) uv(v2);
    if (m1) CloseHandle(m1); if (m2) CloseHandle(m2);
    if (f1 != INVALID_HANDLE_VALUE) CloseHandle(f1); if (f2 != INVALID_HANDLE_VALUE) CloseHandle(f2);
    DeleteFileA(pa);
}


/* build 89: kexnt only for modern programs. KXLEGACY.EXE is a Windows 98 program (subsystem 4.0): kexnt must
 * count it as one and stay out of it; kextest itself (marker export) counts as modern. */
static void test_gate(void)
{
    typedef VOID (WINAPI *T_GI)(PDWORD, PDWORD);
    T_GI gi = (T_GI)(void *)GetProcAddress(kx, "KexGateInfo");
    DWORD st = 0, why = 0, code = 99; char me[MAX_PATH], *bs; STARTUPINFOA si; PROCESS_INFORMATION pi;
    LOG("[kexnt only for modern programs]\n");
    if (!gi) { CHECK(0, "kexnt exports KexGateInfo"); return; }
    gi(&st, &why);
    LOG("    this process: %s (reason %lu: 1 subsystem 5+, 2 NT profile, 3 marker, 4 gate off)\n", st == 2 ? "modern" : st == 1 ? "Windows 9x program" : "?", why);
    CHECK(st == 2, "kextest counts as a modern program (%lu)", st);
    GetModuleFileNameA(NULL, me, MAX_PATH);
    if ((bs = strrchr(me, '\\'))) strcpy(bs + 1, "KXLEGACY.EXE");
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    if (GetFileAttributesA(me) == 0xFFFFFFFF) { CHECK(0, "%s present", me); return; }
    if (CreateProcessA(me, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 15000); GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    LOG("    KXLEGACY.EXE (subsystem 4.0): exit code %lu (1 = kexnt counts it as a Windows 9x program and stays out,\n"
        "      2 = counted as modern, 8 = kexnt not loaded there at all, 9 = KexGateInfo missing)\n", code);
    CHECK(code == 1 || code == 8, "a Windows 98 program is left to plain KernelEx (%lu)", code);
}

/* build 95: byte-stream integrity of kexnt pipes under load, the way Chromium's mojo channels use them: byte mode,
 * overlapped on both ends, both directions at once, writes larger than the 32 KB ring (queued, partial) and
 * reads of random sizes. Every byte carries its stream position, so a lost, doubled or reordered piece shows. */
#define PST_BYTES (6u << 20)
typedef struct { HANDLE h; int dir; volatile LONG bad, err; DWORD first_bad; } PST;
static BYTE pst_byte(int dir, DWORD pos) { DWORD x = (pos + 1) * 2654435761u ^ (dir ? 0x5bd1e995u : 0); return (BYTE)(x >> 13); }
static DWORD WINAPI pst_writer(LPVOID a)
{
    PST *t = (PST *)a; static BYTE wbuf[2][70000]; BYTE *b = wbuf[t->dir]; DWORD pos = 0, seed = 1234 + t->dir, n, i, put;
    OVERLAPPED ov; HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    while (pos < PST_BYTES) {
        seed = seed * 1103515245u + 12345u; n = 1 + (seed >> 8) % 70000u; if (n > PST_BYTES - pos) n = PST_BYTES - pos;
        for (i = 0; i < n; i++) b[i] = pst_byte(t->dir, pos + i);
        memset(&ov, 0, sizeof(ov)); ov.hEvent = ev; put = 0;
        if (!np.WriteFile(t->h, b, n, &put, &ov)) {
            if (GetLastError() != ERROR_IO_PENDING || !np.GetOverlappedResult(t->h, &ov, &put, TRUE)) { InterlockedIncrement(&t->err); break; }
        } else np.GetOverlappedResult(t->h, &ov, &put, TRUE);
        if (put != n) { InterlockedIncrement(&t->err); break; }
        pos += n;
    }
    CloseHandle(ev); return 0;
}
static DWORD WINAPI pst_reader(LPVOID a)
{
    PST *t = (PST *)a; static BYTE rbuf[2][50000]; BYTE *b = rbuf[t->dir]; DWORD pos = 0, seed = 777 + t->dir, n, i, got;
    OVERLAPPED ov; HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    while (pos < PST_BYTES) {
        seed = seed * 1103515245u + 12345u; n = 1 + (seed >> 8) % 50000u;
        memset(&ov, 0, sizeof(ov)); ov.hEvent = ev; got = 0;
        if (!np.ReadFile(t->h, b, n, &got, &ov)) {
            if (GetLastError() != ERROR_IO_PENDING || !np.GetOverlappedResult(t->h, &ov, &got, TRUE)) { InterlockedIncrement(&t->err); break; }
        } else np.GetOverlappedResult(t->h, &ov, &got, TRUE);
        if (!got || got > n) { InterlockedIncrement(&t->err); break; }
        for (i = 0; i < got; i++) if (b[i] != pst_byte(!t->dir, pos + i)) { if (!t->bad) t->first_bad = pos + i; InterlockedIncrement(&t->bad); break; }
        pos += got;
        if (t->bad) break;
    }
    CloseHandle(ev); return 0;
}
static void test_pipe_stream(void)
{
    static const WCHAR name[] = L"\\\\.\\pipe\\kxstress";
    HANDLE srv, cli, ev, th[4]; OVERLAPPED ov; DWORD n, t0, tid, i; PST w0, w1, r0, r1;
    LOG("[pipe byte stream under load]\n");
    if (!np_resolve() || !np.CreateNamedPipeW) { CHECK(0, "pipe exports present"); return; }
    srv = np.CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                              PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
    if (srv == INVALID_HANDLE_VALUE) { CHECK(0, "CreateNamedPipeW (byte) %lu", GetLastError()); return; }
    ev = CreateEventA(NULL, TRUE, FALSE, NULL); memset(&ov, 0, sizeof(ov)); ov.hEvent = ev;
    np.ConnectNamedPipe(srv, &ov);
    cli = np.CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (cli == INVALID_HANDLE_VALUE) { CHECK(0, "client open %lu", GetLastError()); CloseHandle(srv); return; }
    WaitForSingleObject(ev, 3000); np.GetOverlappedResult(srv, &ov, &n, FALSE);
    memset(&w0, 0, sizeof(w0)); w1 = r0 = r1 = w0;
    w0.h = srv; w0.dir = 0; r1.h = cli; r1.dir = 1;     /* server -> client: r1 checks dir 0 bytes */
    w1.h = cli; w1.dir = 1; r0.h = srv; r0.dir = 0;     /* client -> server: r0 checks dir 1 bytes */
    t0 = GetTickCount();
    th[0] = CreateThread(NULL, 0, pst_writer, &w0, 0, &tid); th[1] = CreateThread(NULL, 0, pst_writer, &w1, 0, &tid);
    th[2] = CreateThread(NULL, 0, pst_reader, &r0, 0, &tid); th[3] = CreateThread(NULL, 0, pst_reader, &r1, 0, &tid);
    if (WaitForMultipleObjects(4, th, TRUE, 120000) == WAIT_TIMEOUT) { LOG("    timed out after 120 s\n"); CHECK(0, "pipe stress finished in 120 s"); }
    for (i = 0; i < 4; i++) CloseHandle(th[i]);
    LOG("    2 x %u MB both ways in %lu ms: write errors %ld/%ld, read errors %ld/%ld, bad bytes %ld (at %lu) / %ld (at %lu)\n",
        PST_BYTES >> 20, GetTickCount() - t0, w0.err, w1.err, r0.err, r1.err, r0.bad, r0.first_bad, r1.bad, r1.first_bad);
    CHECK(!w0.err && !w1.err && !r0.err && !r1.err, "pipe stress: no I/O errors");
    CHECK(!r0.bad && !r1.bad, "pipe stress: every byte arrived in order and intact both ways");
    CloseHandle(cli); CloseHandle(srv); CloseHandle(ev);
}

/* build 96: job objects with "kill on job close" (Chromium's helpers must end with the browser) */
typedef HANDLE (WINAPI *T_CJO)(LPSECURITY_ATTRIBUTES, LPCWSTR);
typedef BOOL (WINAPI *T_APJ)(HANDLE, HANDLE);
typedef BOOL (WINAPI *T_SIJ)(HANDLE, int, LPVOID, DWORD);
typedef BOOL (WINAPI *T_CH)(HANDLE);
static HANDLE job_sleeper(T_CJO cjo, T_APJ apj, T_SIJ sij, HANDLE *job_out, DWORD *pid)
{
    char me[MAX_PATH], cmd[MAX_PATH + 32]; STARTUPINFOA si; PROCESS_INFORMATION pi; BYTE lim[112]; HANDLE job;
    GetModuleFileNameA(NULL, me, MAX_PATH); sprintf(cmd, "\"%s\" sleeper", me);
    job = cjo(NULL, NULL); if (!job) return NULL;
    memset(lim, 0, sizeof(lim)); *(DWORD *)(lim + 16) = 0x2000;   /* JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE */
    sij(job, 9, lim, sizeof(lim));
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return NULL;
    apj(job, pi.hProcess); ResumeThread(pi.hThread); CloseHandle(pi.hThread);
    *job_out = job; *pid = pi.dwProcessId;
    return pi.hProcess;
}
static int job_owner_child(void)            /* "jobowner": own a job with a sleeper, publish its pid, wait to be killed */
{
    T_CJO cjo = (T_CJO)(void *)GetProcAddress(kx, "CreateJobObjectW"); T_APJ apj = (T_APJ)(void *)GetProcAddress(kx, "AssignProcessToJobObject");
    T_SIJ sij = (T_SIJ)(void *)GetProcAddress(kx, "SetInformationJobObject");
    HANDLE job = NULL, p, m; DWORD pid = 0, *pp;
    if (!cjo || !apj || !sij) return 2;
    p = job_sleeper(cjo, apj, sij, &job, &pid);
    m = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, "KXJOBTEST_PID");
    pp = m ? (DWORD *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0) : NULL;
    if (pp) *pp = p ? pid : 0xFFFFFFFF;
    Sleep(60000);
    return 0;
}
static void test_jobs(void)
{
    T_CJO cjo = (T_CJO)(void *)GetProcAddress(kx, "CreateJobObjectW"); T_APJ apj = (T_APJ)(void *)GetProcAddress(kx, "AssignProcessToJobObject");
    T_SIJ sij = (T_SIJ)(void *)GetProcAddress(kx, "SetInformationJobObject"); T_CH ch = (T_CH)(void *)GetProcAddress(kx, "CloseHandle");
    HANDLE job = NULL, p, m, owner, gc; DWORD pid = 0, w, *pp, t; char me[MAX_PATH], cmd[MAX_PATH + 32]; STARTUPINFOA si; PROCESS_INFORMATION pi;
    LOG("[job objects: kill on job close]\n");
    if (!cjo || !apj || !sij || !ch) { CHECK(0, "kexnt job functions exported"); return; }
    p = job_sleeper(cjo, apj, sij, &job, &pid);
    CHECK(p != NULL, "job made, sleeper child started and assigned");
    if (p) {
        Sleep(500);
        CHECK(WaitForSingleObject(p, 0) == WAIT_TIMEOUT, "the child runs while the job is open");
        ch(job);
        w = WaitForSingleObject(p, 5000);
        LOG("    job handle closed: child %s\n", w == WAIT_OBJECT_0 ? "ended" : "STILL RUNNING");
        CHECK(w == WAIT_OBJECT_0, "closing the job's last handle ends its processes");
        if (w != WAIT_OBJECT_0) TerminateProcess(p, 0);
        CloseHandle(p);
    }
    /* the owner dies without kexnt seeing it (killed from outside): the member must notice by itself */
    m = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, "KXJOBTEST_PID");
    pp = m ? (DWORD *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0) : NULL;
    if (!pp) { CHECK(0, "test mapping"); return; }
    *pp = 0;
    GetModuleFileNameA(NULL, me, MAX_PATH); sprintf(cmd, "\"%s\" jobowner", me);
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) { CHECK(0, "start job owner"); return; }
    owner = pi.hProcess; CloseHandle(pi.hThread);
    for (t = 0; t < 100 && !*pp; t++) Sleep(100);
    gc = (*pp && *pp != 0xFFFFFFFF) ? OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, *pp) : NULL;
    CHECK(gc != NULL, "job owner started its member (pid %08lx)", *pp);
    TerminateProcess(owner, 1);                          /* from outside: the owner's kexnt never sees it */
    WaitForSingleObject(owner, 5000); CloseHandle(owner);
    if (gc) {
        w = WaitForSingleObject(gc, 8000);
        LOG("    owner killed from outside: its job member %s\n", w == WAIT_OBJECT_0 ? "ended by itself" : "STILL RUNNING");
        CHECK(w == WAIT_OBJECT_0, "a job member ends when the job's owner was killed");
        if (w != WAIT_OBJECT_0) TerminateProcess(gc, 0);
        CloseHandle(gc);
    }
    UnmapViewOfFile(pp); CloseHandle(m);
}


/* build 98: are a thread's SSE (XMM0-7, MXCSR) and x87 registers kept when Windows 98 switches threads? Chrome's
 * renderer parses streamed scripts and marks/sweeps the JS heap on worker threads with SSE code; with those threads
 * off (--single-threaded) Discord loads, with them on its scripts come out as "Invalid or unexpected token". Each
 * worker loads its own pattern into the registers, spins (gets pre-empted by the others), and checks them. Run plain,
 * with a Sleep inside, and with another thread stopping it as kexnt's profiler (CONTEXT_CONTROL) and hang logger
 * (CONTEXT_FULL) do. */
typedef struct { int id; volatile LONG stop, rounds, bad_xmm, bad_csr, bad_x87; void *sleepfn; DWORD spins; } SIMDT;
static int simd_round(SIMDT *t)
{
    /* one block, addressed through ESI only: pat 0..143, out 144..287, spins 288, sleep 292, mxcsr in 296, out 300 */
    DWORD blk[76] __attribute__((aligned(16))); DWORD *pat = blk, *out = blk + 36, want = 0x1F80 | ((t->id & 3) << 13), csr = 0x1F80;
    int i, bad = 0;
    for (i = 0; i < 32; i++) pat[i] = 0x9E3779B9u * (DWORD)(t->id * 64 + i + 1) ^ (DWORD)t->rounds;
    ((double *)(pat + 32))[0] = 1.25 + t->id; ((double *)(pat + 32))[1] = -3.5 - t->id * 7;
    memset(out, 0, 36 * 4);
    blk[72] = t->spins; blk[73] = (DWORD)(ULONG_PTR)t->sleepfn; blk[74] = want; blk[75] = 0;
    __asm__ volatile(
        "mov 292(%0),%%ebx\n\t"
        "ldmxcsr 296(%0)\n\t"
        "fldl 128(%0)\n\tfldl 136(%0)\n\t"
        "movups 0(%0),%%xmm0\n\tmovups 16(%0),%%xmm1\n\tmovups 32(%0),%%xmm2\n\tmovups 48(%0),%%xmm3\n\t"
        "movups 64(%0),%%xmm4\n\tmovups 80(%0),%%xmm5\n\tmovups 96(%0),%%xmm6\n\tmovups 112(%0),%%xmm7\n\t"
        "mov 288(%0),%%ecx\n"
        "1:\n\tdec %%ecx\n\tjnz 1b\n\t"
        "test %%ebx,%%ebx\n\tjz 2f\n\tpush $1\n\tcall *%%ebx\n"
        "2:\n\t"
        "movups %%xmm0,144(%0)\n\tmovups %%xmm1,160(%0)\n\tmovups %%xmm2,176(%0)\n\tmovups %%xmm3,192(%0)\n\t"
        "movups %%xmm4,208(%0)\n\tmovups %%xmm5,224(%0)\n\tmovups %%xmm6,240(%0)\n\tmovups %%xmm7,256(%0)\n\t"
        "fstpl 272(%0)\n\tfstpl 280(%0)\n\t"
        "stmxcsr 300(%0)\n\t"
        : : "S"(blk) : "eax", "ebx", "ecx", "edx", "memory", "cc");
    __asm__ volatile("ldmxcsr %0" : : "m"(csr));
    for (i = 0; i < 32; i++) if (out[i] != pat[i]) bad++;
    if (bad) InterlockedIncrement(&t->bad_xmm);
    if ((blk[75] & 0xFFC0) != (want & 0xFFC0)) InterlockedIncrement(&t->bad_csr);
    if (out[32] != pat[34] || out[33] != pat[35] || out[34] != pat[32] || out[35] != pat[33]) InterlockedIncrement(&t->bad_x87);
    return bad;
}
static DWORD WINAPI simd_worker(LPVOID p) { SIMDT *t = p; while (!t->stop) { simd_round(t); InterlockedIncrement(&t->rounds); } return 0; }
static int cpu_has_sse(void)
{
    DWORD a, b, c, d, f1, f2;
    __asm__ volatile("pushfl\n\tpopl %0\n\tmovl %0,%1\n\txorl $0x200000,%0\n\tpushl %0\n\tpopfl\n\tpushfl\n\tpopl %0\n\tpushl %1\n\tpopfl" : "=&r"(f1), "=&r"(f2));
    if (!((f1 ^ f2) & 0x200000)) return 0;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1));
    return (d >> 25) & 1;
}
/* build 130: the illegal instruction in a Discord call (build 129, crash3 x2) was VZEROUPPER at CHROME.DLL+10db8f9 =
 * Opus' celt/x86/pitch_avx.c. Opus picks its AVX2 code from CPUID alone (opus_select_arch, chrome.dll 192dfc20:
 * leaf 1 ECX bits 28 AVX + 12 FMA, leaf 7 EBX bit 5 AVX2) and never asks whether the OS saves the AVX registers
 * (OSXSAVE / XGETBV). Windows 98 never turns AVX on, so every VEX instruction faults. The VM must not advertise AVX
 * (VMware .vmx: cpuid.1.ecx = "--00:----:----:----:---0:----:----:----"). This check says which case this PC is. */
static void test_cpu_avx(void)
{
    DWORD a, b, c1, d, c7 = 0, b7 = 0, maxl, f1, f2; int avx, fma, osx, avx2, usable = 0;
    LOG("[CPU: AVX advertised vs. usable under Windows 98]\n");
    __asm__ volatile("pushfl\n\tpopl %0\n\tmovl %0,%1\n\txorl $0x200000,%0\n\tpushl %0\n\tpopfl\n\tpushfl\n\tpopl %0\n\tpushl %1\n\tpopfl" : "=&r"(f1), "=&r"(f2));
    if (!((f1 ^ f2) & 0x200000)) { LOG("    no CPUID - skipped\n"); return; }
    __asm__ volatile("cpuid" : "=a"(maxl), "=b"(b), "=c"(c1), "=d"(d) : "a"(0), "c"(0));
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c1), "=d"(d) : "a"(1), "c"(0));
    if (maxl >= 7) __asm__ volatile("cpuid" : "=a"(a), "=b"(b7), "=c"(c7), "=d"(d) : "a"(7), "c"(0));
    avx = (c1 >> 28) & 1; { int f16c = (c1 >> 29) & 1; if (f16c && !avx) LOG("    F16C advertised without AVX\n"); avx |= f16c; } fma = (c1 >> 12) & 1; osx = (c1 >> 27) & 1; avx2 = (b7 >> 5) & 1;
    if (osx) { DWORD lo, hi; __asm__ volatile(".byte 0x0f,0x01,0xd0" : "=a"(lo), "=d"(hi) : "c"(0)); usable = (lo & 6) == 6; }
    LOG("    CPUID leaf 1 ECX %08lx: AVX %d FMA %d OSXSAVE %d; leaf 7 EBX %08lx: AVX2 %d; AVX switched on by Windows: %s\n",
        (unsigned long)c1, avx, fma, osx, (unsigned long)b7, avx2, usable ? "yes" : "no");
    if (!avx) { LOG("    AVX not advertised - programs that trust CPUID alone (Opus voice in Chrome) take their SSE code\n"); CHECK(1, ""); return; }
    CHECK(usable, "the CPU advertises AVX%s%s but Windows 98 cannot run AVX instructions: Chrome's Opus voice encoder "
          "(Discord calls) dies with an invalid instruction. VMware: power the VM off and add to its .vmx file the line  "
          "cpuid.1.ecx = \"--00:----:----:----:---0:----:----:----\"  (hides AVX, F16C and FMA; see README Test 6)",
          fma ? "+FMA" : "", avx2 ? "+AVX2" : "");
}
static void test_simd_state(void)
{
    static const char *mode[4] = { "pre-empted only", "Sleep(1) between load and check", "stopped by a sampler (CONTEXT_CONTROL, as kexnt's profiler)", "stopped by a sampler (CONTEXT_FULL, as kexnt's hang logger)" };
    SIMDT t[4]; HANDLE h[4]; int m, i; DWORD spins = 2000000, t0;
    void *slp = (void *)GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "Sleep");
    LOG("[SSE/x87 registers kept across thread switches]\n");
    if (!cpu_has_sse()) { LOG("    CPU has no SSE - skipped\n"); return; }
    t0 = GetTickCount(); { SIMDT c; memset(&c, 0, sizeof(c)); c.spins = spins; simd_round(&c); }
    t0 = GetTickCount() - t0; if (t0 < 5) spins *= 4;
    for (m = 0; m < 4; m++) {
        LONG rounds = 0, bx = 0, bc = 0, b8 = 0, samples = 0;
        for (i = 0; i < 4; i++) { memset(&t[i], 0, sizeof(t[i])); t[i].id = i + 1; t[i].spins = spins; t[i].sleepfn = m == 1 ? slp : NULL;
            h[i] = CreateThread(NULL, 0, simd_worker, &t[i], 0, NULL); }
        t0 = GetTickCount();
        while (GetTickCount() - t0 < 1500u * g_scale) {
            if (m >= 2) {
                for (i = 0; i < 4; i++) { CONTEXT c; memset(&c, 0, sizeof(c)); c.ContextFlags = m == 2 ? CONTEXT_CONTROL : CONTEXT_FULL;
                    if (SuspendThread(h[i]) != 0xFFFFFFFF) { GetThreadContext(h[i], &c); ResumeThread(h[i]); samples++; } }
                Sleep(2);
            } else Sleep(50);
        }
        for (i = 0; i < 4; i++) t[i].stop = 1;
        WaitForMultipleObjects(4, h, TRUE, 30000);
        for (i = 0; i < 4; i++) { rounds += t[i].rounds; bx += t[i].bad_xmm; bc += t[i].bad_csr; b8 += t[i].bad_x87; CloseHandle(h[i]); }
        LOG("    %s: %ld rounds, XMM changed %ld, MXCSR changed %ld, x87 changed %ld (%ld samples)\n", mode[m], rounds, bx, bc, b8, samples);
        CHECK(rounds > 8 && !bx && !bc && !b8, "%s: registers kept (rounds %ld, xmm %ld, mxcsr %ld, x87 %ld)", mode[m], rounds, bx, bc, b8);
    }
}


/* build 101: Discord's scripts reached V8 as ZEROS of the right length (build 100, 145 of 145). Chromium's data pipe
 * maps its buffer twice in the browser (the second view is a KEXALIAS alias); when the browser writes only through
 * the alias, the section's own page-table entry never gets its "dirty" bit, and after the alias is gone Windows 98's
 * pager may drop the page unsaved under memory pressure - the renderer then reads a fresh zero page.
 * Here: section, two views, write a pattern ONLY through the second (alias), release it, then fill most of the free
 * RAM so Windows has to page, and read the section back through the first view (and through a fresh third view). */
static void test_alias_dirty(void)
{
    typedef HANDLE (WINAPI *T_CFM)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
    typedef LPVOID (WINAPI *T_MV)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
    typedef BOOL (WINAPI *T_UV)(LPCVOID);
    T_CFM cfm = (T_CFM)(void *)GetProcAddress(kx, "CreateFileMappingA");
    T_MV mv = (T_MV)(void *)GetProcAddress(kx, "MapViewOfFile");
    T_UV uv = (T_UV)(void *)GetProcAddress(kx, "UnmapViewOfFile");
    enum { SZ = 2 << 20 };
    HANDLE s; DWORD *a, *b, *c, i, bad_a = 0, bad_c = 0, ver = 0, got = 0; MEMORYSTATUS ms; BYTE *hog[256]; int nh = 0, k;
    HANDLE d = CreateFileA("\\\\.\\KEXALIAS.VXD", 0, 0, NULL, 0, 0, NULL);
    LOG("[shared memory written only through a second view, then memory pressure]\n");
    if (d != INVALID_HANDLE_VALUE) { DeviceIoControl(d, 3, NULL, 0, &ver, sizeof(ver), &got, NULL); CloseHandle(d); }
    LOG("    KEXALIAS.VXD version %lu (4 = keeps pages written through a second view)\n", ver);
    if (!cfm || !mv || !uv) { CHECK(0, "kexnt section exports"); return; }
    s = cfm(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SZ, NULL);
    a = s ? (DWORD *)mv(s, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SZ) : NULL;
    b = a ? (DWORD *)mv(s, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SZ) : NULL;
    if (!a || !b || a == b) { LOG("    no second view (%p %p) - skipped\n", (void *)a, (void *)b); if (a) uv(a); if (b && b != a) uv(b); if (s) CloseHandle(s); return; }
    for (i = 0; i < SZ / 4; i++) b[i] = 0xA5000000u | i;      /* written ONLY through the alias */
    uv(b);                                                     /* the alias goes, as when the browser hands the pipe on */
    GlobalMemoryStatus(&ms);
    if (g_scale == 1) LOG("    (memory pressure part only with STRESS.BAT - it swaps everything else out for a while)\n");
    else
    {   DWORD want = ms.dwAvailPhys + (48u << 20), have = 0;   /* push past the free RAM so Windows pages */
        while (have < want && nh < 256) {
            BYTE *p = (BYTE *)VirtualAlloc(NULL, 4u << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!p) break;
            for (k = 0; k < (4 << 20); k += 4096) p[k] = (BYTE)k | 1;
            hog[nh++] = p; have += 4u << 20;
        }
        LOG("    filled %lu MB (free RAM was %lu MB)\n", have >> 20, ms.dwAvailPhys >> 20);
    }
    for (k = 0; k < nh; k++) VirtualFree(hog[k], 0, MEM_RELEASE);
    for (i = 0; i < SZ / 4; i++) if (a[i] != (0xA5000000u | i)) bad_a++;
    c = (DWORD *)mv(s, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SZ);
    if (c) { for (i = 0; i < SZ / 4; i++) if (c[i] != (0xA5000000u | i)) bad_c++; uv(c); }
    LOG("    read back after the pressure: %lu wrong words through the first view, %lu through a new view (of %u)\n", bad_a, bad_c, SZ / 4);
    CHECK(!bad_a && !bad_c, "data written through a second view survives memory pressure (%lu / %lu wrong)", bad_a, bad_c);
    uv(a); CloseHandle(s);
}

/* build 94: DuplicateHandle(DUPLICATE_CLOSE_SOURCE) on a handle inside a child that has already ended. Windows 98
 * reads the dead process's freed environment block and the CALLER crashes in KERNEL32 (build 93: Chrome's browser
 * process, right after a tab process ended). NT and kexnt refuse it. */
static void test_dead_dup(void)
{
    typedef BOOL (WINAPI *T_DH)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
    T_DH dh = (T_DH)(void *)GetProcAddress(kx, "DuplicateHandle");
    char me[MAX_PATH], *bs; STARTUPINFOA si; PROCESS_INFORMATION pi; BOOL r; DWORD le; HANDLE out = NULL;
    LOG("[handle operations on a process that has ended]\n");
    if (!dh) { CHECK(0, "kexnt exports DuplicateHandle"); return; }
    GetModuleFileNameA(NULL, me, MAX_PATH);
    if ((bs = strrchr(me, '\\'))) strcpy(bs + 1, "KXLEGACY.EXE");
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessA(me, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) { CHECK(0, "start %s", me); return; }
    WaitForSingleObject(pi.hProcess, 15000); Sleep(200);
    LOG("    child ended; closing its handle 4 from here (DUPLICATE_CLOSE_SOURCE) - Windows 98 itself would crash this process\n");
    r = dh(pi.hProcess, (HANDLE)4, NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE); le = GetLastError();
    LOG("    result %d, error %lu\n", r, le);
    CHECK(!r, "close-source DuplicateHandle in an ended process is refused, no crash (%d, %lu)", r, le);
    r = dh(GetCurrentProcess(), GetCurrentProcess(), pi.hProcess, &out, 0, FALSE, DUPLICATE_SAME_ACCESS); le = GetLastError();
    CHECK(!r, "DuplicateHandle INTO an ended process is refused (%d, %lu)", r, le);
    r = dh(GetCurrentProcess(), pi.hThread, GetCurrentProcess(), &out, 0, FALSE, DUPLICATE_SAME_ACCESS);
    CHECK(r, "a duplicate within this process still works");
    if (r) CloseHandle(out);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
}

/* build 48: Chromium puts only CF_UNICODETEXT on the clipboard; Windows 98 never converts it to CF_TEXT */
static void test_clipboard(void)
{
    typedef HANDLE (WINAPI *T_SCD)(UINT, HANDLE); typedef HANDLE (WINAPI *T_GCD)(UINT); typedef BOOL (WINAPI *T_ICFA)(UINT);
    T_SCD scd = (T_SCD)(void *)GetProcAddress(kx, "SetClipboardData");
    T_GCD gcd = (T_GCD)(void *)GetProcAddress(kx, "GetClipboardData");
    T_ICFA icfa = (T_ICFA)(void *)GetProcAddress(kx, "IsClipboardFormatAvailable");
    static const WCHAR txt[] = L"kexng clipboard";
    HGLOBAL g; HANDLE r; int ok_a = 0, ok_w = 0;
    LOG("[clipboard]\n");
    if (!scd || !gcd || !icfa) { CHECK(0, "kexnt clipboard functions exported"); return; }
    if (!OpenClipboard(NULL)) { LOG("    OpenClipboard failed (%lu) - skipped\n", GetLastError()); return; }
    EmptyClipboard();
    g = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, sizeof(txt));
    if (g) { memcpy(GlobalLock(g), txt, sizeof(txt)); GlobalUnlock(g); }
    CHECK(g && scd(CF_UNICODETEXT, g) != NULL, "SetClipboardData(CF_UNICODETEXT)");
    if ((r = GetClipboardData(CF_TEXT)) != NULL) { const char *a = (const char *)GlobalLock(r); ok_a = a && !strcmp(a, "kexng clipboard"); GlobalUnlock(r); }
    CHECK(ok_a, "Unicode text put on the clipboard can be read as CF_TEXT (Notepad, 9x programs)");
    EmptyClipboard();
    g = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, 16);
    if (g) { strcpy((char *)GlobalLock(g), "ansi text"); GlobalUnlock(g); SetClipboardData(CF_TEXT, g); }
    CHECK(icfa(CF_UNICODETEXT), "CF_UNICODETEXT reported available when only CF_TEXT is there");
    if ((r = gcd(CF_UNICODETEXT)) != NULL) { const WCHAR *w = (const WCHAR *)GlobalLock(r); ok_w = w && !lstrcmpW(w, L"ansi text"); GlobalUnlock(r); }
    CHECK(ok_w, "CF_TEXT from a 9x program can be read as CF_UNICODETEXT (pasting into Chrome)");
    EmptyClipboard();
    CloseClipboard();
}

/* build 53: is the back buffer kept across SwapBuffers? Chromium draws only the changed part of a frame. */
static void test_gl_keepback(void)
{
    typedef void (WINAPI *T_RP)(int, int, int, int, unsigned, unsigned, void *);
    typedef void (WINAPI *T_RB)(unsigned);
    HMODULE gl = LoadLibraryA("OPENGL32.DLL");
    typedef BOOL (WINAPI *T_SB)(HDC); T_SB sb = (T_SB)(void *)GetProcAddress(kx, "SwapBuffers");
    T_SB nsb = (T_SB)(void *)GetProcAddress(GetModuleHandleA("GDI32.DLL"), "SwapBuffers");
    T_WCC wcc; T_WMC wmc; T_WDC wdc; T_GLCC cc; T_GLC clr; T_GLF fin; T_RP rp; T_RB rb;
    WNDCLASSA wc; HWND w; HDC dc; PIXELFORMATDESCRIPTOR pfd; int pf; HGLRC rc; DWORD px = 0, px2 = 0;
    LOG("[GL back buffer]\n");
    if (!gl || !sb || !nsb) { LOG("    OpenGL / SwapBuffers not available - skipped\n"); return; }
    {   /* build 55b: OPENGL32's USER32 GetDC slot should now lead into kexnt's guard */
        BYTE *b = (BYTE *)gl; IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(b + *(LONG *)(b + 0x3C));
        IMAGE_NT_HEADERS32 *knt = (IMAGE_NT_HEADERS32 *)((BYTE *)kx + *(LONG *)((BYTE *)kx + 0x3C));
        IMAGE_IMPORT_DESCRIPTOR *d = (IMAGE_IMPORT_DESCRIPTOR *)(b + nt->OptionalHeader.DataDirectory[1].VirtualAddress);
        DWORD lo = (DWORD)(ULONG_PTR)kx, hi = lo + knt->OptionalHeader.SizeOfImage, v = 0;
        for (; d->Name; d++) if (!lstrcmpiA((char *)b + d->Name, "USER32.dll") && d->OriginalFirstThunk) {
            DWORD *ilt = (DWORD *)(b + d->OriginalFirstThunk), *iat = (DWORD *)(b + d->FirstThunk);
            for (; *ilt; ilt++, iat++) if (!(*ilt & 0x80000000) && !lstrcmpA((char *)b + *ilt + 2, "GetDC")) v = *iat;
        }
        {   /* the guard may live in the KernelEx folder's kexnt (system-wide), not this test copy */
            MEMORY_BASIC_INFORMATION mb; char mn[MAX_PATH] = "?";
            if (v && VirtualQuery((LPCVOID)(ULONG_PTR)v, &mb, sizeof(mb))) GetModuleFileNameA((HMODULE)mb.AllocationBase, mn, MAX_PATH);
            LOG("    OPENGL32 import GetDC -> %08lx in %s (%s)\n", v, mn,
                (v >= lo && v < hi) || strstr(mn, "KEXNT") || strstr(mn, "kexnt") ? "kexnt guard" : "not guarded");
        }
    }
    wcc = (T_WCC)(void *)GetProcAddress(gl, "wglCreateContext"); wmc = (T_WMC)(void *)GetProcAddress(gl, "wglMakeCurrent");
    wdc = (T_WDC)(void *)GetProcAddress(gl, "wglDeleteContext"); cc = (T_GLCC)(void *)GetProcAddress(gl, "glClearColor");
    clr = (T_GLC)(void *)GetProcAddress(gl, "glClear"); fin = (T_GLF)(void *)GetProcAddress(gl, "glFinish");
    rp = (T_RP)(void *)GetProcAddress(gl, "glReadPixels"); rb = (T_RB)(void *)GetProcAddress(gl, "glReadBuffer");
    if (!wcc || !wmc || !wdc || !cc || !clr || !fin || !rp || !rb) return;
    memset(&wc, 0, sizeof(wc)); wc.lpfnWndProc = gl_wndproc; wc.hInstance = GetModuleHandleA(NULL); wc.lpszClassName = "KexKeepBack";
    RegisterClassA(&wc);
    w = CreateWindowA("KexKeepBack", "kextest back buffer", WS_POPUP | WS_VISIBLE, 60, 60, 128, 128, NULL, NULL, wc.hInstance, NULL);
    dc = w ? GetDC(w) : NULL;
    if (!dc) return;
    memset(&pfd, 0, sizeof(pfd)); pfd.nSize = sizeof(pfd); pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER; pfd.iPixelType = PFD_TYPE_RGBA; pfd.cColorBits = 32;
    pf = ChoosePixelFormat(dc, &pfd);
    if (pf <= 0 || !SetPixelFormat(dc, pf, &pfd) || !(rc = wcc(dc)) || !wmc(dc, rc)) { LOG("    no GL context - skipped\n"); ReleaseDC(w, dc); DestroyWindow(w); return; }
    rb(0x0405 /* BACK */);
    /* Windows' own SwapBuffers: frame 1 red, frame 2 green, then what is in the back buffer? */
    cc(1, 0, 0, 1); clr(0x4000); fin(); nsb(dc);
    cc(0, 1, 0, 1); clr(0x4000); fin(); nsb(dc);
    rb(0x0405); rp(64, 64, 1, 1, 0x80E1 /* BGRA */, 0x1401, &px);
    LOG("    driver alone: after red, green swapped, the back buffer holds %06lx (%s)\n", px & 0xFFFFFF,
        (px & 0xFFFFFF) == 0x00FF00 ? "the last frame - copy swap" : (px & 0xFFFFFF) == 0xFF0000 ? "the frame before last - flip swap" : "something else");
    /* kexnt's SwapBuffers: the back buffer must hold the frame just shown */
    cc(0, 0, 1, 1); clr(0x4000); fin(); sb(dc);
    cc(1, 1, 0, 1); clr(0x4000); fin(); sb(dc);
    rb(0x0405); rp(64, 64, 1, 1, 0x80E1, 0x1401, &px2);
    LOG("    through kexnt: after blue, yellow swapped, the back buffer holds %06lx\n", px2 & 0xFFFFFF);
    CHECK((px2 & 0xFFFFFF) == 0xFFFF00, "back buffer keeps the frame just shown after SwapBuffers (partial redraws stay correct)");
    wmc(NULL, NULL); wdc(rc); ReleaseDC(w, dc); DestroyWindow(w);
}

static void test_glass(void)
{
    typedef HRESULT (WINAPI *T_DEF)(HWND, const int *);
    typedef void (WINAPI *T_SC)(int, int, int, int);
    HMODULE dwm = LoadLibraryA("DWMAPI.DLL"), gl = LoadLibraryA("OPENGL32.DLL");
    T_DEF def = dwm ? (T_DEF)(void *)GetProcAddress(dwm, "DwmExtendFrameIntoClientArea") : NULL;
    T_WCC wcc; T_WMC wmc; T_WDC wdc; T_GLCC cc; T_GLC clr; T_GLE en; T_SC sc; T_GLF fin;
    typedef BOOL (WINAPI *T_SB)(HDC); T_SB sb = (T_SB)(void *)GetProcAddress(kx, "SwapBuffers");
    WNDCLASSA wc; HWND w; HDC dc; PIXELFORMATDESCRIPTOR pfd, d; int pf; HGLRC rc; HRGN rg; RECT box; int kind;
    LOG("[glass windows]\n");
    if (!def || !gl || !sb) { LOG("    dwmapi / OpenGL / kexnt SwapBuffers not available - skipped\n"); return; }
    wcc = (T_WCC)(void *)GetProcAddress(gl, "wglCreateContext"); wmc = (T_WMC)(void *)GetProcAddress(gl, "wglMakeCurrent");
    wdc = (T_WDC)(void *)GetProcAddress(gl, "wglDeleteContext"); cc = (T_GLCC)(void *)GetProcAddress(gl, "glClearColor");
    clr = (T_GLC)(void *)GetProcAddress(gl, "glClear"); en = (T_GLE)(void *)GetProcAddress(gl, "glEnable");
    sc = (T_SC)(void *)GetProcAddress(gl, "glScissor"); fin = (T_GLF)(void *)GetProcAddress(gl, "glFinish");
    if (!wcc || !wmc || !wdc || !cc || !clr || !en || !sc || !fin) return;
    memset(&wc, 0, sizeof(wc)); wc.lpfnWndProc = gl_wndproc; wc.hInstance = GetModuleHandleA(NULL); wc.lpszClassName = "KexGlass";
    RegisterClassA(&wc);
    w = CreateWindowA("KexGlass", "kextest glass", WS_POPUP | WS_VISIBLE, 40, 40, 200, 100, NULL, NULL, wc.hInstance, NULL);
    dc = w ? GetDC(w) : NULL;
    if (!dc) return;
    memset(&pfd, 0, sizeof(pfd)); pfd.nSize = sizeof(pfd); pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER; pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 32; pfd.cAlphaBits = 8;
    pf = ChoosePixelFormat(dc, &pfd);
    DescribePixelFormat(dc, pf, sizeof(d), &d);
    if (pf <= 0 || !SetPixelFormat(dc, pf, &pfd) || !(rc = wcc(dc)) || !wmc(dc, rc)) { LOG("    no GL context - skipped\n"); ReleaseDC(w, dc); DestroyWindow(w); return; }
    { int m[4] = { -1, -1, -1, -1 }; def(w, m); }
    cc(0, 0, 0, 0); clr(0x4000);                                  /* all transparent ... */
    en(0x0C11 /* SCISSOR_TEST */); sc(100, 0, 100, 100); cc(0.2f, 0.4f, 0.8f, 1.0f); clr(0x4000);   /* ... right half opaque */
    fin(); sb(dc);
    rg = CreateRectRgn(0, 0, 0, 0);
    kind = GetWindowRgn(w, rg);
    GetRgnBox(rg, &box);
    LOG("    pixel format %d has %u alpha bits; window region type %d, box %ld,%ld-%ld,%ld\n", pf, d.cAlphaBits, kind,
        box.left, box.top, box.right, box.bottom);
    if (d.cAlphaBits) CHECK(kind != ERROR && box.left >= 95 && box.left <= 105 && box.right == 200, "glass window shaped from its alpha (opaque right half only)");
    else LOG("    (this OpenGL driver gives no alpha channel - nothing to shape)\n");
    DeleteObject(rg);
    wmc(NULL, NULL); wdc(rc); ReleaseDC(w, dc); DestroyWindow(w);
}

/* build 89: kexnt treats this test program as a modern one (gate_ext.c) */
__declspec(dllexport) int KexNG_ModernProcess = 1;


/* ---------------- build 123: address space above 2 GB for large address aware programs ---------------- */
typedef LPVOID (WINAPI *T_VA3)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *T_VF3)(LPVOID, SIZE_T, DWORD);
typedef BOOL (WINAPI *T_VP3)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI *T_TP3)(HANDLE, UINT);
typedef VOID (WINAPI *T_EP3)(UINT);
static T_VA3 lva; static T_VF3 lvf; static T_VP3 lvp; static T_TP3 ltp; static T_EP3 lep;
static BOOL laa_resolve(void)
{
    /* build 131: the kexnt.dll this process actually runs on (KernelEx's KnownDLLs copy in WINDOWS\KERNELEX), not
     * kextest's second copy (kx): kx's own calls to KERNEL32's VirtualAlloc land in the system copy, which lends the
     * block above 2 GB and keeps it in ITS table - kx then refused to commit in it ("commit 64 KB inside it" FAILED
     * since build 123, the "pre-existing" [above 2 GB] failure). A real program has one kexnt.dll. */
    char sp[MAX_PATH]; HMODULE m = NULL;
    if (GetWindowsDirectoryA(sp, MAX_PATH - 24)) { lstrcatA(sp, "\\KERNELEX\\KEXNT.DLL"); m = GetModuleHandleA(sp); }
    if (!m) m = kx;
    LOG("    memory functions from %s\n", m == kx ? "kextest's kexnt.dll copy" : sp);
    lva = (T_VA3)GetProcAddress(m, "VirtualAlloc"); lvf = (T_VF3)GetProcAddress(m, "VirtualFree");
    lvp = (T_VP3)GetProcAddress(m, "VirtualProtect"); ltp = (T_TP3)GetProcAddress(m, "TerminateProcess");
    lep = (T_EP3)GetProcAddress(m, "ExitProcess");
    return lva && lvf && lvp && ltp && lep;
}
#define LAA_FILL 1200
static DWORD laa_priv[LAA_FILL]; static int laa_npriv;
/* reserve 2 MB blocks through kexnt until one lands above 2 GB (returned) or nothing more comes */
static DWORD laa_fill(void)
{
    laa_npriv = 0;
    while (laa_npriv < LAA_FILL) {
        DWORD r = (DWORD)(ULONG_PTR)lva(NULL, 0x200000, MEM_RESERVE, PAGE_NOACCESS);
        if (!r) return 0;
        if (r >= 0x80000000UL) return r;
        laa_priv[laa_npriv++] = r;
    }
    return 0;
}
static void laa_unfill(void) { while (laa_npriv) VirtualFree((LPVOID)(ULONG_PTR)laa_priv[--laa_npriv], 0, MEM_RELEASE); }
static DWORD laa_shared_free(void)
{
    DWORD a = 0x80000000UL, fr = 0; MEMORY_BASIC_INFORMATION m;
    while (a < 0xC0000000UL && VirtualQuery((LPCVOID)(ULONG_PTR)a, &m, sizeof(m)) && m.RegionSize) {
        if (m.State == MEM_FREE) fr += (DWORD)m.RegionSize;
        a = (DWORD)(ULONG_PTR)m.BaseAddress + (DWORD)m.RegionSize;
    }
    return fr;
}
static DWORD laa_state(DWORD a) { MEMORY_BASIC_INFORMATION m; return VirtualQuery((LPCVOID)(ULONG_PTR)a, &m, sizeof(m)) ? m.State : 0; }
/* child: fill, take 4 blocks above 2 GB, write them to the file, then end the way it was told */
static int laa_child(const char *mode, const char *file)
{
    char dllpath[MAX_PATH], *bs; DWORD b[4], first; int i; FILE *f;
    GetModuleFileNameA(NULL, dllpath, MAX_PATH);
    if ((bs = strrchr(dllpath, '\\'))) { bs[1] = 0; strcat(dllpath, "kexnt.dll"); }
    if (!(kx = LoadLibraryA(dllpath)) || !laa_resolve()) return 11;
    {   typedef VOID (WINAPI *T_PNM)(void); T_PNM pnm = (T_PNM)GetProcAddress(kx, "KexPatchNtModules");
        if (pnm) pnm(); }                             /* NT 6+ program state, as in Chrome (api-ms shells do this) */
    if (!(first = laa_fill())) return 12;
    b[0] = first;
    for (i = 1; i < 4; i++) if (!(b[i] = (DWORD)(ULONG_PTR)lva(NULL, 0x200000, MEM_RESERVE, PAGE_NOACCESS)) || b[i] < 0x80000000UL) return 13;
    if (!lva((LPVOID)(ULONG_PTR)b[0], 0x100000, MEM_COMMIT, PAGE_READWRITE)) return 14;
    memset((void *)(ULONG_PTR)b[0], 0x77, 0x100000);
    if (!(f = fopen(file, "w"))) return 15;
    fprintf(f, "%08lx %08lx %08lx %08lx\n", b[0], b[1], b[2], b[3]); fclose(f);
    if (!strcmp(mode, "exit")) { lep(0); return 0; }
    if (!strcmp(mode, "selfterm")) { ltp(GetCurrentProcess(), 0); return 0; }
    if (!strcmp(mode, "crash")) {
        BYTE *r = (BYTE *)VirtualAlloc(NULL, 65536, MEM_RESERVE, PAGE_NOACCESS);
        SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
        *(volatile BYTE *)r = 1;
        return 16;
    }
    Sleep(60000);                                     /* "wait": the parent ends it */
    return 17;
}
static void laa_child_run(const char *mode)
{
    char exe[MAX_PATH], cmd[MAX_PATH * 2], tmp[MAX_PATH]; STARTUPINFOA si; PROCESS_INFORMATION pi;
    DWORD b[4] = {0, 0, 0, 0}, code = 99, t, w, freed = 0, ms = 0; int i, got = 0; FILE *f;
    GetModuleFileNameA(NULL, exe, MAX_PATH); GetTempPathA(MAX_PATH, tmp); strcat(tmp, "kxlaa.txt"); DeleteFileA(tmp);
    sprintf(cmd, "\"%s\" laachild %s %s", exe, mode, tmp);
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) { CHECK(0, "laachild %s: CreateProcess %lu", mode, GetLastError()); return; }
    for (t = 0; t < 600 && !got; t++) {
        if ((f = fopen(tmp, "r"))) { got = fscanf(f, "%lx %lx %lx %lx", &b[0], &b[1], &b[2], &b[3]) == 4; fclose(f); }
        if (!got && WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) break;
    }
    if (!got && (f = fopen(tmp, "r"))) {   /* build 124: the child may write the file and end between our two checks */
        got = fscanf(f, "%lx %lx %lx %lx", &b[0], &b[1], &b[2], &b[3]) == 4; fclose(f);
    }
    if (got && !strcmp(mode, "wait")) CHECK(ltp(pi.hProcess, 3), "laachild wait: ended by kexnt's TerminateProcess");
    w = WaitForSingleObject(pi.hProcess, 30000);
    if (w != WAIT_OBJECT_0) TerminateProcess(pi.hProcess, 9);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    CHECK(got, "laachild %s: its 4 blocks above 2 GB (exit code %lu)", mode, code);
    if (!got) return;
    for (ms = 0; ms <= 12000; ms += 250) {           /* kexnt frees them after the process has ended */
        for (freed = 0, i = 0; i < 4; i++) if (laa_state(b[i]) == MEM_FREE) freed++;
        if (freed == 4) break;
        Sleep(250);
    }
    LOG("    child %s (exit code %lu): blocks %08lx.. freed %lu of 4 after %lu ms\n", mode, code, b[0], freed, ms);
    CHECK(freed == 4, "laachild %s: its blocks above 2 GB freed after it ended (%lu of 4)", mode, freed);
}
static volatile LONG g_laa_churn_bad, g_laa_churn_ok;
static DWORD WINAPI laa_churn(LPVOID p)
{
    int i; (void)p;
    for (i = 0; i < 300; i++) {
        DWORD r = (DWORD)(ULONG_PTR)lva(NULL, 0x400000, MEM_RESERVE, PAGE_NOACCESS), al, q;
        if (r < 0x80000000UL) { if (r) VirtualFree((LPVOID)(ULONG_PTR)r, 0, MEM_RELEASE); continue; }
        al = (r + 0x1FFFFF) & ~0x1FFFFFUL;
        if (!lvf((LPVOID)(ULONG_PTR)r, 0, MEM_RELEASE)) { InterlockedIncrement(&g_laa_churn_bad); continue; }
        q = (DWORD)(ULONG_PTR)lva((LPVOID)(ULONG_PTR)al, 0x200000, MEM_RESERVE, PAGE_NOACCESS);
        if (!q) continue;
        if (lvf((LPVOID)(ULONG_PTR)q, 0, MEM_RELEASE)) InterlockedIncrement(&g_laa_churn_ok); else InterlockedIncrement(&g_laa_churn_bad);
        if (!(i & 7)) Sleep(0);
    }
    return 0;
}
static HANDLE g_laa_th[2];
static void laa_churn_run(void)                     /* resume the suspended churn threads, wait for them */
{
    int k;
    for (k = 0; k < 2; k++) if (g_laa_th[k]) ResumeThread(g_laa_th[k]);
    for (k = 0; k < 2; k++) if (g_laa_th[k]) { WaitForSingleObject(g_laa_th[k], 120000); CloseHandle(g_laa_th[k]); g_laa_th[k] = NULL; }
}
static void test_laa(void)
{
    BYTE *b = (BYTE *)GetModuleHandleA(NULL); IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + *(LONG *)(b + 0x3C));
    DWORD lent, r, q, fr0, fr1, i, bad, old; MEMORY_BASIC_INFORMATION m;
    LOG("[above 2 GB (large address aware)]\n");
    CHECK(nt->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE, "kextest.exe is large address aware");
    if (!laa_resolve()) { CHECK(0, "kexnt memory exports"); return; }
    {   typedef VOID (WINAPI *T_PNM)(void); T_PNM pnm = (T_PNM)GetProcAddress(kx, "KexPatchNtModules"); if (pnm) pnm(); }
    fr0 = laa_shared_free();
    /* build 132: the churn threads (below) are created now, suspended: once 2 GB is full there is no room left
     * for their 2 MB stacks (measured: CreateThread error 8, largest free block 4032 KB -> the churn never ran) */
    {   int k; DWORD id; g_laa_churn_bad = g_laa_churn_ok = 0;
        for (k = 0; k < 2; k++) g_laa_th[k] = CreateThread(NULL, 0, laa_churn, NULL, CREATE_SUSPENDED, &id); }
    lent = laa_fill();
    LOG("    %d blocks of 2 MB below 2 GB, then %08lx; shared arena free %lu MB before\n", laa_npriv, lent, fr0 >> 20);
    CHECK(lent >= 0x80000000UL && !(lent & 0x1FFFFF), "2 GB full: a 2 MB reservation lands above 2 GB, 2 MB aligned (%08lx)", lent);
    if (lent) {
        BYTE *p = (BYTE *)(ULONG_PTR)lent;
        BOOL committed = lva(p + 0x10000, 0x10000, MEM_COMMIT, PAGE_READWRITE) == p + 0x10000;
        CHECK(committed, "commit 64 KB inside it (error %lu)", committed ? 0 : GetLastError());
        if (!committed) { laa_unfill(); laa_churn_run(); return; }   /* build 131: writing to it now would only crash kextest */
        memset(p + 0x10000, 0x5A, 0x10000); for (bad = 0, i = 0; i < 0x10000; i++) if (p[0x10000 + i] != 0x5A) bad++;
        CHECK(bad == 0, "write/read in it (%lu wrong)", bad);
        CHECK(lva(p + 0x10000, 0x10000, 0x00080000, PAGE_READWRITE) == p + 0x10000 && p[0x10000] == 0, "MEM_RESET in it gives the pages back (%02x)", p[0x10000]);
        CHECK(lvp(p + 0x10000, 0x1000, PAGE_READONLY, &old), "VirtualProtect in it (%lu)", GetLastError());
        CHECK(lvf(p + 0x10000, 0x10000, MEM_DECOMMIT), "decommit in it (%lu)", GetLastError());
        VirtualQuery(p, &m, sizeof(m));
        CHECK(m.State == MEM_RESERVE && m.AllocationBase == p, "VirtualQuery: reserved, its own allocation (state %lx)", m.State);
        {   /* the small holes below 2 GB first take 256 KB blocks; the first one that does not fit goes up */
            static DWORD small[2000]; int ns = 0;
            for (;;) { r = (DWORD)(ULONG_PTR)lva(NULL, 0x40000, MEM_RESERVE, PAGE_NOACCESS);
                       if (!r || r >= 0x80000000UL || ns == 2000) break; small[ns++] = r; }
            LOG("    %d blocks of 256 KB still fitted below 2 GB\n", ns);
            while (ns) VirtualFree((LPVOID)(ULONG_PTR)small[--ns], 0, MEM_RELEASE);
        }
        CHECK(r >= 0x80000000UL && !(r & 0x3FFFF), "256 KB reservation above 2 GB, 256 KB aligned (%08lx)", r);
        if (r >= 0x80000000UL) CHECK(lvf((LPVOID)(ULONG_PTR)r, 0, MEM_RELEASE), "release the 256 KB block");
        r = (DWORD)(ULONG_PTR)lva(NULL, 64u << 20, MEM_RESERVE, PAGE_NOACCESS);
        CHECK(r == 0, "64 MB in one piece is not placed above 2 GB (%08lx)", r);
        if (r) lvf((LPVOID)(ULONG_PTR)r, 0, MEM_RELEASE);
        /* allocator retry: release a 4 MB block, then ask for 2 MB at an aligned address inside it */
        r = (DWORD)(ULONG_PTR)lva(NULL, 0x400000, MEM_RESERVE, PAGE_NOACCESS);
        if (r >= 0x80000000UL) {
            DWORD al = (r + 0x1FFFFF) & ~0x1FFFFFUL;
            CHECK(lvf((LPVOID)(ULONG_PTR)r, 0, MEM_RELEASE) && laa_state(r) == MEM_FREE, "release 4 MB block");
            q = (DWORD)(ULONG_PTR)lva((LPVOID)(ULONG_PTR)al, 0x200000, MEM_RESERVE, PAGE_NOACCESS);
            CHECK(q == al, "reservation at an aligned address up there (%08lx asked, %08lx got)", al, q);
            if (q) CHECK(lvf((LPVOID)(ULONG_PTR)q, 0, MEM_RELEASE), "release it");
        } else CHECK(0, "4 MB block above 2 GB (%08lx)", r);
        CHECK(!lvf((LPVOID)0xBFF70000, 0, MEM_RELEASE), "a Windows block up there is not ours to release");
        {   /* build 128: two threads doing PartitionAlloc's "reserve 4 MB, release, reserve 2 MB aligned inside, release"
             * at once. Build 127 removed the wrong thread's entry when both got the same address -> release refused */
            CHECK(g_laa_th[0] && g_laa_th[1], "two churn threads created before 2 GB was filled");
            laa_churn_run();
            LOG("    2 threads x 300 reserve/release rounds above 2 GB: %ld ok, %ld releases refused\n", g_laa_churn_ok, g_laa_churn_bad);
            CHECK(g_laa_churn_bad == 0 && g_laa_churn_ok > 0, "no release refused when two threads reuse the same addresses (%ld refused)", g_laa_churn_bad);
        }
        CHECK(lvf(p, 0, MEM_RELEASE) && laa_state(lent) == MEM_FREE, "release the first block: free again");
    }
    laa_unfill();
    laa_churn_run();                                /* not run when the 2 GB fill failed: let them end */
    fr1 = laa_shared_free();
    LOG("    shared arena free %lu MB after\n", fr1 >> 20);
    CHECK(fr1 + 0x100000 >= fr0, "shared arena back to where it was (%lu -> %lu KB)", fr0 >> 10, fr1 >> 10);
    /* blocks of processes that end: exit, end themselves (as Chrome's tabs do), are ended, crash */
    fr0 = laa_shared_free();
    laa_child_run("exit");
    laa_child_run("selfterm");
    laa_child_run("wait");
    laa_child_run("crash");
    fr1 = laa_shared_free();
    LOG("    shared arena free %lu MB before the children, %lu MB after\n", fr0 >> 20, fr1 >> 20);
    CHECK(fr1 + 0x100000 >= fr0, "no shared arena left behind by the children (%lu -> %lu KB)", fr0 >> 10, fr1 >> 10);
}

/* build 122: MEM_RESET / DiscardVirtualMemory give private pages back (decommit + commit: zero, still committed) */
/* build 124: installer functions (installer_ext.c) */
static void test_installer(void)
{
    typedef DWORD (WINAPI *T_QDDA)(LPCSTR, LPSTR, DWORD);
    typedef DWORD (WINAPI *T_QDDW)(LPCWSTR, LPWSTR, DWORD);
    typedef BOOL (WINAPI *T_NUMA)(PULONG);
    typedef UINT (WINAPI *T_WOW)(LPSTR, UINT);
    typedef ULONG (WINAPI *T_ST)(PVOID, LPCWSTR, PVOID);
    typedef ULONG (WINAPI *T_ETG)(PVOID *, ULONG, PULONG);
    typedef LONG (WINAPI *T_SD)(ULONG);
    typedef BOOLEAN (WINAPI *T_GCON)(int, LPWSTR, PULONG);
    typedef UINT (WINAPI *T_EPX)(LPCWSTR, LPCWSTR, DWORD, DWORD, WCHAR *, DWORD *, LPWSTR, LPDWORD);
    typedef struct { LPCWSTR data; int type; DWORD order; UINT status; } SEQ;
    typedef UINT (WINAPI *T_DPS)(LPCWSTR, LPCWSTR, DWORD, DWORD, SEQ *);
    T_QDDA qa = (T_QDDA)GetProcAddress(kx, "QueryDosDeviceA");
    T_QDDW qw = (T_QDDW)GetProcAddress(kx, "QueryDosDeviceW");
    T_NUMA numa = (T_NUMA)GetProcAddress(kx, "GetNumaHighestNodeNumber");
    T_WOW wow = (T_WOW)GetProcAddress(kx, "GetSystemWow64DirectoryA");
    T_ST st = (T_ST)GetProcAddress(kx, "StartTraceW");
    T_ETG etg = (T_ETG)GetProcAddress(kx, "EnumerateTraceGuids");
    T_SD sd = (T_SD)GetProcAddress(kx, "NtShutdownSystem");
    T_GCON gcon = (T_GCON)GetProcAddress(kx, "GetComputerObjectNameW");
    T_EPX epx = (T_EPX)GetProcAddress(kx, "MsiEnumProductsExW");
    T_DPS dps = (T_DPS)GetProcAddress(kx, "MsiDeterminePatchSequenceW");
    char b[512], c[8]; WCHAR w[128], code[39]; DWORD r, i; ULONG u = 99; SEQ seq[2]; BOOL has_c = FALSE;
    LOG("[installers]\n");
    CHECK(qa && qw && numa && wow && st && etg && sd && gcon && epx && dps, "installer functions exported by kexnt");
    if (!qa || !qw || !numa || !wow || !st || !etg || !sd || !gcon || !epx || !dps) return;
    r = qa("C:", b, sizeof(b));
    LOG("    QueryDosDevice(C:) = %lu \"%s\"\n", r, r ? b : "");
    CHECK(r == (DWORD)lstrlenA(b) + 2 && !strncmp(b, "\\Device\\HarddiskVolume", 22) && !b[r - 1],
          "QueryDosDeviceA(C:) -> \\Device\\HarddiskVolumeN, count includes both zeros");
    r = qa(NULL, b, sizeof(b));
    for (i = 0; r && i < r && b[i]; i += lstrlenA(b + i) + 1) if (!lstrcmpA(b + i, "C:")) has_c = TRUE;
    CHECK(r > 3 && has_c && !b[r - 1] && !b[r - 2], "QueryDosDeviceA(NULL) lists C: (%lu chars)", r);
    SetLastError(0); r = qa("QQ:", b, sizeof(b));
    CHECK(r == 0 && GetLastError() == ERROR_FILE_NOT_FOUND, "unknown device -> ERROR_FILE_NOT_FOUND (%lu)", GetLastError());
    SetLastError(0); r = qa("C:", c, sizeof(c));
    CHECK(r == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "small buffer -> ERROR_INSUFFICIENT_BUFFER (%lu)", GetLastError());
    r = qa("NUL", b, sizeof(b)); CHECK(r && !lstrcmpA(b, "\\Device\\Null"), "NUL -> \\Device\\Null");
    r = qa("COM2", b, sizeof(b)); CHECK(r && !lstrcmpA(b, "\\Device\\Serial1"), "COM2 -> \\Device\\Serial1");
    r = qw(L"c:", w, 128); CHECK(r > 2 && w[0] == L'\\' && w[r - 1] == 0, "QueryDosDeviceW(c:) (%lu)", r);
    CHECK(numa(&u) && u == 0, "GetNumaHighestNodeNumber -> node 0 (%lu)", u);
    SetLastError(0); r = wow(b, sizeof(b));
    CHECK(r == 0 && GetLastError() == ERROR_CALL_NOT_IMPLEMENTED, "GetSystemWow64DirectoryA: 32-bit Windows (%lu)", GetLastError());
    { char props[256]; ULONGLONG h = 0; memset(props, 0, sizeof(props));
      CHECK(st(&h, L"kextest", props) == ERROR_ACCESS_DENIED, "StartTraceW -> ERROR_ACCESS_DENIED"); }
    u = 5; CHECK(etg(NULL, 0, &u) == ERROR_SUCCESS && u == 0, "EnumerateTraceGuids lists none");
    CHECK(sd(7) == (LONG)0xC000000DL, "NtShutdownSystem(7) refused without shutting down");
    u = 128; CHECK(!gcon(1, w, &u) && GetLastError() == ERROR_CANT_ACCESS_DOMAIN_INFO, "GetComputerObjectNameW: not in a domain");
    r = epx(NULL, L"S-1-5-21-1", 7, 0, code, NULL, NULL, NULL);
    CHECK(r == ERROR_NO_MORE_ITEMS, "MsiEnumProductsExW for a user SID: none (%u)", r);
    r = epx(NULL, NULL, 4, 0, code, NULL, NULL, NULL);
    LOG("    MsiEnumProductsExW machine #0: %u\n", r);
    CHECK(r == ERROR_SUCCESS || r == ERROR_NO_MORE_ITEMS, "MsiEnumProductsExW machine context answered (%u)", r);
    {   typedef DWORD (WINAPI *T_GPPS)(LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, DWORD, LPCWSTR);
        T_GPPS gp = (T_GPPS)GetProcAddress(kx, "GetPrivateProfileStringW");
        WCHAR v[32]; FILE *f = fopen("C:\\KEXTEST\\KXINI.INI", "w");
        if (f) { fprintf(f, "[S]\nK0=abc\nK1=\n"); fclose(f); }
        CHECK(gp != NULL, "GetPrivateProfileStringW exported by kexnt");
        if (gp) {
            r = gp(L"S", L"K0", L"\n", v, 32, L"C:\\KEXTEST\\KXINI.INI");
            CHECK(r == 3 && !lstrcmpW(v, L"abc"), "INI: existing key (%lu)", r);
            r = gp(L"S", L"K1", L"\n", v, 32, L"C:\\KEXTEST\\KXINI.INI");
            CHECK(r == 0 && v[0] == 0, "INI: empty key stays empty (%lu)", r);
            r = gp(L"S", L"K9", L"\n", v, 32, L"C:\\KEXTEST\\KXINI.INI");
            CHECK(r == 1 && v[0] == L'\n', "INI: missing key returns the default \\n as on NT - NSIS 3 (%lu, %04x)", r, v[0]);
            r = gp(L"S", L"K9", L"dflt  ", v, 32, L"C:\\KEXTEST\\KXINI.INI");
            CHECK(r == 4 && !lstrcmpW(v, L"dflt"), "INI: trailing spaces of the default removed (%lu)", r);
            r = gp(L"S", L"K0", L"\n", v, 2, L"C:\\KEXTEST\\KXINI.INI");
            CHECK(r == 1 && v[0] == L'a' && v[1] == 0, "INI: truncated to the buffer (%lu)", r);
            r = gp(L"S", L"K9", L"\n", v, 32, L"C:\\KEXTEST\\NOFILE.INI");
            CHECK(r == 1 && v[0] == L'\n', "INI: missing file returns the default (%lu)", r);
        }
        DeleteFileA("C:\\KEXTEST\\KXINI.INI");
    }
    {   /* build 125: "\\?\" long-path prefix on CreateFile (VLC/Qt read loop) */
        typedef HANDLE (WINAPI *T_CFW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
        T_CFW cfw = (T_CFW)GetProcAddress(kx, "CreateFileW");
        FILE *f = fopen("C:\\KEXTEST\\KXLP.TXT", "w"); char rb[16]; DWORD g1 = 0, g2 = 9; HANDLE h;
        if (f) { fputs("abc", f); fclose(f); }
        h = cfw ? cfw(L"\\\\?\\C:\\KEXTEST\\KXLP.TXT", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL) : INVALID_HANDLE_VALUE;
        CHECK(h != INVALID_HANDLE_VALUE, "CreateFileW with the \\\\?\\ prefix opens the file");
        if (h != INVALID_HANDLE_VALUE) {
            ReadFile(h, rb, sizeof(rb), &g1, NULL); ReadFile(h, rb, sizeof(rb), &g2, NULL);
            CHECK(GetFileType(h) == FILE_TYPE_DISK && GetFileSize(h, NULL) == 3 && g1 == 3 && g2 == 0,
                  "\\\\?\\ file: disk type, size 3, then end of file (type %lu, size %lu, reads %lu %lu)", GetFileType(h), GetFileSize(h, NULL), g1, g2);
            CloseHandle(h);
        }
        DeleteFileA("C:\\KEXTEST\\KXLP.TXT");
    }
    {   /* build 125: FormatMessageW inserts as on NT (VS 2010 setup "%1!I64u!") */
        typedef DWORD (WINAPI *T_FM)(DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list *);
        T_FM fm = (T_FM)GetProcAddress(kx, "FormatMessageW");
        DWORD_PTR av[4]; WCHAR *ob = NULL, sb[64]; DWORD fr;
        CHECK(fm != NULL, "FormatMessageW exported by kexnt");
        if (fm) {
            av[0] = 1234567890; av[1] = 2; av[2] = (DWORD_PTR)L"C:"; av[3] = 0;   /* %1!I64u! = 2*2^32+1234567890 */
            SetLastError(0);
            fr = fm(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY,
                    L"%3 has %1!I64u! bytes%0", 0, 0, (LPWSTR)&ob, 0, (va_list *)av);
            CHECK(fr && ob && !lstrcmpW(ob, L"C: has 9824502482 bytes") && GetLastError() == 0,
                  "FormatMessageW %%1!I64u! (%lu, last error %lu)", fr, GetLastError());
            if (ob) LocalFree(ob);
            av[0] = 42; av[1] = 7;
            fr = fm(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY, L"[%1!04u!|%2!-3x!|%%]", 0, 0, sb, 64, (va_list *)av);
            LOG("    FormatMessageW width/flags: %lu \"%ls\"\n", fr, fr ? sb : L"");
            CHECK(fr == 12 && !lstrcmpW(sb, L"[0042|7  |%]"), "FormatMessageW width/flags (%lu)", fr);   /* 12 characters */
            fr = fm(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY, L"abcdef", 0, 0, sb, 3, (va_list *)av);
            CHECK(fr == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "FormatMessageW small buffer");
        }
    }
    {   /* build 125: what WiX Burn (VC++ 2013+ setups) needs */
        typedef DWORD (WINAPI *T_SEA)(ULONG, void *, void *, void **);
        typedef DWORD (WINAPI *T_SNSI)(LPWSTR, DWORD, DWORD, PVOID, PVOID, PVOID, PVOID);
        typedef BOOL (WINAPI *T_CAC)(ULONG_PTR *, LPCWSTR, LPCWSTR, DWORD, DWORD);
        typedef BOOL (WINAPI *T_CRC)(ULONG_PTR, DWORD);
        typedef UINT (WINAPI *T_SLX)(LPCWSTR, LPCWSTR, DWORD, DWORD, LPCWSTR, DWORD);
        T_SEA sea = (T_SEA)GetProcAddress(kx, "SetEntriesInAclW");
        T_SNSI snsi = (T_SNSI)GetProcAddress(kx, "SetNamedSecurityInfoW");
        T_CAC cac = (T_CAC)GetProcAddress(kx, "CryptAcquireContextW");
        T_SLX slx = (T_SLX)GetProcAddress(kx, "MsiSourceListAddSourceExW");
        T_CRC crc = (T_CRC)GetProcAddress(GetModuleHandleA("ADVAPI32.DLL"), "CryptReleaseContext");
        HMODULE msi = LoadLibraryA("MSI.DLL");
        CHECK(sea && snsi && cac && slx, "SetEntriesInAclW, SetNamedSecurityInfoW, CryptAcquireContextW, MsiSourceListAddSourceExW exported");
        if (sea && snsi) {
            static BYTE everyone[12] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
            struct { DWORD perm, mode, inherit; void *multi; DWORD mop, form, type; void *name; } ea[2];
            BYTE *acl = NULL; DWORD e;
            ZeroMemory(ea, sizeof(ea));
            ea[0].perm = 0x1F01FF; ea[0].mode = 2 /* SET_ACCESS */; ea[0].inherit = 3; ea[0].form = 0 /* TRUSTEE_IS_SID */; ea[0].name = everyone;
            ea[1].perm = 0x10000; ea[1].mode = 3 /* DENY_ACCESS */; ea[1].form = 0; ea[1].name = everyone;
            e = sea(2, ea, NULL, (void **)&acl);
            CHECK(e == 0 && acl && acl[0] == 2 && *(WORD *)(acl + 4) == 2 && acl[8] == 1 /* deny first */ && acl[8 + 1] == 0 &&
                  *(DWORD *)(acl + 8 + 4) == 0x10000 && acl[8 + 20] == 0 && acl[8 + 21] == 3 && *(WORD *)(acl + 2) == 8 + 2 * 20,
                  "SetEntriesInAclW builds an ACL (deny ACE first, %lu)", e);
            if (acl) LocalFree(acl);
            e = snsi(L"C:\\", 1 /* SE_FILE_OBJECT */, 4 /* DACL */, NULL, NULL, NULL, NULL);
            CHECK(e == 0, "SetNamedSecurityInfoW(C:\\) succeeds (%lu)", e);
            e = snsi(L"C:\\no such folder kx", 1, 4, NULL, NULL, NULL, NULL);
            CHECK(e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND, "SetNamedSecurityInfoW on a missing file fails (%lu)", e);
        }
        if (cac) {
            ULONG_PTR prov = 0; BOOL ok = cac(&prov, NULL, NULL, 1 /* PROV_RSA_FULL */, 0xF0000000UL | 0x40 /* VERIFYCONTEXT|SILENT */);
            CHECK(ok && prov, "CryptAcquireContextW(VERIFYCONTEXT|CRYPT_SILENT) works (%lu)", ok ? 0 : GetLastError());
            if (ok && crc) crc(prov, 0);
        }
        if (slx) {
            UINT u2 = slx(L"{00000000-0000-0000-0000-000000000000}", NULL, 4, 0x40000000UL | 1, L"C:\\", 0);
            CHECK(u2 == ERROR_UNKNOWN_PATCH, "MsiSourceListAddSourceExW(patch) -> ERROR_UNKNOWN_PATCH (%u)", u2);
            u2 = slx(L"{00000000-0000-0000-0000-000000000000}", NULL, 4, 1, L"C:\\", 0);
            CHECK(u2 == ERROR_UNKNOWN_PRODUCT || u2 == ERROR_BAD_CONFIGURATION, "MsiSourceListAddSourceExW(unknown product) -> %u", u2);
        }
        CHECK(msi == NULL || GetProcAddress(msi, "MsiSourceListAddSourceExW") != NULL, "GetProcAddress(msi.dll, MsiSourceListAddSourceExW) found");
        if (msi) FreeLibrary(msi);
    }
    {   /* build 126: UTF-16 INI files (NSIS 3 InstallOptions ioSpecial.ini) */
        typedef DWORD (WINAPI *T_GS)(LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, DWORD, LPCWSTR);
        typedef UINT (WINAPI *T_GI)(LPCWSTR, LPCWSTR, INT, LPCWSTR);
        typedef BOOL (WINAPI *T_WS)(LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
        T_GS gs = (T_GS)GetProcAddress(kx, "GetPrivateProfileStringW");
        T_GI gi = (T_GI)GetProcAddress(kx, "GetPrivateProfileIntW");
        T_WS ws = (T_WS)GetProcAddress(kx, "WritePrivateProfileStringW");
        char tp[MAX_PATH]; WCHAR wf[MAX_PATH], v[64]; HANDLE f; DWORD w2; BYTE head[2] = {0};
        static const WCHAR body[] = L"\xFEFF[Settings]\r\nNumFields=3\r\n[Field 1]\r\nType = bitmap \r\nLeft=\"0\"\r\n";
        CHECK(gs && gi && ws, "GetPrivateProfileIntW / WritePrivateProfileStringW exported by kexnt");
        GetTempPathA(MAX_PATH, tp); lstrcatA(tp, "kxuini.ini");
        MultiByteToWideChar(CP_ACP, 0, tp, -1, wf, MAX_PATH);
        f = CreateFileA(tp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) { WriteFile(f, body, sizeof(body) - sizeof(WCHAR), &w2, NULL); CloseHandle(f); }
        if (gs && gi && ws && f != INVALID_HANDLE_VALUE) {
            DWORD r = gs(L"field 1", L"TYPE", L"x", v, 64, wf);
            CHECK(r == 6 && !lstrcmpW(v, L"bitmap"), "UTF-16 INI: value read (%lu)", r);
            CHECK(gi(L"Settings", L"NumFields", 7, wf) == 3 && gi(L"Settings", L"Nope", 7, wf) == 7, "UTF-16 INI: GetPrivateProfileIntW");
            r = gs(L"Field 1", L"Left", L"x", v, 64, wf); CHECK(r == 1 && v[0] == L'0', "UTF-16 INI: quotes removed");
            CHECK(ws(L"Field 1", L"Text", L"C:\\a.bmp", wf) && ws(L"Field 2", L"Type", L"label", wf) && ws(L"Settings", L"NumFields", L"4", wf),
                  "UTF-16 INI: WritePrivateProfileStringW");
            r = gs(L"Field 1", L"Text", L"x", v, 64, wf);
            CHECK(r == 8 && !lstrcmpW(v, L"C:\\a.bmp") && gi(L"Settings", L"NumFields", 0, wf) == 4 &&
                  gs(L"Field 2", L"Type", L"", v, 64, wf) == 5, "UTF-16 INI: written values read back");
            r = gs(NULL, NULL, L"", v, 64, wf);
            CHECK(r == 25 && !lstrcmpW(v, L"Settings") && !lstrcmpW(v + 9, L"Field 1") && !lstrcmpW(v + 17, L"Field 2"), "UTF-16 INI: section list (%lu)", r);
            ws(L"Field 2", NULL, NULL, wf); ws(L"Field 1", L"Left", NULL, wf);
            CHECK(gs(L"Field 2", L"Type", L"d", v, 64, wf) == 1 && v[0] == L'd' && gs(L"Field 1", L"Left", L"d", v, 64, wf) == 1 && v[0] == L'd',
                  "UTF-16 INI: key and section deleted");
            f = CreateFileA(tp, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (f != INVALID_HANDLE_VALUE) { ReadFile(f, head, 2, &w2, NULL); CloseHandle(f); }
            CHECK(head[0] == 0xFF && head[1] == 0xFE, "UTF-16 INI: file still UTF-16");
        }
        DeleteFileA(tp);
    }
    {   /* build 126: activation contexts (Firefox 52 xul.dll), NTDLL present, RtlGetVersion */
        typedef HANDLE (WINAPI *T_CAC)(void *); typedef BOOL (WINAPI *T_AAC)(HANDLE, ULONG_PTR *);
        typedef BOOL (WINAPI *T_DAC)(DWORD, ULONG_PTR); typedef VOID (WINAPI *T_RAC)(HANDLE);
        typedef LONG (WINAPI *T_RGV)(OSVERSIONINFOW *);
        T_CAC cac = (T_CAC)GetProcAddress(kx, "CreateActCtxW"); T_AAC aac = (T_AAC)GetProcAddress(kx, "ActivateActCtx");
        T_DAC dac = (T_DAC)GetProcAddress(kx, "DeactivateActCtx"); T_RAC rac = (T_RAC)GetProcAddress(kx, "ReleaseActCtx");
        T_RGV rgv = (T_RGV)GetProcAddress(kx, "RtlGetVersion");
        CHECK(cac && aac && dac && rac && rgv, "CreateActCtxW / ActivateActCtx / DeactivateActCtx / ReleaseActCtx / RtlGetVersion exported");
        CHECK(GetModuleHandleA("ntdll") != NULL, "GetModuleHandle(ntdll) finds NTDLL in a modern process, as on NT");
        if (cac && aac && dac && rac) {
            DWORD ac[8] = { 32, 0, 0, 0, 0, 0, 0, 0 }; WCHAR mf[] = L"x.manifest"; HANDLE h; ULONG_PTR ck = 0;
            ac[2] = (DWORD)(ULONG_PTR)mf;
            h = cac(ac);
            CHECK(h && h != INVALID_HANDLE_VALUE && aac(h, &ck) && ck && dac(0, ck), "activation context created, activated, deactivated");
            if (h && h != INVALID_HANDLE_VALUE) rac(h);
        }
        if (rgv) {
            OSVERSIONINFOW v; OSVERSIONINFOA a; LONG st;
            ZeroMemory(&v, sizeof(v)); v.dwOSVersionInfoSize = sizeof(v); a.dwOSVersionInfoSize = sizeof(a);
            st = rgv(&v); GetVersionExA(&a);
            LOG("    RtlGetVersion %08lx: %lu.%lu.%lu, GetVersionExA %lu.%lu\n", st, v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber, a.dwMajorVersion, a.dwMinorVersion);
            CHECK(st == 0 && v.dwMajorVersion == a.dwMajorVersion && v.dwMinorVersion == a.dwMinorVersion, "RtlGetVersion = what GetVersionEx reports to this program");
        }
    }
    seq[0].data = L"x.msp"; seq[0].type = 0; seq[0].order = 5; seq[0].status = 0; seq[1] = seq[0];
    r = dps(L"{00000000-0000-0000-0000-000000000000}", NULL, 4, 2, seq);
    CHECK(r == ERROR_SUCCESS && seq[0].order == (DWORD)-1 && seq[1].status == ERROR_PATCH_TARGET_NOT_FOUND,
          "MsiDeterminePatchSequenceW: patches do not apply");
}

static void test_discard(void)
{
    typedef DWORD (WINAPI *T_DVM)(PVOID, SIZE_T);
    typedef LPVOID (WINAPI *T_VA)(LPVOID, SIZE_T, DWORD, DWORD);
    T_DVM dvm = (T_DVM)GetProcAddress(kx, "DiscardVirtualMemory");
    T_VA va = (T_VA)GetProcAddress(kx, "VirtualAlloc");
    BYTE *p; DWORD i, r, bad = 0; MEMORY_BASIC_INFORMATION m; LPVOID q;
    LOG("[discarded memory]\n");
    CHECK(dvm && va, "DiscardVirtualMemory / VirtualAlloc exported by kexnt");
    if (!dvm || !va) return;
    p = (BYTE *)VirtualAlloc(NULL, 0x100000, MEM_COMMIT, PAGE_READWRITE);
    CHECK(p != NULL, "1 MB committed");
    if (!p) return;
    memset(p, 0x5A, 0x100000);
    r = dvm(p + 0x800, 0x100000 - 0x800);
    CHECK(r == ERROR_SUCCESS, "DiscardVirtualMemory result %lu", r);
    for (i = 0; i < 0x1000; i++) if (p[i] != 0x5A) bad++;
    CHECK(bad == 0, "partial first page kept its contents (%lu changed)", bad);
    VirtualQuery(p + 0x1000, &m, sizeof(m));
    CHECK(m.State == MEM_COMMIT && m.Protect == PAGE_READWRITE, "discarded pages still committed, read-write (state %lx, protect %lx)", m.State, m.Protect);
    LOG("    after discard: second page byte %02x (00 = given back)\n", p[0x1000]);
    CHECK(p[0x1000] == 0 && p[0xFFFFF] == 0, "discarded pages read zero (%02x %02x)", p[0x1000], p[0xFFFFF]);
    p[0x2000] = 7; CHECK(p[0x2000] == 7, "discarded page writable");
    memset(p, 0x33, 0x100000);
    q = va(p, 0x100000, 0x00080000 /* MEM_RESET */, PAGE_READWRITE);
    CHECK(q == p, "VirtualAlloc(MEM_RESET) returns the address (%p)", q);
    VirtualQuery(p + 0x8000, &m, sizeof(m));
    CHECK(m.State == MEM_COMMIT && p[0x8000] == 0, "MEM_RESET pages committed and zero (state %lx, byte %02x)", m.State, p[0x8000]);
    q = va(p, 0x100000, 0x01000000 /* MEM_RESET_UNDO */, PAGE_READWRITE);
    CHECK(q == NULL, "MEM_RESET_UNDO after a real reset reports the data is gone (%p)", q);
    VirtualFree(p, 0, MEM_RELEASE);
}

/* build 131: "kextest only ... mods ..." - this process's module list (hang bisection: what differs between VMs) */
static void test_mods(void)
{
    HANDLE sn = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0); MODULEENTRY32 me; int n = 0;
    LOG("[modules]\n");
    if (sn == INVALID_HANDLE_VALUE) { LOG("    snapshot failed %lu\n", GetLastError()); return; }
    me.dwSize = sizeof(me);
    if (Module32First(sn, &me)) do {
        WIN32_FILE_ATTRIBUTE_DATA fa; SYSTEMTIME st; memset(&st, 0, sizeof(st)); fa.nFileSizeLow = 0;
        if (GetFileAttributesExA(me.szExePath, GetFileExInfoStandard, &fa)) FileTimeToSystemTime(&fa.ftLastWriteTime, &st);
        LOG("    mod %08lx %8lu %10lu %04u-%02u-%02u %s\n", (unsigned long)(DWORD_PTR)me.modBaseAddr, me.modBaseSize,
            fa.nFileSizeLow, st.wYear, st.wMonth, st.wDay, me.szExePath);
        n++;
    } while (Module32Next(sn, &me));
    CloseHandle(sn);
    LOG("    %d modules\n", n);
}

/* build 131: "only ... hangdump" - ask kexnt's hang watcher (hang_ext.c) for KEXHANG_kextest.LOG: every thread, now */
static void test_hangdump(void)
{
    HANDLE ev = OpenEventA(EVENT_MODIFY_STATE, FALSE, "KexNG_ThreadDump");
    LOG("[thread dump] %s\n", ev ? "asked kexnt for KEXHANG_kextest.LOG" : "no listener");
    if (ev) { PulseEvent(ev); CloseHandle(ev); Sleep(4000); }
}

/* build 131 hang hunt: "kextest dwstep N" - Windows 10 DWrite.dll in steps (1 load, 2 +factory, 3 +font collection,
 * 4 +FreeLibrary after 3), then a normal exit: which step leaves the process unable to finish ExitProcess */
static int dw_step(int n)
{
    typedef HRESULT (WINAPI *T_DCF)(DWRITE_FACTORY_TYPE, REFIID, IUnknown **);
    char path[MAX_PATH]; HMODULE h; T_DCF dcf; IDWriteFactory *f = NULL; IDWriteFontCollection *coll = NULL; HRESULT hr;
    g_log = fopen("kextest.log", "a");
    GetSystemDirectoryA(path, sizeof(path) - 16); lstrcatA(path, "\\DWRITE.DLL");
    h = LoadLibraryA(path);
    LOG("dwstep %d: LoadLibrary %p (error %lu)\n", n, (void *)h, h ? 0 : GetLastError());
    if (!h || n < 2) goto out;
    dcf = (T_DCF)(void *)GetProcAddress(h, "DWriteCreateFactory");
    hr = dcf ? dcf(DWRITE_FACTORY_TYPE_SHARED, &kIID_IDWriteFactory, (IUnknown **)&f) : E_FAIL;
    LOG("dwstep %d: factory %08lx\n", n, (unsigned long)hr);
    if (!f || n < 3) goto out;
    hr = IDWriteFactory_GetSystemFontCollection(f, &coll, FALSE);
    LOG("dwstep %d: font collection %08lx\n", n, (unsigned long)hr);
    if (coll) IDWriteFontCollection_Release(coll);
    IDWriteFactory_Release(f); f = NULL;
    if (n >= 4) { LOG("dwstep %d: FreeLibrary %d\n", n, FreeLibrary(h)); }
out:
    LOG("dwstep %d: exiting\n", n); fclose(g_log);
    return 0;
}

/* ---------------- build 131: the sandbox's restricted token (Firefox 115 content processes) ----------------
 * The same calls, in the same order, as Chromium's sandbox (Firefox esr115 security/sandbox/chromium:
 * restricted_token.cc GetRestrictedToken, acl.cc AddSidToDefaultDacl, restricted_token_utils.cc
 * SetTokenIntegrityLevel). Firefox's broker failed with SBOX_ERROR_CANNOT_CREATE_RESTRICTED_TOKEN (49). */
static void test_sbtoken(void)
{
    HANDLE tok = NULL, dup = NULL, rt = NULL, rt2 = NULL; DWORD len = 0, e; BOOL ok;
    BYTE ubuf[256]; TOKEN_DEFAULT_DACL *dd = NULL; PACL nd = NULL; PSID il = NULL, rsid = NULL;
    SID_AND_ATTRIBUTES deny[1], restr[1]; LUID_AND_ATTRIBUTES privs[1]; EXPLICIT_ACCESSW ea;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY, world = SECURITY_WORLD_SID_AUTHORITY;
    LOG("[sandbox token]\n");
#define SB(what, expr) do { SetLastError(0); ok = (expr); e = GetLastError(); LOG("    %-52s %s (error %lu)\n", what, ok ? "ok" : "FAILED", ok ? 0 : e); } while (0)
    SB("OpenProcessToken(TOKEN_ALL_ACCESS)", OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &tok));
    CHECK(ok, "OpenProcessToken %lu", e);
    if (!ok) return;
    SB("DuplicateHandle(token, SAME_ACCESS)", DuplicateHandle(GetCurrentProcess(), tok, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS));
    CHECK(ok, "DuplicateHandle of the token %lu", e);
    if (!dup) dup = tok;
    SB("GetTokenInformation(TokenUser)", GetTokenInformation(dup, TokenUser, ubuf, sizeof(ubuf), &len));
    CHECK(ok, "GetTokenInformation(TokenUser) %lu", e);
    AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &deny[0].Sid);
    deny[0].Attributes = SE_GROUP_USE_FOR_DENY_ONLY;
    AllocateAndInitializeSid(&nt, 1, SECURITY_RESTRICTED_CODE_RID, 0, 0, 0, 0, 0, 0, 0, &rsid);
    restr[0].Sid = rsid; restr[0].Attributes = 0;
    memset(privs, 0, sizeof(privs));
    SB("LookupPrivilegeValueW(SeChangeNotifyPrivilege)", LookupPrivilegeValueW(NULL, L"SeChangeNotifyPrivilege", &privs[0].Luid));
    SB("CreateRestrictedToken(1 deny, 0 privs, 1 restricting)", CreateRestrictedToken(dup, 0, 1, deny, 0, NULL, 1, restr, &rt));
    CHECK(ok && rt, "CreateRestrictedToken %lu", e);
    SB("DuplicateTokenEx(TokenPrimary)", DuplicateTokenEx(dup, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenPrimary, &rt2));
    CHECK(ok && rt2, "DuplicateTokenEx %lu", e);
    if (!rt) rt = rt2;
    if (!rt) return;
    len = 0; GetTokenInformation(rt, TokenDefaultDacl, NULL, 0, &len); e = GetLastError();
    LOG("    %-52s length %lu (error %lu)\n", "GetTokenInformation(TokenDefaultDacl, size query)", len, e);
    CHECK(len >= sizeof(TOKEN_DEFAULT_DACL), "TokenDefaultDacl size query gives a length (%lu)", len);
    if (len >= sizeof(TOKEN_DEFAULT_DACL) && (dd = (TOKEN_DEFAULT_DACL *)malloc(len))) {
        SB("GetTokenInformation(TokenDefaultDacl)", GetTokenInformation(rt, TokenDefaultDacl, dd, len, &len));
        CHECK(ok, "GetTokenInformation(TokenDefaultDacl) %lu", e);
        memset(&ea, 0, sizeof(ea));
        ea.grfAccessPermissions = GENERIC_ALL; ea.grfAccessMode = GRANT_ACCESS; ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID; ea.Trustee.ptstrName = (LPWSTR)rsid;
        SetLastError(0); e = SetEntriesInAclW(1, &ea, ok ? dd->DefaultDacl : NULL, &nd); ok = e == ERROR_SUCCESS;
        LOG("    %-52s %s (result %lu)\n", "SetEntriesInAclW(+restricted SID)", ok ? "ok" : "FAILED", e);
        CHECK(ok && nd, "SetEntriesInAclW %lu", e);
        if (nd) {
            TOKEN_DEFAULT_DACL nt2; nt2.DefaultDacl = nd;
            SB("SetTokenInformation(TokenDefaultDacl)", SetTokenInformation(rt, TokenDefaultDacl, &nt2, sizeof(nt2)));
            CHECK(ok, "SetTokenInformation(TokenDefaultDacl) %lu", e);
            LocalFree(nd);
        }
        free(dd);
    }
    SB("ConvertStringSidToSidW(S-1-16-4096 low integrity)", ConvertStringSidToSidW(L"S-1-16-4096", &il));
    CHECK(ok && il, "ConvertStringSidToSidW %lu", e);
    if (il) {
        BYTE lb[sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE]; TOKEN_MANDATORY_LABEL *lab = (TOKEN_MANDATORY_LABEL *)lb;
        lab->Label.Attributes = SE_GROUP_INTEGRITY; lab->Label.Sid = il;
        SB("SetTokenInformation(TokenIntegrityLevel)", SetTokenInformation(rt, TokenIntegrityLevel, lab, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(il)));
        CHECK(ok, "SetTokenInformation(TokenIntegrityLevel) %lu", e);
        LocalFree(il);
    }
    {   HANDLE h2 = NULL;
        SB("DuplicateHandle(new token, TOKEN_ALL_ACCESS)", DuplicateHandle(GetCurrentProcess(), rt, GetCurrentProcess(), &h2, TOKEN_ALL_ACCESS, FALSE, 0));
        CHECK(ok && h2, "DuplicateHandle of the restricted token %lu", e);
        if (h2) CloseHandle(h2);
    }
#undef SB
    FreeSid(deny[0].Sid); FreeSid(rsid);
    if (rt2 && rt2 != rt) CloseHandle(rt2);
    if (rt) CloseHandle(rt);
    if (dup != tok) CloseHandle(dup);
    CloseHandle(tok);
}

/* build 131: what a Windows 98 child started CREATE_SUSPENDED has in memory before it runs (Chromium sandbox:
 * GetProcessBaseAddress reads the child's PEB and EXE header, TransferVariable writes into its EXE) */
static void test_suspchild(void)
{
    STARTUPINFOA si; PROCESS_INFORMATION pi; char cmd[MAX_PATH + 16]; BYTE mz[2] = { 0, 0 }; DWORD got = 0, base, kxb;
    BYTE *me = (BYTE *)GetModuleHandleA(NULL); IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(me + *(LONG *)(me + 0x3C));
    LOG("[suspended child]\n");
    base = nt->OptionalHeader.ImageBase;
    GetModuleFileNameA(NULL, cmd, MAX_PATH); strcat(cmd, " sleeper");
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    {   typedef BOOL (WINAPI *T_CPA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
        T_CPA cpa = (T_CPA)GetProcAddress(kx, "CreateProcessA");    /* through kexnt, as an NT 6+ program's call goes */
        if (!cpa || !cpa(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) { CHECK(0, "CreateProcess suspended %lu", GetLastError()); return; } }
    SetLastError(0);
    {   BOOL ok = ReadProcessMemory(pi.hProcess, (LPCVOID)(ULONG_PTR)base, mz, 2, &got);
        LOG("    child EXE header at %08lx before it ran: %s, read %lu, '%c%c' (error %lu)\n", base, ok ? "readable" : "NOT readable", got, mz[0] ? mz[0] : '.', mz[1] ? mz[1] : '.', ok ? 0 : GetLastError()); }
    kxb = 0x6A000000UL;                                  /* the system kexnt.dll (KnownDLLs) */
    {   BYTE k2[2] = { 0, 0 }; BOOL ok; SetLastError(0); ok = ReadProcessMemory(pi.hProcess, (LPCVOID)(ULONG_PTR)kxb, k2, 2, &got);
        LOG("    child kexnt.dll at %08lx before it ran: %s '%c%c' (error %lu)\n", kxb, ok ? "readable" : "NOT readable", k2[0] ? k2[0] : '.', k2[1] ? k2[1] : '.', ok ? 0 : GetLastError()); }
    {   typedef LONG (WINAPI *T_NQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG); T_NQIP q = (T_NQIP)GetProcAddress(kx, "NtQueryInformationProcess");
        struct { LONG exit; PVOID peb; ULONG_PTR aff; LONG prio; ULONG_PTR pid, ppid; } b; LONG st = -1;
        memset(&b, 0, sizeof(b)); if (q) st = q(pi.hProcess, 0, &b, sizeof(b), NULL);
        LOG("    NtQueryInformationProcess(child, basic): status %08lx, PEB %p\n", (unsigned long)st, b.peb);
        if (b.peb) { BYTE pb[0x250]; BOOL ok = ReadProcessMemory(pi.hProcess, b.peb, pb, sizeof(pb), &got);
            LOG("    child PEB read: %s, ImageBaseAddress %08lx\n", ok ? "ok" : "FAILED", ok ? *(DWORD *)(pb + 8) : 0);
            CHECK(ok && *(DWORD *)(pb + 8) == base, "the child's PEB gives its EXE base"); }
        else CHECK(0, "a PEB address for the suspended child");
    }
    {   /* what Chromium's sandbox broker does next to the suspended child (interception.cc, win_utils.cc) */
        BYTE *rb, code[16]; DWORD old = 0, w = 0; BOOL ok; BYTE *gate = (BYTE *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenKey");
        SetLastError(0); rb = (BYTE *)VirtualAllocEx(pi.hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        LOG("    VirtualAllocEx(child) %p (error %lu)\n", (void *)rb, rb ? 0 : GetLastError());
        CHECK(rb != NULL, "VirtualAllocEx in the suspended child");
        if (rb) { memset(code, 0x90, sizeof(code)); ok = WriteProcessMemory(pi.hProcess, rb, code, sizeof(code), &w);
            LOG("    WriteProcessMemory(child, its new block) %s (error %lu)\n", ok ? "ok" : "FAILED", ok ? 0 : GetLastError()); CHECK(ok, "write into the child's new block"); }
        if (gate && ReadProcessMemory(pi.hProcess, gate, code, sizeof(code), &w)) {
            SetLastError(0); ok = VirtualProtectEx(pi.hProcess, gate, sizeof(code), PAGE_WRITECOPY, &old);
            LOG("    VirtualProtectEx(child NtOpenKey gate %p, WRITECOPY) %s old %08lx (error %lu)\n", (void *)gate, ok ? "ok" : "FAILED", old, ok ? 0 : GetLastError());
            CHECK(ok, "VirtualProtectEx on the child's code");
            {   /* does a write into the CHILD's code change OUR copy too (pages shared between processes)? */
                BYTE mod[16], mine = gate[15], back[16]; memcpy(mod, code, 16); mod[15] = (BYTE)(code[15] ^ 0x5A);
                SetLastError(0); ok = WriteProcessMemory(pi.hProcess, gate, mod, sizeof(mod), &w);
                LOG("    WriteProcessMemory(child code, 1 byte changed) %s (error %lu)\n", ok ? "ok" : "FAILED", ok ? 0 : GetLastError());
                CHECK(ok, "WriteProcessMemory into the child's code");
                ReadProcessMemory(pi.hProcess, gate, back, 16, &w);
                LOG("    child's copy now %02x (wrote %02x); OUR copy %02x (was %02x)\n", back[15], mod[15], gate[15], mine);
                CHECK(back[15] == mod[15], "the child's code changed");
                CHECK(gate[15] == mine, "our own code did NOT change (code pages are not shared between processes)");
                WriteProcessMemory(pi.hProcess, gate, code, sizeof(code), &w);
            }
            if (old) { ok = VirtualProtectEx(pi.hProcess, gate, sizeof(code), old, &old); CHECK(ok, "VirtualProtectEx restores (%lu)", ok ? 0 : GetLastError()); }
        } else CHECK(0, "the child's NtOpenKey gate readable");
    }
    ResumeThread(pi.hThread); Sleep(300);
    {   BYTE k3[2] = { 0, 0 }; BOOL ok = ReadProcessMemory(pi.hProcess, (LPCVOID)(ULONG_PTR)kxb, k3, 2, &got);
        LOG("    child kexnt.dll after 300 ms running: %s '%c%c'\n", ok ? "readable" : "NOT readable", k3[0] ? k3[0] : '.', k3[1] ? k3[1] : '.'); }
    TerminateProcess(pi.hProcess, 0); WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
}

/* build 131: NTDLL functions Chromium's sandbox patches in its children must start like an NT service stub
 * (service_resolver_32.cc: B8 id / BA x / FF D2 / C2 n) - kexnt's gates for them have that shape and still work */
static void test_svcshape(void)
{
    static const char *names[] = { "NtMapViewOfSection", "NtUnmapViewOfSection", "NtSetInformationThread",
        "NtOpenThreadToken", "NtOpenThreadTokenEx", "NtOpenThread", "NtOpenProcess", "NtOpenProcessToken",
        "NtOpenProcessTokenEx", "NtCreateFile", "NtOpenFile", "NtQueryAttributesFile", "NtQueryFullAttributesFile",
        "NtSetInformationFile", "NtCreateKey", "NtOpenKey", "NtOpenKeyEx", "NtCreateEvent", "NtOpenEvent",
        "NtCreateSection" };
    HMODULE nt = GetModuleHandleA("NTDLL.DLL"); int i, good = 0;
    LOG("[NT service stubs]\n");
    {   /* build 131: GetModuleHandle("ntdll.dll") in a modern program is kexnt's facade: its export table, read by hand as
         * Chromium's PEImage does, has kexnt's NTDLL functions; GetProcAddress / GetModuleFileName treat it as NTDLL */
        HMODULE f = GetModuleHandleW(L"ntdll.dll"); BYTE *b = (BYTE *)f; char fn[MAX_PATH] = "";
        FARPROC byhand = NULL, gpa = f ? GetProcAddress(f, "NtOpenKey") : NULL;
        if (b && *(WORD *)b == IMAGE_DOS_SIGNATURE) {
            IMAGE_NT_HEADERS32 *h = (IMAGE_NT_HEADERS32 *)(b + *(LONG *)(b + 0x3C));
            IMAGE_EXPORT_DIRECTORY *e = (IMAGE_EXPORT_DIRECTORY *)(b + h->OptionalHeader.DataDirectory[0].VirtualAddress);
            DWORD k;
            if (h->OptionalHeader.DataDirectory[0].VirtualAddress)
                for (k = 0; k < e->NumberOfNames; k++)
                    if (!strcmp((char *)(b + ((DWORD *)(b + e->AddressOfNames))[k]), "NtOpenKey")) {
                        byhand = (FARPROC)(b + ((DWORD *)(b + e->AddressOfFunctions))[((WORD *)(b + e->AddressOfNameOrdinals))[k]]); break; }
            LOG("    GetModuleHandle(ntdll.dll) %p: %lu exported names\n", (void *)f, h->OptionalHeader.DataDirectory[0].VirtualAddress ? e->NumberOfNames : 0);
        }
        CHECK(byhand && byhand == gpa, "NtOpenKey found by reading NTDLL's export table = GetProcAddress (%p, %p)", (void *)byhand, (void *)gpa);
        CHECK(f && GetProcAddress(f, "RtlNtStatusToDosError"), "GetProcAddress(GetModuleHandle(ntdll.dll), RtlNtStatusToDosError)");
        if (f) GetModuleFileNameA(f, fn, sizeof(fn));
        CHECK(strstr(fn, "NTDLL") || strstr(fn, "ntdll"), "GetModuleFileName(GetModuleHandle(ntdll.dll)) = %s", fn);
        nt = f ? f : nt;
        {   /* every NTDLL function Chromium's sandbox resolves by reading the export table (policy_broker.cc InitGlobalNt) */
            static const char *gnt[] = { "NtAllocateVirtualMemory", "NtClose", "NtDuplicateObject", "NtFreeVirtualMemory",
                "NtMapViewOfSection", "NtProtectVirtualMemory", "NtQueryInformationProcess", "NtQueryObject", "NtQuerySection",
                "NtQueryVirtualMemory", "NtUnmapViewOfSection", "NtSignalAndWaitForSingleObject", "NtWaitForSingleObject",
                "RtlAllocateHeap", "RtlAnsiStringToUnicodeString", "RtlCompareUnicodeString", "RtlCreateHeap",
                "RtlCreateUserThread", "RtlDestroyHeap", "RtlFreeHeap", "_strnicmp", "strlen", "wcslen", "memcpy" };
            int g, found = 0;
            for (g = 0; g < (int)(sizeof(gnt) / sizeof(gnt[0])) && b; g++) {
                IMAGE_NT_HEADERS32 *h2 = (IMAGE_NT_HEADERS32 *)(b + *(LONG *)(b + 0x3C));
                IMAGE_EXPORT_DIRECTORY *e2 = (IMAGE_EXPORT_DIRECTORY *)(b + h2->OptionalHeader.DataDirectory[0].VirtualAddress);
                DWORD k; int hit = 0;
                for (k = 0; k < e2->NumberOfNames && !hit; k++) hit = !strcmp((char *)(b + ((DWORD *)(b + e2->AddressOfNames))[k]), gnt[g]);
                if (!hit) LOG("    sandbox NTDLL import %s: not in the export table\n", gnt[g]);
                found += hit;
            }
            CHECK(found == (int)(sizeof(gnt) / sizeof(gnt[0])), "all %d NTDLL functions Chromium's sandbox imports are in the export table (%d)", (int)(sizeof(gnt) / sizeof(gnt[0])), found);
        }
    }
    if (!nt) { CHECK(0, "NTDLL.DLL loaded"); return; }
    for (i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++) {
        BYTE *f = NULL, *b = (BYTE *)nt;
        if (b && *(WORD *)b == IMAGE_DOS_SIGNATURE) {   /* by hand, as Chromium's PEImage::GetProcAddress */
            IMAGE_NT_HEADERS32 *h = (IMAGE_NT_HEADERS32 *)(b + *(LONG *)(b + 0x3C)); DWORD rva = h->OptionalHeader.DataDirectory[0].VirtualAddress, k;
            IMAGE_EXPORT_DIRECTORY *e = (IMAGE_EXPORT_DIRECTORY *)(b + rva);
            if (rva) for (k = 0; k < e->NumberOfNames; k++)
                if (!strcmp((char *)(b + ((DWORD *)(b + e->AddressOfNames))[k]), names[i])) {
                    f = b + ((DWORD *)(b + e->AddressOfFunctions))[((WORD *)(b + e->AddressOfNameOrdinals))[k]]; break; }
        }
        BOOL ok = f && f[0] == 0xB8 && f[5] == 0xBA && f[10] == 0xFF && f[11] == 0xD2 && f[12] == 0xC2;
        if (!ok) LOG("    %s: %s\n", names[i], f ? "not shaped like a service stub" : "not found");
        CHECK(ok, "%s starts like an NT service stub", names[i]);
        good += ok;
    }
    LOG("    %d of %d shaped like NT service stubs\n", good, (int)(sizeof(names) / sizeof(names[0])));
    {   typedef LONG (WINAPI *T_OPT)(HANDLE, ACCESS_MASK, PHANDLE); T_OPT opt = (T_OPT)GetProcAddress(nt, "NtOpenProcessToken");
        HANDLE t = NULL; LONG st = opt ? opt(GetCurrentProcess(), TOKEN_QUERY, &t) : -1;
        CHECK(st == 0 && t, "NtOpenProcessToken through its stub (status %08lx)", (unsigned long)st);
        if (t) CloseHandle(t); }
    {   typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } US;
        typedef struct { ULONG Length; HANDLE RootDirectory; US *ObjectName; ULONG Attributes; PVOID sd, sqos; } OA;
        typedef LONG (WINAPI *T_OK)(PHANDLE, ACCESS_MASK, OA *); T_OK ok = (T_OK)GetProcAddress(nt, "NtOpenKey");
        static WCHAR path[] = L"\\Registry\\Machine\\Software"; US u; OA oa; HANDLE k = NULL; LONG st = -1;
        u.Buffer = path; u.Length = (USHORT)(lstrlenW(path) * 2); u.MaximumLength = u.Length + 2;
        memset(&oa, 0, sizeof(oa)); oa.Length = sizeof(oa); oa.ObjectName = &u; oa.Attributes = 0x40;
        if (ok) st = ok(&k, KEY_READ, &oa);
        CHECK(st == 0 && k, "NtOpenKey(\\Registry\\Machine\\Software) through its stub (status %08lx)", (unsigned long)st);
        if (k) RegCloseKey((HKEY)k); }
}

/* build 131: NT file / object functions kexnt added for Chromium's sandbox (also used by NT programs directly) */
static void test_ntobj(void)
{
    typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } US;
    typedef struct { ULONG Length; HANDLE RootDirectory; US *ObjectName; ULONG Attributes; PVOID sd, sqos; } OA;
    typedef struct { LONG Status; ULONG_PTR Information; } IOSB;
    typedef LONG (WINAPI *T_NCF)(PHANDLE, ACCESS_MASK, OA *, IOSB *, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    typedef LONG (WINAPI *T_NQF)(OA *, PVOID);
    typedef LONG (WINAPI *T_NSI)(HANDLE, IOSB *, PVOID, ULONG, ULONG);
    typedef LONG (WINAPI *T_NCE)(PHANDLE, ACCESS_MASK, OA *, ULONG, BOOLEAN);
    typedef LONG (WINAPI *T_NOE)(PHANDLE, ACCESS_MASK, OA *);
    typedef LONG (WINAPI *T_NCS)(PHANDLE, ACCESS_MASK, OA *, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    typedef LONG (WINAPI *T_NOP)(PHANDLE, ACCESS_MASK, OA *, PVOID);
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    T_NCF ncf = (T_NCF)GetProcAddress(nt, "NtCreateFile"); T_NQF nqf = (T_NQF)GetProcAddress(nt, "NtQueryFullAttributesFile");
    T_NSI nsi = (T_NSI)GetProcAddress(nt, "NtSetInformationFile"); T_NCE nce = (T_NCE)GetProcAddress(nt, "NtCreateEvent");
    T_NOE noe = (T_NOE)GetProcAddress(nt, "NtOpenEvent"); T_NCS ncs = (T_NCS)GetProcAddress(nt, "NtCreateSection");
    T_NOP nop = (T_NOP)GetProcAddress(nt, "NtOpenProcess"), nth = (T_NOP)GetProcAddress(nt, "NtOpenThread");
    WCHAR tmp[MAX_PATH], path[MAX_PATH + 8]; US u; OA oa; IOSB io; HANDLE h = NULL, h2 = NULL; LONG st; BYTE info[64];
    LOG("[NT files and objects]\n");
    if (!ncf || !nqf || !nsi || !nce || !noe || !ncs || !nop || !nth) { CHECK(0, "NT file/object functions exported"); return; }
    {   char a[MAX_PATH]; GetTempPathA(MAX_PATH, a); lstrcatA(a, "kxntobj.tmp"); DeleteFileA(a);
        MultiByteToWideChar(CP_ACP, 0, a, -1, tmp, MAX_PATH); }
    lstrcpyW(path, L"\\??\\"); lstrcatW(path, tmp);
    u.Buffer = path; u.Length = (USHORT)(lstrlenW(path) * 2); u.MaximumLength = u.Length + 2;
    memset(&oa, 0, sizeof(oa)); oa.Length = sizeof(oa); oa.ObjectName = &u; oa.Attributes = 0x40;
    st = ncf(&h, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, 0, 3 /* OPEN_IF */, 0x20 /* SYNC_NONALERT */, NULL, 0);
    CHECK(st == 0 && h && io.Information == 2, "NtCreateFile creates a file (status %08lx, info %lu)", (unsigned long)st, (unsigned long)io.Information);
    if (h) {
        LONGLONG eof = 12345; BYTE del = 1;
        st = nsi(h, &io, &eof, 8, 20 /* FileEndOfFileInformation */);
        CHECK(st == 0, "NtSetInformationFile(end of file) %08lx", (unsigned long)st);
        CloseHandle(h); h = NULL;
        st = nqf(&oa, info);
        CHECK(st == 0 && *(DWORD *)(info + 40) == 12345, "NtQueryFullAttributesFile size %lu (status %08lx)", st ? 0 : *(DWORD *)(info + 40), (unsigned long)st);
        st = ncf(&h, DELETE | SYNCHRONIZE, &oa, &io, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 3, 0x20, NULL, 0);
        CHECK(st == 0 && io.Information == 1, "NtCreateFile opens it again (status %08lx, info %lu)", (unsigned long)st, (unsigned long)io.Information);
        if (h) {
            st = nsi(h, &io, &del, 1, 13 /* FileDispositionInformation */);
            CHECK(st == 0, "NtSetInformationFile(delete on close) %08lx", (unsigned long)st);
            CloseHandle(h); h = NULL;
        }
        CHECK(nqf(&oa, info) != 0, "the file is gone after the delete-on-close handle closed");
    }
    {   static WCHAR en[] = L"\\BaseNamedObjects\\KxNtObjTest"; US eu; OA eo; LONG st2;
        eu.Buffer = en; eu.Length = (USHORT)(lstrlenW(en) * 2); eu.MaximumLength = eu.Length + 2;
        memset(&eo, 0, sizeof(eo)); eo.Length = sizeof(eo); eo.ObjectName = &eu;
        st = nce(&h, EVENT_ALL_ACCESS, &eo, 0, FALSE);
        st2 = h ? nce(&h2, EVENT_ALL_ACCESS, &eo, 0, FALSE) : -1;
        CHECK(st == 0 && h, "NtCreateEvent(\\BaseNamedObjects\\...) %08lx", (unsigned long)st);
        CHECK(st2 == 0x40000000L, "a second NtCreateEvent says OBJECT_NAME_EXISTS (%08lx)", (unsigned long)st2);
        if (h2) CloseHandle(h2), h2 = NULL;
        st = noe(&h2, EVENT_ALL_ACCESS, &eo);
        CHECK(st == 0 && h2, "NtOpenEvent finds it (%08lx)", (unsigned long)st);
        if (h && h2) { SetEvent(h2); CHECK(WaitForSingleObject(h, 0) == WAIT_OBJECT_0, "the opened event is the same object"); }
        if (h2) CloseHandle(h2), h2 = NULL;
        if (h) CloseHandle(h), h = NULL;
    }
    {   static WCHAR sn[] = L"\\BaseNamedObjects\\KxNtSecTest"; US su; OA so; LARGE_INTEGER mx; BYTE *v;
        su.Buffer = sn; su.Length = (USHORT)(lstrlenW(sn) * 2); su.MaximumLength = su.Length + 2;
        memset(&so, 0, sizeof(so)); so.Length = sizeof(so); so.ObjectName = &su; mx.QuadPart = 65536;
        st = ncs(&h, SECTION_ALL_ACCESS, &so, &mx, PAGE_READWRITE, SEC_COMMIT, NULL);
        CHECK(st == 0 && h, "NtCreateSection(named, 64 KB) %08lx", (unsigned long)st);
        if (h && (v = (BYTE *)MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, 0))) { v[100] = 0x5A; CHECK(v[100] == 0x5A, "section view writable"); UnmapViewOfFile(v); }
        if (h) CloseHandle(h), h = NULL;
    }
    {   struct { HANDLE p, t; } cid; cid.p = (HANDLE)(ULONG_PTR)GetCurrentProcessId(); cid.t = NULL;
        memset(&oa, 0, sizeof(oa)); oa.Length = sizeof(oa);
        st = nop(&h, PROCESS_QUERY_INFORMATION, &oa, &cid);
        CHECK(st == 0 && h, "NtOpenProcess(own id) %08lx", (unsigned long)st);
        if (h) CloseHandle(h), h = NULL;
        cid.p = NULL; cid.t = (HANDLE)(ULONG_PTR)GetCurrentThreadId();
        st = nth(&h, THREAD_QUERY_INFORMATION, &oa, &cid);
        CHECK(st == 0 && h, "NtOpenThread(own id) %08lx", (unsigned long)st);
        if (h) CloseHandle(h), h = NULL;
    }
}

/* build 131: the mitigations a Chromium-sandbox child applies to itself when it lowers its token
 * (process_mitigations.cc ApplyProcessMitigationsToCurrentProcess; failure = exit 7011 SBOX_FATAL_MITIGATION) */
static void test_mitig(void)
{
    typedef BOOL (WINAPI *T_SDD)(DWORD); typedef BOOL (WINAPI *T_DEP)(DWORD);
    HMODULE k32 = GetModuleHandleA("kernel32.dll"); T_SDD sdd = (T_SDD)GetProcAddress(k32, "SetDefaultDllDirectories");
    T_DEP dep = (T_DEP)GetProcAddress(k32, "SetProcessDEPPolicy"); HANDLE tok = NULL; DWORD need = 0, e; BOOL ok;
    LOG("[sandbox mitigations]\n");
#define MG(what, expr) do { SetLastError(0); ok = (expr); e = GetLastError(); LOG("    %-56s %s (error %lu)\n", what, ok ? "ok" : "FAILED", ok ? 0 : e); } while (0)
    if (sdd) { MG("SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)", sdd(0x1000)); CHECK(ok || e == ERROR_ACCESS_DENIED, "SetDefaultDllDirectories %lu", e); }
    else LOG("    SetDefaultDllDirectories not exported (the sandbox skips it)\n");
    MG("HeapSetInformation(NULL, HeapEnableTerminationOnCorruption)", HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0));
    CHECK(ok || e == ERROR_ACCESS_DENIED, "HeapSetInformation(terminate on corruption) %lu", e);
    MG("OpenProcessToken(READ_CONTROL | WRITE_OWNER)", OpenProcessToken(GetCurrentProcess(), READ_CONTROL | WRITE_OWNER, &tok));
    CHECK(ok, "OpenProcessToken(READ_CONTROL|WRITE_OWNER) %lu", e);
    if (tok) {
        BYTE *sd = NULL; PACL sacl = NULL; BOOL present = FALSE, def = FALSE;
        SetLastError(0); GetKernelObjectSecurity(tok, LABEL_SECURITY_INFORMATION, NULL, 0, &need); e = GetLastError();
        LOG("    %-56s length %lu (error %lu)\n", "GetKernelObjectSecurity(token, LABEL, size query)", need, e);
        CHECK(e == ERROR_INSUFFICIENT_BUFFER && need, "GetKernelObjectSecurity size query (%lu, %lu)", need, e);
        if (need && (sd = (BYTE *)malloc(need))) {
            MG("GetKernelObjectSecurity(token, LABEL)", GetKernelObjectSecurity(tok, LABEL_SECURITY_INFORMATION, sd, need, &need));
            CHECK(ok, "GetKernelObjectSecurity %lu", e);
            if (ok) { MG("GetSecurityDescriptorSacl", GetSecurityDescriptorSacl(sd, &present, &sacl, &def)); CHECK(ok, "GetSecurityDescriptorSacl %lu", e);
                      LOG("    SACL present %d, %u ACEs\n", present, sacl ? sacl->AceCount : 0);
                      MG("SetKernelObjectSecurity(token, LABEL)", SetKernelObjectSecurity(tok, LABEL_SECURITY_INFORMATION, sd)); CHECK(ok || e == ERROR_ACCESS_DENIED, "SetKernelObjectSecurity %lu", e); }
            free(sd);
        }
        CloseHandle(tok);
    }
    if (dep) { MG("SetProcessDEPPolicy(PROCESS_DEP_ENABLE | DISABLE_ATL_THUNK)", dep(3)); CHECK(ok || e == ERROR_ACCESS_DENIED, "SetProcessDEPPolicy %lu", e); }
    else { LOG("    SetProcessDEPPolicy not exported\n"); CHECK(0, "SetProcessDEPPolicy exported"); }
#undef MG
}

/* build 131: process ids as NT shows them (pid_ext.c) - every source agrees, all below 2^31 (Firefox reads its
 * parent's id back with strtol: Windows 98's 0xFFFxxxxx ids saturated to 0x7FFFFFFF) */
static void test_pids(void)
{
    typedef LONG (WINAPI *T_NQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    DWORD me = GetCurrentProcessId(), v; char buf[32]; HANDLE s; PROCESSENTRY32 pe; MODULEENTRY32 mo; BOOL found = FALSE;
    LOG("[process ids as NT shows them]\n");
    LOG("    GetCurrentProcessId %08lx\n", me);
    CHECK(me && me < 0x80000000UL, "process id below 2^31 (%08lx)", me);
    sprintf(buf, "%lu", me); v = (DWORD)strtol(buf, NULL, 10);
    CHECK(v == me, "printf %%lu + strtol gives the id back (%08lx)", v);
    v = GetProcessId(GetCurrentProcess()); CHECK(v == me, "GetProcessId(GetCurrentProcess()) %08lx", v);
    {   typedef DWORD (WINAPI *T_GPT)(HANDLE); T_GPT g = (T_GPT)GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "GetProcessIdOfThread");
        v = g ? g(GetCurrentThread()) : 0; CHECK(v == me, "GetProcessIdOfThread(GetCurrentThread()) %08lx", v); }
    {   T_NQIP q = (T_NQIP)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
        struct { LONG exit; PVOID peb; ULONG_PTR aff; LONG prio; ULONG_PTR pid, ppid; } b; memset(&b, 0, sizeof(b));
        if (q) q(GetCurrentProcess(), 0, &b, sizeof(b), NULL);
        CHECK(b.pid == me, "NtQueryInformationProcess UniqueProcessId %08lx", (unsigned long)b.pid); }
    s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); pe.dwSize = sizeof(pe);
    if (s != INVALID_HANDLE_VALUE) { if (Process32First(s, &pe)) do if (pe.th32ProcessID == me) found = TRUE; while (Process32Next(s, &pe)); CloseHandle(s); }
    if (!found) { s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); pe.dwSize = sizeof(pe);
        if (s != INVALID_HANDLE_VALUE) { if (Process32First(s, &pe)) do LOG("      toolhelp process %08lx parent %08lx %s\n", pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile); while (Process32Next(s, &pe)); CloseHandle(s); } }
    CHECK(found, "Toolhelp lists this process under the same id");
    s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, me); mo.dwSize = sizeof(mo);
    CHECK(s != INVALID_HANDLE_VALUE && Module32First(s, &mo) && mo.th32ProcessID == me, "Toolhelp module snapshot of this id (%08lx)", s != INVALID_HANDLE_VALUE ? mo.th32ProcessID : 0);
    if (s != INVALID_HANDLE_VALUE) CloseHandle(s);
    {   HWND w = CreateWindowA("STATIC", "kxpid", 0, 0, 0, 1, 1, NULL, NULL, NULL, NULL); DWORD wp = 0;
        if (w) { GetWindowThreadProcessId(w, &wp); DestroyWindow(w); }
        CHECK(wp == me, "GetWindowThreadProcessId of our window %08lx", wp); }
    {   STARTUPINFOA si; PROCESS_INFORMATION pi; char cmd[MAX_PATH + 16]; HANDLE h;
        GetModuleFileNameA(NULL, cmd, MAX_PATH); strcat(cmd, " sleeper");
        memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
        if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            CHECK(pi.dwProcessId < 0x80000000UL && pi.dwProcessId == GetProcessId(pi.hProcess), "child id from CreateProcess = GetProcessId(handle) (%08lx, %08lx)", pi.dwProcessId, GetProcessId(pi.hProcess));
            found = FALSE; s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); pe.dwSize = sizeof(pe);
            if (s != INVALID_HANDLE_VALUE) { if (Process32First(s, &pe)) do if (pe.th32ProcessID == pi.dwProcessId && pe.th32ParentProcessID == me) found = TRUE; while (Process32Next(s, &pe)); CloseHandle(s); }
            CHECK(found, "Toolhelp: the child under its id, with us as parent");
            h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pi.dwProcessId);
            CHECK(h != NULL, "OpenProcess(the child's id) %lu", h ? 0 : GetLastError());
            if (h) CloseHandle(h);
            TerminateProcess(pi.hProcess, 0); WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        } else CHECK(0, "CreateProcess(sleeper) %lu", GetLastError());
    }
}

/* build 131: "kextest only NAME... [nopause]" runs the named tests in that order (hang bisection) */
static const struct { const char *n; void (*f)(void); } g_only[] = {
    { "srw", test_srw },
    { "cv", test_cv },
    { "wait_on_address", test_wait_on_address },
    { "init_once", test_init_once },
    { "fls", test_fls },
    { "sysinfo", test_sysinfo },
    { "locale", test_locale },
    { "veh", test_veh },
    { "versions", test_versions },
    { "chromium", test_chromium },
    { "ntreg", test_ntreg },
    { "svcshape", test_svcshape },
    { "ntobj", test_ntobj },
    { "mitig", test_mitig },
    { "pids", test_pids },
    { "shm", test_shm },
    { "stubs", test_stubs },
    { "spawn", test_spawn },
    { "pipes", test_pipes },
    { "lockfile", test_lockfile },
    { "dirhandle", test_dirhandle },
    { "iocp", test_iocp },
    { "waits", test_waits },
    { "layered", test_layered },
    { "layeredx", test_layered_xthread },
    { "assocreg", test_assocreg },
    { "spi", test_spi },
    { "fontmem", test_fontmem },
    { "gdiguard", test_gdiguard },
    { "dns", test_dns },
    { "tls_dll", test_tls_dll },
    { "dwrite", test_dwrite },
    { "coreaudio", test_coreaudio },
    { "capture", test_capture },
    { "adapters", test_adapters },
    { "ntldr", test_ntldr },
    { "vq_image", test_vq_image },
    { "tpwork", test_tpwork },
    { "opengl", test_opengl },
    { "draw_speed", test_draw_speed },
    { "glass", test_glass },
    { "gl_keepback", test_gl_keepback },
    { "clipboard", test_clipboard },
    { "handle_path", test_handle_path },
    { "positional_io", test_positional_io },
    { "zero_grow", test_zero_grow },
    { "datafile_res", test_datafile_res },
    { "ro_share", test_ro_share },
    { "gate", test_gate },
    { "simd_state", test_simd_state },
    { "cpu_avx", test_cpu_avx },
    { "alias_dirty", test_alias_dirty },
    { "dead_dup", test_dead_dup },
    { "pipe_stream", test_pipe_stream },
    { "jobs", test_jobs },
    { "file_dialog", test_file_dialog },
    { "file_dialog2", test_file_dialog2 },
    { "memory_status", test_memory_status },
    { "msgwait", test_msgwait },
    { "discard", test_discard },
    { "laa", test_laa },
    { "installer", test_installer },
    { "mods", test_mods },
    { "sbtoken", test_sbtoken },
    { "suspchild", test_suspchild },
    { "hangdump", test_hangdump },
};

int main(int argc, char **argv)
{
    OSVERSIONINFOA vi;
    int i;
    if (argc > 1 && !strcmp(argv[1], "tlschild")) return tls_child();
    if (argc > 2 && !strcmp(argv[1], "dwstep")) return dw_step(atoi(argv[2]));
    if (argc > 2 && !strcmp(argv[1], "loadlib")) {   /* build 131 hang hunt: LoadLibrary each named DLL, then exit */
        int j; g_log = fopen("kextest.log", "a");
        for (j = 2; j < argc; j++) { HMODULE h = LoadLibraryA(argv[j]); LOG("loadlib %s: %p (error %lu)\n", argv[j], (void *)h, h ? 0 : GetLastError()); }
        LOG("loadlib: exiting\n"); fclose(g_log); return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "sleeper")) { Sleep(60000); return 0; }
    if (argc > 1 && (!strcmp(argv[1], "dwrite") || !strcmp(argv[1], "dwritekx"))) {   /* [DirectWrite] alone */
        g_log = fopen("kextest_dwrite.log", "w");
        if (!strcmp(argv[1], "dwritekx")) {               /* with kextest's own kexnt.dll copy loaded first */
            char dllpath[MAX_PATH], *bs;
            GetModuleFileNameA(NULL, dllpath, MAX_PATH);
            if ((bs = strrchr(dllpath, '\\'))) { bs[1] = 0; strcat(dllpath, "kexnt.dll"); }
            kx = LoadLibraryA(dllpath);
            LOG("kexnt copy %p\n", (void *)kx);
        }
        test_dwrite();
        LOG("\n%d passed, %d failed\n", g_pass, g_fail);
        return g_fail;
    }
    if (argc > 2 && !strcmp(argv[1], "offtry")) return off_try(argv[2]);
    if (argc > 1 && !strcmp(argv[1], "fileoffs")) {     /* writes ~300 MB files to %TEMP% */
        for (i = 2; i < argc; i++) if (!strcmp(argv[i], "nopause")) g_nopause = 1;
        g_log = fopen("kextest.log", "a");
        file_offs();
        return finish(0);
    }
    if (argc > 3 && !strcmp(argv[1], "realtry")) return real_try(argv[2], (DWORD)strtoul(argv[3], NULL, 10));
    if (argc > 1 && !strcmp(argv[1], "rsrcbisect")) {    /* copies the DLL (~275 MB) to %TEMP% */
        const char *src = "C:\\WINDOWS\\Desktop\\chrome-win\\chrome.dll";
        for (i = 2; i < argc; i++) { if (!strcmp(argv[i], "nopause")) g_nopause = 1; else src = argv[i]; }
        g_log = fopen("kextest.log", "a");
        rsrc_bisect(src);
        return finish(0);
    }
    if (argc > 1 && !strcmp(argv[1], "rsrcimage")) {
        for (i = 2; i < argc; i++) if (!strcmp(argv[i], "nopause")) g_nopause = 1;
        g_log = fopen("kextest.log", "a");
        rsrc_image();
        return finish(0);
    }
    if (argc > 1 && !strcmp(argv[1], "realimage")) {    /* separate: copies the DLL (~275 MB) to %TEMP% */
        const char *src = "C:\\WINDOWS\\Desktop\\chrome-win\\chrome.dll";
        for (i = 2; i < argc; i++) { if (!strcmp(argv[i], "nopause")) g_nopause = 1; else src = argv[i]; }
        g_log = fopen("kextest.log", "a");
        real_image(src);
        return finish(0);
    }
    if (argc > 1 && !strcmp(argv[1], "bigimage")) {     /* separate: writes up to ~280 MB to %TEMP% */
        for (i = 2; i < argc; i++) if (!strcmp(argv[i], "nopause")) g_nopause = 1;
        g_log = fopen("kextest.log", "a");
        big_image();
        return finish(0);
    }
    if (argc > 2 && !strcmp(argv[1], "inhchild")) return inh_child(argv[2], argc > 3 ? argv[3] : NULL, argc > 4 ? argv[4] : NULL);
    if (argc > 1 && !strcmp(argv[1], "jobowner")) {       /* helper of the [job objects] test */
        char dllpath[MAX_PATH], *bs;
        GetModuleFileNameA(NULL, dllpath, MAX_PATH);
        if ((bs = strrchr(dllpath, '\\'))) { bs[1] = 0; strcat(dllpath, "kexnt.dll"); }
        if (!(kx = LoadLibraryA(dllpath))) return 1;
        return job_owner_child();
    }
    if (argc > 3 && !strcmp(argv[1], "laachild")) return laa_child(argv[2], argv[3]);   /* [above 2 GB] */
    if (argc > 1 && !strcmp(argv[1], "pipechild")) {      /* child half of the [named pipes] test */
        char dllpath[MAX_PATH], *bs;
        GetModuleFileNameA(NULL, dllpath, MAX_PATH);
        if ((bs = strrchr(dllpath, '\\'))) { bs[1] = 0; strcat(dllpath, "kexnt.dll"); }
        if (!(kx = LoadLibraryA(dllpath))) return 1;
        return pipe_child();
    }
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "stress")) g_scale = 10;
        else if (!strcmp(argv[i], "nopause")) g_nopause = 1;
    }
    g_log = fopen("kextest.log", "a");     /* append: normal + stress runs in one file */
    vi.dwOSVersionInfoSize = sizeof(vi); GetVersionExA(&vi);
    LOG("kextest build %d\n", KEXNG_BUILD);
    LOG("kextest: host reports %lu.%lu.%lu platform %lu, scale %d\n", vi.dwMajorVersion, vi.dwMinorVersion,
        vi.dwBuildNumber & 0xFFFF, vi.dwPlatformId, g_scale);
    /* Load kexnt.dll from the same directory as this exe, so we test OUR copy
     * even when KernelEx has an older version loaded via KnownDLLs. */
    {
        char dllpath[MAX_PATH], *bs;
        GetModuleFileNameA(NULL, dllpath, MAX_PATH);
        if ((bs = strrchr(dllpath, '\\'))) { bs[1] = 0; strcat(dllpath, "kexnt.dll"); }
        else strcpy(dllpath, "kexnt.dll");
        kx = LoadLibraryA(dllpath);
        if (!kx) { LOG("cannot load %s (error %lu)\n", dllpath, GetLastError()); return finish(100); }
    }
    {
        char loaded[MAX_PATH];
        GetModuleFileNameA(kx, loaded, MAX_PATH);
        LOG("kexnt.dll loaded from %s (HMODULE %08lx)\n", loaded, (unsigned long)(DWORD_PTR)kx);
    }
    if (resolve()) { LOG("kexnt.dll is missing exports\n"); return finish(101); }
    if (argc > 1 && !strcmp(argv[1], "only")) {         /* build 131: chosen tests in the given order */
        int j, k;
        for (j = 2; j < argc; j++) {
            if (!strcmp(argv[j], "nopause")) continue;
            for (k = 0; k < (int)(sizeof(g_only) / sizeof(g_only[0])); k++) if (!strcmp(argv[j], g_only[k].n)) break;
            if (k == (int)(sizeof(g_only) / sizeof(g_only[0]))) { LOG("only: unknown test %s\n", argv[j]); continue; }
            LOG("only: %s\n", argv[j]); fflush(g_log);
            g_only[k].f();
        }
        LOG("\n%d passed, %d failed\n", g_pass, g_fail);
        return finish(g_fail);
    }
    if (argc > 1 && !strcmp(argv[1], "laa")) {          /* build 131: [above 2 GB] alone */
        test_laa();
        LOG("\n%d passed, %d failed\n", g_pass, g_fail);
        return finish(g_fail);
    }
    if (argc > 1 && !strcmp(argv[1], "audio")) {        /* build 128: [Core Audio], microphone/loopback, adapters alone */
        test_coreaudio(); test_capture(); test_adapters();
        LOG("\n%d passed, %d failed\n", g_pass, g_fail);
        return finish(g_fail);
    }
    test_srw();
    test_cv();
    test_wait_on_address();
    test_init_once();
    test_fls();
    test_sysinfo();
    test_locale();
    test_veh();
    test_versions();
    test_chromium();
    test_ntreg();
    test_svcshape();
    test_ntobj();
    test_pids();
    test_shm();
    test_stubs();
    test_spawn();
    test_pipes();
    test_lockfile();
    test_dirhandle();
    test_iocp();
    test_waits();
    test_layered();
    test_layered_xthread();
    test_assocreg();
    test_spi();
    test_fontmem();
    test_gdiguard();
    test_dns();
    test_tls_dll();
    test_dwrite();
    test_coreaudio();
    test_capture();
    test_adapters();
    test_ntldr();
    test_vq_image();
    test_tpwork();
    test_opengl();
    test_draw_speed();
    test_glass();
    test_gl_keepback();
    test_clipboard();
    test_handle_path();
    test_positional_io();
    test_zero_grow();
    test_datafile_res();
    test_ro_share();
    test_gate();
    test_simd_state();
    test_cpu_avx();
    test_alias_dirty();
    test_dead_dup();
    test_pipe_stream();
    test_jobs();
    test_file_dialog();
    test_file_dialog2();
    test_memory_status();
    test_msgwait();
    test_discard();
    test_laa();
    test_installer();
    LOG("\n%d passed, %d failed\n", g_pass, g_fail);
    return finish(g_fail);
}
