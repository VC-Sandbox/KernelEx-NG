/*
 * kexroute.c - checks that KernelEx routes Vista+/Win10 imports to kexnt.dll.
 *
 * Unlike kextest (which LoadLibrary's kexnt.dll directly), this program imports the functions
 * STATICALLY from KERNEL32.DLL / NTDLL.DLL / an api-ms-win-* set, exactly like Chromium does.
 * Plain Win98 has none of them, so:
 *   - routing broken  -> Windows refuses to start it ("linked to missing export KERNEL32.DLL:...")
 *   - routing works   -> it starts, checks every import lands inside kexnt.dll, calls each one.
 * Output also goes to kexroute.log (appended).   kexroute nopause = no "Press Enter" at the end.
 */
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* Not in the MinGW headers for i686 user mode. */
__declspec(dllimport) LONG WINAPI NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

static FILE *g_log;
static int g_pass, g_fail;
#define LOG(...) do { printf(__VA_ARGS__); if (g_log) { fprintf(g_log, __VA_ARGS__); fflush(g_log); } } while (0)
#define CHECK(c, ...) do { if (c) { g_pass++; } else { g_fail++; LOG("  FAIL: " __VA_ARGS__); LOG("\n"); } } while (0)

static HMODULE g_kexnt;

/* Report which module a resolved import points into; must be kexnt.dll. */
static void where(const char *name, void *p)
{
    MEMORY_BASIC_INFORMATION mbi;
    char path[MAX_PATH] = "?";
    HMODULE owner = NULL;
    /* MinGW headers lack dllimport on some names (AcquireSRWLockExclusive, WaitOnAddress), so
     * &func is the linker's "jmp dword ptr [__imp_func]" stub inside this exe. Follow it to the IAT. */
    const BYTE *b = (const BYTE *)p;
    if (b[0] == 0xFF && b[1] == 0x25) p = **(void ***)(b + 2);
    if (VirtualQuery(p, &mbi, sizeof(mbi))) owner = (HMODULE)mbi.AllocationBase;
    if (owner) GetModuleFileNameA(owner, path, sizeof(path));
    LOG("  %-28s -> %08lx  %s\n", name, (unsigned long)(DWORD_PTR)p, path);
    CHECK(owner && owner == g_kexnt, "%s does not resolve into kexnt.dll", name);
}

static BOOL CALLBACK once_cb(PINIT_ONCE o, PVOID param, PVOID *ctx) { (*(int *)param)++; return TRUE; }

static int g_nopause;
static int finish(int code)
{
    if (g_log) { fclose(g_log); g_log = NULL; }
    if (!g_nopause) { printf("\nPress Enter to close..."); fflush(stdout); getchar(); }
    return code;
}

int main(int argc, char **argv)
{
    SRWLOCK srw = SRWLOCK_INIT;
    CONDITION_VARIABLE cv;
    INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION lpi[64];
    DWORD len = sizeof(lpi), fls, ret = 0;
    BYTE sbi[64];
    LONG word = 5, cmp = 7;
    int calls = 0;
    WCHAR wbuf[32];
    FARPROC dyn;

    if (argc > 1 && !strcmp(argv[1], "nopause")) g_nopause = 1;
    g_log = fopen("kexroute.log", "a");
    LOG("kexroute: static KERNEL32/NTDLL/api-ms imports -> kexnt.dll\n");

    g_kexnt = GetModuleHandleA("kexnt.dll");
    LOG("kexnt.dll mapped at %08lx\n", (unsigned long)(DWORD_PTR)g_kexnt);
    CHECK(g_kexnt != NULL, "kexnt.dll is not loaded in this process");

    LOG("[where do the imports point]\n");
    where("KERNEL32!AcquireSRWLockExclusive", (void *)AcquireSRWLockExclusive);
    where("KERNEL32!InitOnceExecuteOnce", (void *)InitOnceExecuteOnce);
    where("KERNEL32!GetTickCount64", (void *)GetTickCount64);
    where("KERNEL32!FlsAlloc", (void *)FlsAlloc);
    where("KERNEL32!GetLogicalProcInfo", (void *)GetLogicalProcessorInformation);
    where("KERNEL32!InitializeCSEx", (void *)InitializeCriticalSectionEx);
    where("NTDLL!NtQuerySystemInformation", (void *)NtQuerySystemInformation);
    where("api-ms-synch-l1-2-0!WaitOnAddr", (void *)WaitOnAddress);
    where("KERNEL32!LCIDToLocaleName", (void *)LCIDToLocaleName);
    where("KERNEL32!GetLocaleInfoEx", (void *)GetLocaleInfoEx);
    where("KERNEL32!CompareStringEx", (void *)CompareStringEx);
    where("KERNEL32!CompareStringOrdinal", (void *)CompareStringOrdinal);
    dyn = GetProcAddress(GetModuleHandleA("kernel32.dll"), "SleepConditionVariableSRW");
    CHECK(dyn != NULL, "GetProcAddress(kernel32, SleepConditionVariableSRW) = NULL");
    if (dyn) where("GetProcAddress SleepCondVarSRW", (void *)dyn);

    LOG("[call them]\n");
    AcquireSRWLockExclusive(&srw);
    InitializeConditionVariable(&cv);
    CHECK(!SleepConditionVariableSRW(&cv, &srw, 10, 0) && GetLastError() == ERROR_TIMEOUT,
          "SleepConditionVariableSRW timeout (err %lu)", GetLastError());
    ReleaseSRWLockExclusive(&srw);
    CHECK(TryAcquireSRWLockExclusive(&srw), "SRW free again after release");
    ReleaseSRWLockExclusive(&srw);
    CHECK(InitOnceExecuteOnce(&once, once_cb, &calls, NULL) && InitOnceExecuteOnce(&once, once_cb, &calls, NULL)
          && calls == 1, "InitOnceExecuteOnce ran callback %d times", calls);
    CHECK(GetTickCount64() > 0, "GetTickCount64");
    fls = FlsAlloc(NULL);
    CHECK(fls != FLS_OUT_OF_INDEXES && FlsSetValue(fls, &fls) && FlsGetValue(fls) == &fls && FlsFree(fls), "Fls*");
    CHECK(GetLogicalProcessorInformation(lpi, &len) && len >= sizeof(lpi[0]), "GetLogicalProcessorInformation");
    CHECK(NtQuerySystemInformation(0, sbi, 44, &ret) == 0, "NtQuerySystemInformation(Basic) ret %lu", ret);
    CHECK(WaitOnAddress(&word, &cmp, sizeof(word), 0), "WaitOnAddress value differs -> returns at once");
    CHECK(LCIDToLocaleName(0x0409, wbuf, 32, 0) == 6 && wbuf[0] == 'e' && wbuf[2] == '-' && wbuf[5] == 0, "LCIDToLocaleName(0409)");
    CHECK(GetLocaleInfoEx(L"de-DE", LOCALE_SISO3166CTRYNAME, wbuf, 32) == 3 && wbuf[0] == 'D' && wbuf[1] == 'E', "GetLocaleInfoEx(de-DE, country)");
    CHECK(CompareStringEx(L"en-US", NORM_IGNORECASE, L"Chrome", -1, L"CHROME", -1, NULL, NULL, 0) == CSTR_EQUAL,
          "CompareStringEx ignore case (err %lu)", GetLastError());
    CHECK(CompareStringOrdinal(L"abc", 3, L"abd", 3, FALSE) == CSTR_LESS_THAN, "CompareStringOrdinal");

    LOG("\n%d passed, %d failed\n", g_pass, g_fail);
    return finish(g_fail);
}
