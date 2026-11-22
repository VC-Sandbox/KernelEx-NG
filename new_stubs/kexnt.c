/* kexnt.c - DllMain of kexnt.dll (ntdll_ext, kernel32_ext, sync_ext, fls_ext, sysinfo_ext).
 * Thread notifications stay ENABLED: FLS destructors and per-thread park events are
 * released on DLL_THREAD_DETACH. */
#include "ntdll_ext.h"
#include "kernel32_ext.h"
#include "sync_ext.h"
#include "fls_ext.h"

BOOL kex_peb_init(void);
BOOL kex_veh_init(void);
void kex_tls_init(void);
void kex_tls_thread_attach(void);
void kex_tls_thread_detach(void);
void kex_veh_detach(void);
void kex_tls_reserve_init(void);
void kex_w10_fonts_sync(void);   /* w10_ext.c */
void kex_proctime_init(void);    /* proctime_ext.c */
void kex_font_detach(void);        /* font_ext.c */   /* veh_ext.c: native TLS slots kept for SYSTEM-folder DLLs */

static volatile LONG g_init;          /* 0 not yet, 1 running, 2 done ok, 3 failed */
LONG kex_gate_decide(void);          /* gate_ext.c: 1 Windows 9x program, 2 modern program */

/* kexnt's start-up: at process start in a modern program; in a Windows 9x program only if it ever calls a
 * function that exists nowhere but in kexnt (gate_ext.c) */
static BOOL full_init(void)
{
    {   /* build 131: which step failed (a Windows 98 program reaching kexnt through the gate - regsvr32 registering
         * K-Lite's filters crashed in FlsAlloc on an uninitialised lock) */
        int step = 0; void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
        if (!(++step, kex_k32ext_init()) || !(++step, kex_ntext_init()) || !(++step, kex_sync_init()) ||
            !(++step, kex_fls_init()) || !(++step, kex_peb_init()) || !(++step, kex_veh_init())) {
            kex_crashnote("kexnt start-up FAILED at step (1 k32ext 2 ntext 3 sync 4 fls 5 peb 6 veh, error, gate)", (DWORD)step, GetLastError(), 0, 0);
            return FALSE;
        }
    }
    kex_tls_init();
    kex_proctime_init();
    if (kex_is_win9x()) { kex_tls_reserve_init(); kex_w10_fonts_sync(); }
    { void kex_realos_attach(void); kex_realos_attach(); }   /* realos_ext.c: browsers' real-OS UA option */
    { void kex_job_child_init(void); kex_job_child_init(); } /* job_ext.c: watch the owner of our job */
    /* build 126: on NT, NTDLL is in every process, so programs find it with GetModuleHandle("ntdll") without loading
     * it. Windows 98's NTDLL.DLL is only there if something imported it (GMH.EXE: GetModuleHandleW(ntdll) = NULL,
     * error 126). WiX Burn 3.14 (VC++ 2015-2022 setup) stops on that: "Failed to locate NTDLL" -> 0x8007007E.
     * Modern programs get it loaded once, for the life of the process. */
    LoadLibraryA("NTDLL.DLL");
    /* build 131: patch the NT 6+ modules already mapped (the process's static imports) now, before their own DllMain
     * runs. Until now only the api-ms shells' DllMain did it, so a DLL importing none of them (Supermium 150's
     * pwrp_k32.dll) ran its DllMain unpatched and read the Windows 98 process database as its PEB. */
    { VOID KEXAPI kex_KexPatchNtModules(void); kex_KexPatchNtModules(); }
    return TRUE;
}
static DWORD g_init_tid;
void kex_full_init(void)
{
    if (InterlockedCompareExchange(&g_init, 1, 0) == 0) { g_init_tid = GetCurrentThreadId(); InterlockedExchange(&g_init, full_init() ? 2 : 3); }
    else if (g_init_tid == GetCurrentThreadId()) return;     /* build 131: re-entered from our own start-up (a DllMain) */
    else while (g_init == 1) Sleep(0);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        { void kex_manifest_comctl(void); kex_manifest_comctl(); }   /* build 131: manifest_ext.c, every program with a comctl32 6 manifest */
        if (kex_gate_decide() != 2) return TRUE;   /* build 89: a Windows 9x program - kexnt stays out of it */
        { void kex_loaderfix_ensure(void); kex_loaderfix_ensure(); }   /* build 132: NT 5+ DLLs without relocations movable (veh_ext.c) */
        kex_full_init();
        {   /* build 132: .NET programs - kexnt's fault fixes (teb_tls_fix) and the crash log (otherwise armed only by the
             * NT 6+ module patcher, which never runs for them) */
            int kex_gate_is_clr(void); void kex_veh_ensure(void); void kex_crashlog_arm(void);
            if (kex_gate_is_clr()) { void kex_clr_validate(void); kex_crashlog_arm(); kex_veh_ensure(); kex_clr_validate(); }
        }
        return g_init == 2;           /* PEB patching is driven by the api-ms shells (see peb_ext.c) */
    case DLL_THREAD_ATTACH:
        if (g_init != 2) break;
        kex_tls_thread_attach();      /* static TLS of DLLs loaded later (tls_ext.c) */
        { void kex_prof_thread_attach(void); kex_prof_thread_attach(); }   /* prof_ext.c: every thread gets sampled */
        { void kex_hang_thread_attach(void); kex_hang_thread_attach(); }   /* hang_ext.c: thread list for the hang dump */
        break;
    case DLL_THREAD_DETACH:
        if (g_init != 2) break;
        { void kex_hang_thread_detach(void); kex_hang_thread_detach(); }   /* hang_ext.c */
        kex_tls_thread_detach();
        kex_fls_thread_detach();      /* FLS callbacks may still use locks -> before sync */
        kex_sync_thread_detach();
        break;
    case DLL_PROCESS_DETACH:
        if (g_init != 2) break;
        kex_font_detach();
        kex_veh_detach();             /* always: the shared VEH stub must stop jumping into us */
        if (reserved) { void kex_job_process_exit(void); kex_job_process_exit(); }   /* job_ext.c: process exit */
        if (!reserved) {              /* FreeLibrary, not process exit: clean up this thread */
            kex_fls_thread_detach();
            kex_sync_thread_detach();
        }
        break;
    }
    return TRUE;
}
