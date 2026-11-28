
## Build 72: CHRVAR8 process count
CHRVAR8 also passes --process-per-site --disable-site-isolation-trials and disables SitePerProcess, SpareRenderer,
Prerender2, NoStatePrefetch, SpeculativeServiceWorkerWarmUp: every chrome.dll child costs ~41 MB of private
big-section copies on Windows 98, so the number of processes decides whether 1 GB is enough.

## Build 73: CHRVAR housekeeping
CHRVAR ends leftover CHROME.EXE processes before starting Chrome; CHRVAR8 enables NetworkServiceInProcess2.

## Build 74: Save dialog name
filedlg_ext.c installs an OFN hook that sets the suggested file name into the dialog's edt1 at CDN_INITDONE.

## Build 75: Save dialog name refill and foreground; no tab discarding
fd_hook refills an empty name box on CDN_FOLDERCHANGE/TYPECHANGE and timers, and brings the dialog to the
foreground via AttachThreadInput. CHRVAR sets the TabDiscardingExceptions policy to "*".

## Build 76
SHOpenFolderAndSelectItems via explorer /select; Chromium-style helper processes (--type=) end when their parent
process has ended (hang_ext.c orphan watcher).

## Build 77
chrome.dll .rdata is shared between processes again (veh_ext.c): import-table patches into it are undone when the
program restores the protection (rdata_patch), so the other processes keep the real functions; KEXNG_PRIVRDATA=1
restores the per-process copies. The browser brings a helper process's file dialog to the front (hang_ext.c).
Pipe ends count as gone only when OpenEvent says the name does not exist (pipe_ext.c).

## Build 78
kex_bigsec_protect reports the section's protection as the old value, so a program's restore call is recognised
and the shared-.rdata import-table patch is undone (build 77 left it in place: every helper crashed at address 0).


## Build 79
K32QueryWorkingSetEx answers for the own process (committed = valid); CertControlStore AUTO_RESYNC/CANCEL_NOTIFY
succeed; KEXCRASH exit lines carry wall-clock time and process id.

## Build 80
The crash log of an unhandled exception ends with the process's last 4 pipe writes as text (pipe_ext.c ring):
what a Chromium child sent last before a CHECK on a refused request.

## Build 81
Pipe-end liveness takes a second opinion from the end's K32 event object before declaring the other end gone;
GetDpiForMonitor's DPI is read once; helper processes ask the browser (named event + mapping) to bring their
file dialog to the front.

## Build 82
The pipe-end second opinion applies only to ends made by another process. Closing or handing a pipe end to
another process is written to KEXCRASH (who closes the tab channels).

## Build 83
CreateProcess honours PROC_THREAD_ATTRIBUTE_HANDLE_LIST: Windows 98 hands a child every inheritable handle, so
before build 83 each new renderer/utility got copies of other tabs' pipe ends and, when it exited or closed
them, the browser saw those tabs' connections drop. procspawn_ext.c now clears the inherit flag of every
handle not in the list for the duration of the CreateProcess call (one launch at a time) and restores it.
A failed client-end creation in pipe_ext.c open_client is written to KEXCRASH (error, slots in use).

## Build 84
kextest's child-process test now lists every handle the child needs (as Chromium does) and checks that an
inheritable handle left out of the list does not reach the child and keeps its inherit flag in the parent.
No change to kexnt from build 83.

## Build 85
- Positional file I/O is atomic: Windows 98 has no OVERLAPPED offsets on disk files, so kexnt seeks and then
  reads/writes (kex_ReadFile/kex_WriteFile, NtReadFile/NtWriteFile, SetFileInformationByHandle end-of-file).
  The pair now runs under a lock chosen by the handle (pipe_ext.c kex_fpos_lock, 32 locks); before, a second
  thread could move the file pointer in between and the read returned bytes from the wrong place.
- res_ext.c: resources of data-file modules (LoadLibraryEx AS_DATAFILE, handle = base | 1) are read from the
  PE file by kexnt: EnumResourceNamesW/A, FindResource(Ex)W/A, LoadResource, SizeofResource, LockResource, and
  LoadImageW/A for icons/cursors (gdiguard_ext.c). Raw-file and image layouts are both recognised.
- memstat_ext.c: a KEXCRASH note when the swap file is nearly full (with free disk space).

## Build 86
shm_ext.c: a read-only, unnamed CreateFileMapping of a file of 1 MB or more that this process opened read-only
gets a name made from the file's path, size and last-write time (KexNG_RO_<hash>_<size>_<time>). Windows 98 makes
a new mapping - a new copy in the 1 GB shared arena - for every unnamed mapping of a file; with the name every
process shares one mapping object. The caller never sees ERROR_ALREADY_EXISTS. If the named call fails, the
unnamed call is made as before.

## Build 87
- shm_ext.c: shared read-only file mappings only for files inside the program's folder.
- Notes: pipe-end close notes carry the closing process id, pipe-end duplications the target process id;
  crash dumps list heap text the stack points to (UTF-16 12+ chars, ASCII 20+).

## Build 88
Build 87's added Chromium switches are removed again: kexnt never changes a program's command line (the only
exception stays the opt-in "Report real OS version to websites" --user-agent of the KernelEx tab).

## Build 89 - kexnt only for programs built for newer Windows (gate_ext.c)
Every function kexnt publishes through the KernelEx resolver is a gate thunk generated by gen_apitable.py:
`cmp [kex_gate_state],2 / je <kexnt function> / push index / jmp kexgate_slow`. The state is decided once per
process (kexnt DllMain): MODERN if the EXE's MajorSubsystemVersion >= 5, or the user gave the program an NT
profile on the KernelEx tab (AppSettings\Configs entry other than DCFG1/WIN95/WIN98/WINME/NOHEAP, wildcards as
KernelEx), or the EXE exports KexNG_ModernProcess (kextest), or HKLM\Software\KernelEx\KexNG Gate=0. Otherwise
(Windows 98 programs, subsystem 4.x) every gate forwards to kex_prev_impl (kexbasen, kexbases, the system DLL) =
exactly what KernelEx gave before kexnt existed, cached per gate; a function that exists only in kexnt still runs
kexnt's (kexnt initialises itself on that first call). In such a process DllMain does nothing (no TLS slots, no
KERNEL32 hook registration, no logs, no profiler). tests/check_apitable.py follows the gates; KXLEGACY.EXE
(subsystem 4.0) reports its gate state to kextest. MS-DOS and 16-bit programs never reach KernelEx.

## Build 90
gate_ext.c: kexgate_slow keeps EAX/ECX/EDX/flags (calls that arrive before DllMain decided, MSVCRT helpers with
register arguments); decide() looks at the EXE header first (subsystem 5+ -> modern without any registry call).
GATEOFF.REG / GATEON.REG switch the gate off/on for Windows 9x programs (A/B test). hang_ext.c: a helper
process's dialog brought to the front is logged with its process id, title and texts.

## Build 91
sec_ext.c: when a process closes a SERVER pipe end, the EBP chain of the caller (28 frames, 12 per process) goes
to KEXCRASH (crashlog_ext.c kex_crashlog_callers) - which Chromium component closes a tab's link and why.

## Build 92
pipe_ext.c kex_zero_gap / kex_zero_to_pos: NT semantics for growing files - the part between the old end and a
write past it, a SetEndOfFile/SetFileInformationByHandle(EndOfFile) further out, or a writable file mapping larger
than the file is filled with zeros (Windows 98 leaves old disk contents). Runs under the positional-I/O lock, disk
files only. Chromium's disk cache and metrics files depend on it.

## Build 93
iocp_ext.c lock order: the completion-port lock (a spin lock) is the innermost lock. Pipe completions (arena mutex
held) and folder-handle completions queue packets under it, so nothing may take the pipe arena mutex, the folder
lock or the handle-facts lookups while holding it. CreateIoCompletionPort checks the handle before locking.

## Build 94
shm_ext.c kex_DuplicateHandle: a source or target process that has ended (signalled, or its PDB's environment
database pointer already 0) is refused with ERROR_ACCESS_DENIED as on NT - Windows 98's KERNEL32 would crash the
caller dereferencing the freed environment database (chrome_ext.c kex_process_alive).

## Build 95
tests/kextest.c test_pipe_stream: integrity stress test of kexnt pipes in byte mode with overlapped I/O both ways.

## Build 96
job_ext.c: job objects for modern programs with NT's kill-on-job-close (CloseHandle of the last job handle, owner
exit, owner killed from outside via a member-side watcher thread and the shared KXJOB_TABLE). tests/chrvar.c mode 9
(V8 single-threaded A/B test).

## Build 97
tests/chrvar.c modes 10-12 (V8 helper-thread A/B split).

## Build 98
tests/kextest.c test_simd_state: are SSE (XMM0-7, MXCSR) and x87 registers kept across Windows 98 thread switches,
Sleep, and SuspendThread+GetThreadContext (CONTEXT_CONTROL / CONTEXT_FULL, as prof_ext.c and hang_ext.c do).
tests/chrvar.c modes 13 (no streaming + single-threaded GC) and 14 (no streaming + background compiling off).

## Build 99
pipe_ext.c: positional-I/O lock keyed by the Windows 98 file object (duplicated handles share it), remembered per
thread; sequential disk ReadFile/WriteFile under it; fpos_check logs a file pointer moved during an emulated
positional read/write. shm_ext.c: notes disk files duplicated into another process. tests/chrvar.c: CHRVAR8 writes
Chrome's net log and checks every script body afterwards (C:\NETCHECK.TXT, C:\KEXBAD\).

## Build 100
tests/chrvar.c: CHRVAR8 runs a small DevTools-protocol client (127.0.0.1:9222) that saves the text V8 failed to
parse and compares it with Chrome's net-log copy of the same script (NETCHECK.TXT). kextest reports the first wrong
positional read in detail.

## Build 101
vxd_alias/kexalias.c version 4: before removing an alias, pages written through it are re-dirtied through the
section's own address (PTE dirty bit lives per mapping; a clean source PTE let Win98 drop the data -> zeros in the
other process). shm_ext.c kex_alias_release logs the counts (user-mode fallback for an older VxD).
tests/kextest.c test_alias_dirty (write through the alias only + memory pressure).

## Build 102
pipe_ext.c: one seek+I/O lock for all disk files (duplicated handles can be different K32 objects on the same file).
kextest: the memory-pressure part of test_alias_dirty only in stress mode.

## Build 103
tests/chrvar.c: CHRVAR8's DevTools client records each page's console, exceptions and log entries
(C:\KEXBAD\PAGE.TXT) and every 15 s the page state plus a screenshot (C:\KEXBAD\SHOTnn.JPG).

## Build 104
prof_ext.c: profiler self-cost, Windows 98 memory-manager counters over the run (PerfStats VMM/VCACHE), per-process
memory map (private/module/reserved/free, largest allocations, shared arena) in KEXPROF_*.LOG.

## Build 105
prof_ext.c: 25 ms sampling, PerfStats cpg values are bytes. vxd_alias/kexalias.c v5: IOCTL 4 = read page-table entries.
tests/kextest.c mem_where(): memory-manager counters + shared-arena blocks classified RAM/device/not present.
tests/chrvar.c: CDP target discovery events, wasDiscarded, discard/process-host vmodule logging.

## Build 106
vxd_alias/kexalias.c v6: IOCTL 5 VxD list, IOCTL 6 pointer search. tests/kextest.c who_owns(): owner inventory of big
shared-arena RAM blocks.

## Build 107
tests/kextest.c who_owns(): exact-value pointer search for big shared-arena blocks.

## Build 108
gdiguard_ext.c: guard_call restores FS:[0]; dead-window GetDC/GetWindowDC/GetDCEx answered NULL. tests/chrvar.c: UI DevTools
views-tree dump (C:\KEXBAD\UITREE.TXT).
## Build 109
gdiguard_ext.c: per-thread WH_CALLWNDPROC focus/activation history ring, printed by crashlog_ext.c under access
violations. tests/chrvar.c: UI DevTools dump replaced by a DevTools probe of chrome://webui-toolbar.top-chrome/
(browser_ui target) -> C:\KEXBAD\TOOLBAR.TXT; browser_ui targets' console/errors -> PAGE.TXT.
## Build 110
prof_ext.c mem_report: 16 largest address-space holders + reserved-size histogram. tests/chrvar.c: on-screen capture of
Chrome's window top strip at each toolbar probe (WINTOPn.BMP, links gdi32); screenshots of the newest page only.
## Build 111
dll_base.py: small DLLs (api-ms-win-*, ext-ms-win-*, stubs) at 0x6C400000 + 128 KB x index (was 0x5A000000 + 256 KB):
keeps 0x214B0000-0x69000000 free in Chrome processes so 1 GB contiguous reservations fit.
## Build 112
gdiguard_ext.c: WS_EX_NOACTIVATE emulation - windows created with the bit are remembered; per-thread WH_CBT hook
refuses mouse activation (HCBT_ACTIVATE with fMouse) for them, as NT does.
## Build 113
gdiguard_ext.c: per-thread HHOOKs kept and passed to CallNextHookEx. tests/chrvar.c: click probe (KEXCLICK lines).
## Build 114
gdiguard_ext.c: dispatched left clicks as KEXCRASH notes. tests/chrvar.c: click probe re-installed every 15 s.
## Build 115
gdiguard_ext.c: SetCapture/ReleaseCapture and GetMessageExtraInfo (touch signature) notes; sent button messages
in the WH_CALLWNDPROC hook. tests/chrvar.c: page input counters, hasFocus, activeElement in STATE.
## Build 116
tests/chrvar.c: DevTools mouse move per page every 15 s with acknowledgement timing; rAF / event-delay counters.
tests/kextest.c: page file totals and SYSTEM.INI paging settings.
## Build 117
yield_ext.c: timeGetTime TSC cache resyncs after 10 ms. mem_ext.c: failed VirtualAlloc names its caller.
tests/chrvar.c: rafat/now in the page counters.
## Build 118
tests/chrvar.c: CHRVAR8 without --renderer-process-limit=1.
## Build 119
shm_ext.c: failed CreateFileMapping / MapViewOfFile go to KEXCRASH with size, error and caller.
## Build 120
tests/kextest.c: VEH fault on a reserved page (not address 0); TLS test without the 10 s limit. QEMU
test VM scripts (not published).
## Build 121
pipe_ext.c: a pipe end whose name is gone is gone (no "event object still live" second opinion - that object was
another event Windows had put at the freed address). New ends clear their address from other slots (drop_aliases);
kex_CloseHandle tells pipe_ext when an end's last handle closed (kex_pipe_close_begin/_end) so the slot forgets the
address. mem_ext.c: live reservations >= 1 MB by caller, reported at the first real shortage. crashlog_ext.c:
TerminateProcess of another process noted. sysdll_ext.c: CertControlStore calls noted. shm_ext.c: read-only shared
mapping names its file; MapViewOfFile failure callers.
## Build 122
mem_ext.c kex_discard_private: MEM_RESET / DiscardVirtualMemory on private memory = decommit + recommit (pages
given back instead of swapped); MEM_RESET_UNDO on private memory fails. tests/kextest.c: [discarded memory].
## Build 123
laa_ext.c: large-address-aware NT 6+ programs get reservations above 2 GB (Windows 98 shared arena) when their own
2 GB are full - system-wide table KXLAA_TABLE/KXLAA_LOCK, owner-only release, sweeps free blocks of ended processes
(Windows 98 does not), 128 MB of the shared arena always kept free, <= 32 MB per block. mem_ext.c lets programs use
their own blocks up there. kextest.exe large address aware; [above 2 GB]. probes/lprobe.c.
## Build 124
installer_ext.c: NtShutdownSystem, GetSystemWow64Directory, GetNumaHighestNodeNumber, ETW session functions,
GetComputerObjectName, QueryDosDeviceA/W (NT device names), MSI 3 ordinals on MSI 2.0 (237-240, 242, 244, 246,
254, 270, 281), WLDAP32 ber_free (#301), GetPrivateProfileStringW with NT default handling (NSIS 3 hang).
gate_ext.c: g_always - kexnt functions every program gets (GetPrivateProfileStringW). stubs: xinput9_1_0.dll,
4 more winhttp. kexsetup: WINXP default rules for VC++ redistributable setups. kextest [installers].
Test VM: in-guest command agent + host server (not published);
probes DBG, ATTACH, SAMPLE, DUMPMEM, GPA, QDD, INI.
## Build 125
msicompat_ext.c: Windows Installer 3+ packages on Windows Installer 2.0 - the program's MSI.DLL calls (install, patch,
open, summary, verify; PATCH= lists) are served from a converted copy (CFB v4 -> v3 through Windows 98's OLE32,
summary minimum installer lowered, LaunchCondition VersionNT/ServicePackLevel as on XP SP2); WinVerifyTrust verifies a
version-4 MSI through an exact version-3 copy. fmtmsg_ext.c: FormatMessageW inserts (%1!I64u! etc.).
loader_ext.c: resource-only DLLs without relocations whose base is taken. pipe_ext.c: CreateFile strips \\?\ (VLC).
sec_ext.c: SetEntriesInAcl, SetNamedSecurityInfo. stubfix_ext.c: CryptAcquireContextA/W without CRYPT_SILENT.
installer_ext.c: MsiSetExternalUIRecord bridge, MsiSourceListAddSourceEx, more MSI 3 names. stubs/gdiplus.c (PNG/BMP).
kexsetup: "Microsoft Root Certificate Authority" (2001) into the local machine trusted roots (removed by /u).
vmtest.sh: boot 1 KEXSETUP, boot 2 kextest. Probes MSIT, WVT, CACQ, MSIQ, FMSG, LPATH, FREAD, PEEK.
## Build 126
uini_ext.c: UTF-16 INI files for GetPrivateProfileStringW/IntW and WritePrivateProfileStringW (NSIS 3 InstallOptions).
actctx_ext.c: activation contexts (accepted, no effect), CoGetContextToken/CoGetInterceptor (E_NOTIMPL), ShellExecute
"runas" as the default verb. installer_ext.c: RtlGetVersion through the program's configuration. kexnt.c: NTDLL loaded
in every modern process. msicompat_ext.c: "system32" folders of downlevel merge modules -> SYSTEM. kexaudio: Release
waits for the engine thread. kexsetup: KnownDLLs for every API-set name (SYSTEM copies win over app-local ones, as on
Windows 10), *\VC_REDIST.X86.EXE = WIN7, a Windows 10 ucrtbase.dll into SYSTEM (private CD).

## Build 127
Click timeline for Chrome/Discord (diagnostic). prof_ext.c writes KEXTL_<prog>.LOG (per-second CPU, page-ins, main
thread state and location, IPC traffic, pipe message wait max / >300 ms count, pipe mutex wait) when KexNG\Profile=1.
pipe_ext.c stamps each ring piece with GetTickCount at write (RING.mt[NP_MQ], arena v4) and measures at read.
gdiguard_ext.c logs mouse-button messages at DispatchMessage with their age. chrvar.c mode 15 (CHRVAR8) = remote
debugging only plus the page probe (KEXCLICK/KEXGAP/KEXLATE/KEXLONG/KEXEVT) on the same local clock.

## Build 128
- net_ext.c: GetAdaptersAddresses (Vista IP_ADAPTER_ADDRESSES layout) built from Windows 98's GetAdaptersInfo +
  GetNetworkParams; if_indextoname/if_nametoindex. Needed by WebRTC (ICE host candidates) and net::GetNetworkList.
- gdiguard_ext.c kexg_dispatch: BitBlt/StretchBlt rop & 0x3FFFFFFF (98 copies nothing with CAPTUREBLT/NOMIRRORBITMAP).
- laa_ext.c: kex_laa_release removes the process-list entry under the table lock (two-thread race).
- audio/kexaudio.c: capture endpoint ({0.0.1...} id, waveIn), IAudioCaptureClient, ISimpleAudioVolume,
  IAudioEndpointVolume, LOOPBACK clients and process loopback over the shared KXAUDIO_BUS (4 process slots, 16-bit
  stereo blocks of 256 frames tagged with their position on the timeGetTime x rate clock; writers = render engines at
  their play position, readers 60 ms behind), exported KexActivateAudioInterfaceAsync; stub MMDEVAPI.DLL ordinal 17
  forwards to it (stubs.txt: name@size%ordinal syntax in gen_stubs.py).

## Build 129-130
- ws_ext.c kex_ws2_getsockname (WS2_32 #6): 0.0.0.0 on a connected socket -> the adapter address that reaches the peer.
- crashlog_ext.c: c000001d at a VEX byte (C4/C5) is labelled as AVX on Windows 98 (no OS AVX state; Chrome's Opus
  chooses AVX2 from CPUID alone). kextest test_cpu_avx checks CPUID AVX/F16C/FMA vs XGETBV; the remedy is a VM CPUID
  mask, not kexnt code.

## Build 131
- ntldr_ext.c: LdrLoadDll/LdrGetProcedureAddress (resolved as the process via a SYSTEM-module return address),
  NtAllocateVirtualMemory, Nt(Un)MapViewOfSection, NtQueryInformationFile, Rtl* memory/PC helpers. ntcrt_ext.c: the
  116 C library names NT's NTDLL exports (lazy jumps into MSVCRT). psapi/: KernelEx's PSAPI rebuilt with
  GetModuleInformation/GetMappedFileName*/EnumProcessModulesEx/GetPerformanceInfo (KEXSETUP replaces PSAPI.DLL).
- peb_ext.c: split TEB->PEB reads (mov r,fs:[18h] ... mov r,[r+30h]); kexnt.c full_init patches the mapped NT 6+
  modules before their DllMain; veh_ext.c DLL-entry hook patches non-SYSTEM DLLs before their DllMain;
  is_sysdir_dll resolves "\..\" (KnownDLLs paths). kex_vxd_log uses kex_spin_acquire (Windows froze).
- KexPatchNtModules starts kexnt when an api-ms shell loads into a Windows 98 program (shell exports bypass the
  gate). gate_ext.c: a "previous implementation" inside kexnt counts as kexnt-only; Windows 98 programs get a
  LoadLibrary wrapper that retries a failing full-path load with LOAD_WITH_ALTERED_SEARCH_PATH (private SxS DLLs,
  LAV Filters); the kexnt loader does the same for modern programs.
- manifest_ext.c: comctl32 6 manifest -> InitCommonControlsEx at process start (7-Zip SFX progress dialog).
- tpwork_ext.c: thread-pool work/wait objects, CreateFile2, CopyFile2, GetNativeSystemInfo, GetVolumePathName,
  K32QueryWorkingSet, GetLastInputInfo. sysinfo_ext.c: K32GetMappedFileName/GetProcessImageFileName as NT paths.
- mem_ext.c: VirtualQuery(Ex) reports MEM_IMAGE for module pages (VCRUNTIME140 _except_handler3 rejects __try scope
  tables that are not MEM_IMAGE -> every such __try was skipped on 98: Pale Moon's SetThreadName crash).
- lockfile_ext.c: UnlockFileEx says ERROR_NOT_LOCKED (158) like NT; closed handles forget their shared-lock bytes.
- sysdll_ext.c: SHGetFolderPath/SHGetSpecialFolderPath for CSIDL 0x26/0x2A/0x2B/0x2C/0x29 (Windows 98 refuses them);
  CoGetApartmentType answers from a CoInitializeEx probe (Firefox mscom assertion).
- gecko115_ext.c: Firefox 115 / Inno Setup 6.4 / Chrome setup imports (Nt/Rtl, Cred*, Reg*KeyValue/Tree,
  CryptBinaryToStringW, WSCGetProviderInfo, touch/gesture, DPI, GetThreadUILanguage, GetSystemTimes, _allshl etc.).
- chrome_ext.c: GetVolumeInformationByHandleW. procspawn_ext.c: failed CreateProcess noted; error 31 keeps a copy
  of the program as %TEMP%\KEXFAIL31.EXE for the import check.
- stubs: dwmapi iconic/thumbnail calls, ktmw32.dll, shcore.dll, ncrypt (BCrypt*/NCryptDecrypt/DeleteKey),
  bcrypt hash calls, propsys schema calls, winhttp options.
- kexsetup: rules VC_REDIST.X86.EXE / FIREFOX?SETUP / FIREFOX?INSTALLER / K-LITE_CODEC_PACK_* = WIN10_21H2,
  PALEMOON-*.EXE = WIN7; KernelEx's own "*\FIREFOX SETUP *.EXE" = WINXP retargeted (restored on uninstall);
  KnownDLLs DWrite -> the Windows 10 DWrite.dll when installed.
- Later in 131: combase.dll / windowscodecs.dll stubs (Firefox 160 xul.dll imports them statically), api-set shells
  version-l1-1-1, psapi-l1-1-0, libraryloader-l1-2-1, heap-l2-1-0, rtlsupport-l1-2-0, path-l1-1-0 (PathCch*);
  userenv.dll = KernelEx's userenv.c + userenv_ng.c (EnterCriticalPolicySection) installed into the KernelEx folder
  like PSAPI (USERENV.ORG kept); filedlg_ext.c CoCreateInstance retries with context & 7 when OLE32 refuses newer
  bits; kexsetup *\FIREFOX.EXE (KernelEx's DCFG1) -> WIN7, Chrome setup rules.
- Final 131 (2026-11-21, see analysis/b131_findings.md 26-31): the full kextest hang at [DirectWrite] came from the
  test-CD diagnostics, not from 131's code or the VM's installs. (a) KEXTRACE's file lock and the VxD-trace table lock
  were bare spins; ExitProcess terminated the vxd_flusher thread while it held the KEXTRACE lock (and the profiler's
  sampler can suspend a holder) -> the next locker spun forever: a process that loaded the Windows 10 DWrite.dll could
  not exit (Trace=1). kexnt_common.h kex_spin_try: kex_trace_raw drops a line after 500 ms, kex_vxd_log a sighting
  after 200 ms. (b) The VxD-call trace hook (kexnt code on every thread inside KERNEL32) together with the profiler's
  25 ms SuspendThread sampler froze Windows 98 (Trace=1 + Profile=1): with the profiler running the VxD-call trace is
  no longer installed (crashlog_ext.c; KEXTRACE says so). (c) sec_ext.c kex_CloseHandle: CloseHandle(NULL) goes
  straight to Windows - kexnt's handle tables mark empty slots with 0 and kex_dir_close dereferenced 64 NULL
  OVERLAPPEDs (Firefox 115 mozglue page fault); dirhandle_ext.c ignores 0 too. Firefox 115 ESR now shows its window.
- kextest: [above 2 GB] takes kexnt's memory functions from WINDOWS\KERNELEX\KEXNT.DLL (the copy the process runs on;
  its second copy kx refused blocks the system copy had lent - the old "pre-existing" failure); a failed commit no
  longer crashes kextest. New diagnostic modes: "kextest only NAME..." (chosen tests in order; "mods" = module list,
  "hangdump" = KEXHANG thread dump), "kextest dwstep N", "kextest loadlib DLL...". KEXDBG -stall N: reports every
  thread when the debuggee sends no debug event for N s.

## Build 132
- msicompat_ext.c / slip_ext.c: .NET 3.5 SP1 installs to "Setup complete" on Windows 98 SE. New subsystem:
  Windows Installer 3 patch slipstreaming (kex_slip_install in slip_ext.c). When a program calls
  MsiInstallProductW with a PATCH= list, the hook:
  (1) opens each .msp patch with StgOpenStorage,
  (2) extracts transforms from the patch's summary stream and applies them to a copy of the base .msi,
  (3) copies each patch's cabinet streams into the merged package (naming them KX98P_CABn),
  (4) rewrites the Media table so the merged package is self-contained with all patch cabinets embedded,
  (5) calls real MsiInstallProduct on the merged package at %WINDIR%\KEXMSI\<name>_kx98p.msi.
  Also added: prntvpt.dll stub (skips XPS print update that aborts on Windows 98),
  QueryServiceConfig2W/A stubs (WixCA custom action), PROCESSOR_ARCHITECTURE=x86 supplied to env_ext,
  MsiDetermineApplicablePatches stub (returns all patches applicable in given order).

## Build 133
- slip_ext.c: Fix .NET 3.0 SP2 partial install. Root cause: .NET 3.0 patches embed their cabinets under
  MSI-encoded stream names whose first decoded byte is <= 0x20 (space), which the build 132 filter
  `if (an[0] > ' ')` rejected. All patch cabinets were silently skipped, leaving only the base .msi's WCF
  files; WPF, WF, Windows Communication Foundation Setup (WCS) and XPS components were never installed.
  Fix: replace the MSIDBOPEN_PATCHFILE + _Streams MSI API path with direct IStorage stream enumeration
  (IEnumSTATSTG) and MSCF magic detection (first 4 bytes "MSCF"). The name filter is removed entirely;
  cabinet streams are identified by content, not by name. MSIDBOPEN_PATCHFILE (value 32) is a WI 3.0
  addition not reliably available on Windows 98's MSI 2.0; IStorage enumeration avoids it.
  CoTaskMemFree for STATSTG::pwcsName loaded lazily via kex_sysproc.

## Build 134
- slip_ext.c: Fix .NET 3.0 WF/WPF/WCS/XPS components still not installing after build 133. Root cause:
  DOTNETFX35.EXE makes a second MsiInstallProductW call for netfx30a_x86.msi WITHOUT PATCH= (a chain
  verify/repair pass after the .NET 3.5 SP1 MSI completes). kex_slip_install returned FALSE (no PATCH=),
  so conv_w processed the original D:\ extraction MSI and created netfx30a_x86_kx98.msi beside it on D:\.
  But the MSI source cache from the first (PATCH=) install registered the package as netfx30a_x86_kx98p_kx98.msi
  in %WINDIR%\KEXMSI\. The name mismatch caused error 1316 on the second pass, aborting the component
  install phase that would have written WF/WPF/WCS/XPS.
  Fix: in kex_slip_install, when no PATCH= is in cmd, check if %WINDIR%\KEXMSI\<basename>_kx98p.msi
  already exists. If it does, return it as the new package so conv_w produces %WINDIR%\KEXMSI\..._kx98p_kx98.msi
  - matching the registered name. kex suffixes (_kx98p, _kx98) are stripped from the basename before the
  lookup so the check is correct even if the caller passes an already-processed path.

## Build 135 (withdrawn) and Build 136

Build 135 rewrote "NOT Version9X" component conditions on a guess; the KEXMSI.LOG of the next run showed the merged
.NET 3.0 package has no such conditions. Build 136 reverts it.

Build 136 fixes the real cause of the missing WPF/WF/WCS/XPS files. `merge()` in slip_ext.c extracted every patch
transform to the same temporary .mst file. Windows Installer 2.0 keeps an applied transform file open until the database
is closed, so writing the next transform over it failed with STG_E_SHAREVIOLATION (80030020) and only the first patch
(WCF) got its File/Component rows; the other nine patches' cabinets were embedded but nothing referenced them. Proven
with probes/msslip.c (a C:\SLIPONE.FLG flag makes it reuse one file): one file -> File stays at 52 rows and every later
copy fails with 80030020; one file per transform -> File grows to 144 rows. Fix: one GetTempFileName per transform,
all deleted after the database is closed. Verified in the VM: the merged netfx30a package grows to 16,265,728 bytes and
its WPF components (font cache service) are installed.

Open after 136: .NET 3.0 SP2 install stops at the WiX custom action ExecSecureObjects
("Error 0x80070103: failed to process CustomActionData", data "FontCache3.0.0.0\tServiceInstall\t\tINTERACTIVE\t16"),
which sets the ACL of the PresentationFontCache service. A package merged by build 134/135 is stale: uninstall .NET 3.5
SP1 and 3.0 SP2 and delete %WINDIR%\KEXMSI\netfx30a_x86_kx98p*.msi before reinstalling.

## Build 137

.NET 3.0 SP2 (and so .NET 3.5 SP1) installs completely; WPF/WF/WCS/XPS assemblies are in the GAC.

1. WiX CustomActionData delimiter (msicompat_ext.c kex_MsiSetPropertyW / kex_MsiGetPropertyW, MSI ordinals 145 / 74).
   WiX joins CustomActionData fields with MAGIC_MULTISZ_DELIM = 128 (U+0080, wcawrap.cpp). Windows Installer 2.0 on
   Windows 98 keeps properties as ANSI text; U+0080 has no code page 1252 character and is stored as '?' (0x3F bytes in
   KXMSI.LOG). WcaReadStringFromCaData then finds no delimiter, the second field read returns E_NOMOREITEMS
   (0x80070103) and ExecSecureObjects logs "failed to process CustomActionData" (ExecXmlConfig failed the same way).
   Fix: MsiSetPropertyW stores U+0080 as the character of ANSI byte 0x80 (computed at runtime, used only if it
   round-trips; U+20AC on 1252); MsiGetPropertyW("CustomActionData") maps that character back to U+0080. A genuine
   euro sign inside a WiX CustomActionData would also be read back as a delimiter.
2. WiX ServiceConfig (msicompat_ext.c drop_service_config, applied in convert() to NT-only packages). Windows Installer
   on 9x skips ServiceInstall/ServiceControl; ExecServiceConfig then failed on OpenServiceW (error 120) for
   FontCache3.0.0.0 and rolled the install back. The ServiceConfig rows are deleted from the converted copy, so service
   configuration is skipped like service installation. No service API changed for other programs.
Probes: svcacl.c (service/ACL calls on 98: OpenServiceW, LookupAccountNameW, SetEntriesInAclW by name all return 120),
tail.c (copy the end of a big log: uploads of several MB hang the VM's agent link).

## Build 138 - .NET runtime stress test (probes/dotnet)

Suite: probes/dotnet/{core20,net35,wf,wcf,wpf,xps,winforms}.cs with T.cs (PASS/FAIL per check, C:\T\<NAME>.LOG),
built in the VM with the 3.5 csc and response files (*.RSP, BUILD.BAT). Results on build 138: CORE20 25/25, NET35 10/10,
WINFORMS 2/2. Each fix was proven first:
- CryptoAPI: .NET 2.0 SP2 asks for PROV_RSA_AES (24) on "XP" (crash note: type 0x18, error 80090017; probe cryptprov.c:
  Windows 98 defines types 1, 3, 13). stubfix_ext.c falls back to the Enhanced RSA provider (type 1).
- Services: Windows 98 stubs (error 120) broke .NET's ServiceController and WCF's ServiceModelReg (probe iishelper.cs,
  smrcomp.cs). OpenService/GetServiceKeyName/GetServiceDisplayName -> ERROR_SERVICE_DOES_NOT_EXIST, CloseServiceHandle of
  the 0xCAFE manager handle -> TRUE.
- SystemParametersInfoW (spi_ext.c nt_default): XP defaults for 2000/XP GET actions 98 rejects (probe spiall.c).
- wpfgfx_v0300.dll static imports (KEXIMP): RTL bitmap functions, DbgPrintEx (cdecl), GdiEntry13; PresentationCore
  P/Invokes (strings of the WPF binaries): RtlAllocateAndInitializeSid/RtlInitializeSid/RtlFreeSid, Nt*Port (LPC: no
  port -> STATUS_OBJECT_NAME_NOT_FOUND / STATUS_NOT_IMPLEMENTED).
- LsaLookupSids, LsaGetLogonSessionData (lsa_ext.c), LsaFreeReturnBuffer frees them.
- WPF FileMapping.Commit: kexnt refused VirtualAlloc(MEM_COMMIT) in the shared arena, and the program's own view was
  not recognised because a view mapped with size 0 was recorded as 0 bytes (shm_ext.c view_add). Probe fmap.cs.
- Event log: RegisterEventSource/ReportEvent write to the KEXCRASH log (that is how the CLR's "Unrecoverable system
  error" of the WPF run was seen).
VM note: machine.config of run2 held .NET 3.5's <system.serviceModel> block without 3.0's declarations (ServiceModelReg
had failed in the 3.0 install). The block was set aside (C:\T\MACHINE.BAK) and the declarations were written by the
WCF ConfigurationHandlersInstallComponent (probe smrcomp.cs).
Open: WPF/XPS CLR fatal error during XAML parse (C++ exception from MSCORJIT first), WF InitializeProcessSecurity NRE,
WCF net.tcp client connection refused, ServiceModelReg "The handle is invalid".
