KernelEx-NG CD
==============
Use this only in a virtual machine or on a spare computer with no important data on it (see README.md on
GitHub). Requires Windows 98 SE with KernelEx 4.5.2 installed.

Install (and after every new CD)
  Once KEXSETUP has run, KernelEx maps every "kexnt.dll" to the installed copy
  C:\WINDOWS\KERNELEX\KEXNT.DLL (KnownDLLs); a newer kexnt.dll in C:\KEXTEST is ignored until KEXSETUP runs again.
  1. From an MS-DOS prompt:
       DELTREE /Y C:\KEXTEST
       MKDIR C:\KEXTEST
       COPY D:\*.* C:\KEXTEST      (or copy everything in Explorer)
  2. C:\KEXTEST\KEXSETUP.EXE
       - installs kexnt.dll and the version profiles into KernelEx (original kept as
         C:\WINDOWS\KERNELEX\KERNELEX.KNG);
       - copies the stub DLLs listed in STUB_DLLS.TXT to C:\WINDOWS\SYSTEM, only where Windows has no DLL
         of that name and never over a genuine Microsoft DLL.
     KEXSETUP /u removes everything again.
  3. Restart Windows.

Windows 10 DLLs (optional)
  Some programs need Microsoft's own Windows 10 DLLs (DWrite.dll, TextShaping.dll, ucrtbase.dll). KernelEx-NG
  does not include them; KEXSETUP installs the ones you put in a WIN10 folder next to it from your own Windows 10.

Self-tests
  C:\KEXTEST\KEXTEST.EXE     kexnt.dll self-test (ends with "N passed, 0 failed"); C:\KEXTEST\STRESS.BAT repeats it.
  C:\KEXTEST\KEXROUTE.EXE    checks that KernelEx routes the extended functions.
  C:\KEXTEST\VERTEST.EXE     shows the Windows version a program sees. Right-click it > Properties > KernelEx tab >
                             "Use specific compatibility mode" > e.g. "Windows 11 24H2" and run it again.
  C:\KEXTEST\UCRTLOAD.EXE, UCRTTEST.EXE   the Universal C runtime (needs ucrtbase.dll, see above).

Check a program before running it (KEXIMP)
  KEXIMP reads a program's import list and reports every Windows function that is missing on this machine, all at
  once (Windows 98 only ever shows the first one).
  a) Right-click C:\KEXTEST\KEXIMP.EXE > Properties > KernelEx tab: same mode as the program (e.g. Windows XP).
  b) Command prompt:  C:\KEXTEST\KEXIMP.EXE "C:\Program Files\Some Program\program.exe"
     The report is KEXIMP.LOG in the current folder.

Logs
  KEXCRASH_<program>.LOG (crashes, hangs, notes) and KEXTRACE_<program>.LOG (only with TRACEON.REG) are written next
  to the program. TRACEOFF.REG, PROFOFF.REG and BOOSTOFF.REG switch the diagnostic options off for everyday use.

Explorer crash diagnosis (EXPLDBG) - independent of KernelEx-NG
  Attaches a debugger to the running Explorer and writes C:\EXPLDBG.LOG with the full state of every crash.
  a) Copy KEXDBG.EXE and EXPLDBG.BAT to C:\KEXTEST.
  b) Double-click EXPLDBG.BAT. A DOS window says "attached to EXPLORER.EXE". Minimise it - do not close it
     (Windows 98 cannot detach a debugger; closing the window ends Explorer).
  c) The log is appended after each crash. Run EXPLDBG.BAT again after each Windows start.

Build history (most recent first)
  Build 134 (2026-11-28): .NET 3.5 SP1 on Windows 98: fix WF/WPF/WCS/XPS components still missing after 133.
    Root cause: DOTNETFX35.EXE makes a second MsiInstallProductW call for netfx30a_x86.msi without PATCH=
    (chain verify/repair pass). Without PATCH=, kex_slip_install returned FALSE so conv_w processed the
    original D:\ extraction MSI and created netfx30a_x86_kx98.msi beside it, but the MSI source cache from
    the first install registered the package as netfx30a_x86_kx98p_kx98.msi in %WINDIR%\KEXMSI\ - name
    mismatch caused error 1316, aborting the WF/WPF/WCS/XPS component install phase. Fixed in
    kex_slip_install: when no PATCH= is in cmd, check if %WINDIR%\KEXMSI\<basename>_kx98p.msi already
    exists; if so, return it so conv_w produces the matching _kx98p_kx98.msi name.

  Build 133 (2026-11-28): .NET 3.5 SP1 on Windows 98: fix .NET 3.0 SP2 partial install (only WCF files were
    installed; WPF, WF, WCS and XPS components missing). Root cause: cabinet streams in .NET 3.0 patches use
    MSI-encoded names that begin with bytes <= 0x20, filtered out by the previous stream-name check. Fixed by
    replacing the MSI API cabinet-extraction path with direct IStorage stream enumeration and MSCF magic
    detection, which is encoding-agnostic.

  Build 132 (2026-11-27): .NET 3.5 SP1 installs to "Setup complete" on Windows 98 SE. Merged: MSI 3
    slipstream (patches merged into the package before install), prntvpt.dll stub (skips XPS print update),
    QueryServiceConfig2W/A stubs (WixCA custom action), PROCESSOR_ARCHITECTURE=x86 supplied to env_ext,
    MsiDetermineApplicablePatches stub.

  Build 131 (2026-11-21): Firefox 115 ESR window appears. KEXTRACE deadlock fix (bounded spin). DWrite.dll,
    TextShaping.dll, ucrtbase.dll via KEXSETUP. kextest regression suite green (772/0).
