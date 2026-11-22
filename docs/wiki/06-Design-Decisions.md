# 6. Design rules and decisions

Each rule below was either set at the start or **learned the hard way**. The reason is given with each one.

## Prove the cause before changing code

Every fix starts with evidence: a crash log line, a thread dump, a probe program, a measured difference. Only
then is the cause named and the fix written. Guessed fixes in this kind of system have a way of "working" by
changing timing, and then the real bug comes back elsewhere.
[Case studies](09-Case-Studies.md) shows what that looks like in practice.

## Never return success with garbage

Every function does one of three things:
- works for real;
- emulates NT's documented contract;
- fails with the error NT gives when the feature is absent.

KernelEx 4.5 had several stubs that said "success" and did nothing, for example `NtQuerySystemInformation`,
`AddFontMemResourceEx` and `LockFileEx` with a shared lock. Each one cost a long hunt, because the program failed
much later and somewhere else. A clean failure lets the program take its own fallback path.

## No effect on Windows 98 programs

The project must never make an existing Windows 98 program behave differently. Early builds broke that rule by
accident: KernelEx applies one configuration to every program, so `kexnt` was in every process. The **gates**
(build 89) enforce the rule in code. The decision is made per process from the EXE's subsystem version or an
explicit NT profile.

## kexnt imports only KERNEL32 and ADVAPI32

This was learned on the first real run. KernelEx initialises API libraries *before* the program's own DLLs. When
kexnt imported `msvcrt.dll`, msvcrt's DllMain ran during that early phase. It called `TlsAlloc`, which reached
KernelEx's `kexbasen` before kexbasen was initialised, and Windows page-faulted in `_EnterSysLevel(NULL)`.
KERNEL32 and ADVAPI32 live in the shared arena and are never re-routed, so they are safe. Everything else is
looked up at call time. The Makefile rejects any other import.

## Write from documentation and measurement, never from Microsoft code

Each function is written from:
- Microsoft's public documentation;
- open-source projects' published behaviour (Wine/ReactOS structure layouts, Chromium and Firefox source);
- measurements on real Windows 98 (probe programs).

Disassembly of Windows 98's own KERNEL32 is used only to learn *where* to hook, for example the exception
dispatcher's address and prologue, and never to copy code. No Microsoft binary is redistributed.
"Bring your own Windows 10 DLL" (ucrtbase, DWrite) is the only way genuine Microsoft code enters a test machine.

## Do not patch the programs

No browser is modified and no switch is injected into a program. Chromium and Firefox are treated like any other
program; only the operating system underneath changes.

There is one opt-in exception, the KernelEx tab option "Report real OS version to websites". It uses each
browser's own documented override mechanism: a user-agent pref file for Gecko, the `--user-agent` command line
for Chromium.

## Keep old CPUs working

Our code is built with `-march=i686 -mno-sse`, and `check_nosse.py` checks every binary. Modern browsers need
SSE2 anyway, but KernelEx-NG itself must not stop a Pentium II from booting.

## Windows 98 PE rules

Our DLLs are built with:
- subsystem version 4.0;
- no ASLR and no NX flags;
- the `.reloc` section kept, because Windows 98 must be able to move a DLL;
- a fixed, unique base address for each DLL (`dll_base.py`).

The last rule exists because a 277 MB `chrome.dll` was once moved by 64 KB because one of our small DLLs sat at
the default base. Windows 98 then did not apply its relocations. `reloc_ext.c` is the safety net.

## Prefer a leak over a wrong free

When shared state cannot be cleaned up with certainty, it is left alone. An example is blocks lent in the shared
arena whose owner may still be alive. A few megabytes leaked until a reboot is better than freeing memory that
another process is using.

## Bounded waits in diagnostics

The diagnostics must never become the bug. Logging locks are bounded (`kex_spin_try`): a log line is dropped
rather than waiting forever. The profiler and the VxD-call trace exclude each other. Both rules exist because
builds 130–131 froze Windows *only* when tracing was on.

## Measure, then decide what to emulate

Missing functions were found with tools, not by browsing documentation:
- `GPA.EXE` asks KernelEx's resolver for every import of a program;
- `KEXIMP.EXE` lists all missing imports at once (Windows 98 shows only the first);
- the import scanners in `tools/re_scripts/` produce Chromium and Firefox gap reports.

Every new module's header names the program and the failure that led to it.
