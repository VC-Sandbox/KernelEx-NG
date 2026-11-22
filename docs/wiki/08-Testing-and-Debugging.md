# 8. Testing and debugging

On Windows 98 you cannot attach a modern debugger, and attaching Windows 98's own debugging API changes how
KernelEx resolves functions. KernelEx-NG therefore carries its own instruments, plus a self-test suite and an
automated VM.

## kextest: the self-test

`KEXTEST.EXE` (`tests/kextest.c`) is a normal NT program that exercises kexnt through the real KernelEx routing.
It has about 770 checks in about 60 sections, for example:
- SRW/CV/WaitOnAddress;
- FLS and VEH (it deliberately causes an access violation, an int3 and `RaiseException`, and catches them);
- the PEB, locale names, pipes, shared memory, completion ports, the registry, process ids;
- layered windows, DirectWrite, audio and many more.

It writes `kextest.log`; the exit code is the number of failed checks. Modes:

| Command | Purpose |
|---|---|
| `kextest` | the full run |
| `kextest stress` | everything 10× with threads |
| `kextest only srw cv layeredx ...` | named sections in that order (bisecting a hang) |
| `kextest loadlib <dll>` | load a DLL step by step |
| `kextest only hangdump` | ask every running kexnt process for a thread dump |

Other test tools:
- `KEXROUTE.EXE` checks that every static import resolves into kexnt.
- `KEXCFG.EXE` shows which `core.ini` configurations KernelEx really loaded.
- `VERTEST.EXE` shows the version a profile reports.
- `UCRTLOAD.EXE` / `UCRTTEST.EXE` test Windows 10's ucrtbase.
- `KEXIMP.EXE <exe>` lists every missing import at once.

## Logs written next to the program

All of these appear only for modern (NT) programs.

| Log | When | Contents |
|---|---|---|
| `KEXCRASH_<prog>.LOG` | always | every exception: module+offset, registers, EBP chain, stack values pointing into modules, text found on the stack (Chromium copies its `CHECK` message there); plus one-line notes from kexnt ("refused class 4", "lent block", ...) |
| `KEXHANG_<prog>.LOG` | 30 s / 75 s after start if nothing was drawn, or on request | every thread's EIP, EBP frames and stack values, collected without taking KERNEL32's locks |
| `KEXTRACE_<prog>.LOG` | `TRACEON.REG` | API-level trace lines (DNS lookups, guard events, ...) |
| `KEXPROF_<prog>.LOG` | `PROFON.REG` | sampling profile: time per module and thread, the hottest addresses, guarded GDI/USER call counts and cycles |

The hang dump turned out to be the most useful of these. To read it:
1. Find the thread that is waiting.
2. Find *what* it waits for (the kexnt function at its top: `kex_SleepConditionVariableSRW`,
   `kex_park`, ...).
3. Find which other thread should wake it, and what that thread is waiting for.

That chain is usually the whole bug. Mozilla publishes symbol files, so program offsets can be named exactly.
See [case studies](09-Case-Studies.md#firefox-115-froze-at-its-first-popup).

## KEXDBG

`KEXDBG.EXE` is a small Windows 98 debugger:
- `-attach <exe|pid>` attaches to a running process;
- `-log <file>` appends to a log file;
- breakpoints come from a file;
- every crash is logged in full.

`EXPLDBG.BAT` attaches it to Explorer to diagnose Explorer crashes. Use it when the in-process crash log is not
enough. Remember that under a debugger, Windows 98 hands out debug thunks, which changes KernelEx's behaviour.

## Probes

`probes/*.c` are tiny one-question programs. Each answers a single question on real Windows 98, for
example:
- "does `VA_SHARED` memory survive process exit?" (`lprobe.c`);
- "what does `GetProcAddress` return for X in mode Y?" (`gpa.c`);
- "does FormatMessageW leave an error code?" (`fmsg.c`).

When documentation and reality might differ, a probe settles it before code is written.

## The automated VM

Testing on real Windows 98 is the only test that counts. The developers' harness (not part of this repository: it is
tied to one particular VM setup) drives a Windows 98 SE QEMU VM without a person at the keyboard:

- `agent/vmagent.sh` / `boot.sh` start QEMU. Options: KVM or TCG, the CPU model with AVX hidden, `SNAP=1` to
  discard all disk writes, `MEM=`, and QMP control.
- `AGENT.EXE` (`agent/agent.c`) runs inside Windows 98. It polls a small HTTP server (`agent/server.py`) for
  commands: run, ps, kill, ls, get, upload, wins, click, regq, off.
- `ac.sh "<command>"` sends one command and prints the result.
- `inst.sh` installs the freshly built CD in the guest and reboots it.
- `try.sh` runs kextest and reports a hang.
- `ffrun.sh` starts Firefox with logging.
- `tdump.sh` summarises hang dumps.
- `key.py` / `mouse.py` / `shot.sh` send keystrokes and mouse input and take screenshots through QMP.
- `hmp.py` runs any QEMU monitor command. Sampling the guest's EIP this way found the disk-I/O storm in build 132.
- `disk/nbdfat.py` reads files out of a stopped VM's disk image.

Disk speed in QEMU/KVM: switch the guest disk to DMA (`agent/dma_on.sh`). Measured on 2026-11-21:
- KVM batches PIO *reads* (`rep insw`) but exits to QEMU for every word of PIO *writes* (`rep outsw`). That is about
  300 exits per sector, so writeback ran at about 125 KB/s and froze the guest whenever Firefox wrote its profile
  or Windows paged.
- Windows 98's own "DMA" setting (`IDEDMADrive0` on the channel's `hdc` class key) moves whole blocks per command.
  Port exits dropped from 80,000/s to about 1,500/s.
- Data was verified by a checksum after a reboot.

Safety rules the harness follows:
- Never kill QEMU while Windows runs; shut down from inside the guest.
- Never start a second QEMU.
- Experiments that might damage the disk run with `SNAP=1`.

## Release checklist (per build)

1. Raise `KEXNG_BUILD`.
2. Full kextest in the VM: it must reach the end with no unexplained failures.
3. Update the notes (`new_stubs/ARCHITECTURE.md`, `docs/wiki/`) and the CD's `README_ISO.TXT` test steps.
4. Build the ISO and a source archive.
