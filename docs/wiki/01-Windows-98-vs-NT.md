# 1. Windows 98 vs. Windows NT

To see why a Windows 10 program will not start on Windows 98, you need to know that the two systems are only
cousins.

## Two operating systems behind one API

| | Windows 98 SE | Windows NT family (XP … 11) |
|---|---|---|
| Kernel | VMM + VxDs (32-bit), with large parts of the old 16-bit Windows (USER.EXE, GDI.EXE) still in charge | NT kernel (ntoskrnl), fully 32/64-bit |
| User-mode base | KERNEL32 talks to VMM/VxDs directly | NTDLL is the single doorway to the kernel ("system calls"); KERNEL32 sits on top |
| CPUs | uses one CPU | many CPUs |
| Address space | 0–2 GB per process, **0x80000000–0xBFFFFFFF shared by all processes** (system DLLs, shared memory), 0xC0000000+ kernel | 0–2 GB (or 4 GB on 64-bit) private, the rest kernel only |
| Security | none: no users, tokens, ACLs | everything is a secured object |
| Unicode | mostly ANSI; most `...W` functions are stubs | Unicode throughout |
| Locking | `Win16Mutex` serialises much of USER/GDI | fine-grained |

The Win32 API was designed so that programs could run on both families, up to roughly Windows 2000/XP. After
that, Microsoft built new APIs **only** for NT, and modern compilers and runtimes depend on them.

## What a modern program expects that 98 lacks

There are four layers of problems, from easy to hard:

1. **Missing functions.** A static import such as `KERNEL32!AcquireSRWLockExclusive` that does not exist stops
   the program before it starts: "The X.EXE file is linked to missing export KERNEL32.DLL:…". There are
   *thousands* of these between 98 and 10.
2. **Missing DLLs.** `bcrypt.dll`, `dwmapi.dll`, `api-ms-win-core-synch-l1-2-0.dll`, … do not exist at all.
3. **Different behaviour behind the same name.** A function exists on 98 but behaves differently. These failures
   are silent and the hardest to find:
   - `SwitchToThread` does nothing.
   - `LockFileEx` cannot share a lock.
   - Process ids have their top bit set.
   - A file mapping does not see `WriteFile` changes.
4. **Different data structures.** NT code reads NT internals directly. The typical example is `mov eax, fs:[30h]`
   to get the PEB. On 98, the same instruction gives the process database, with a completely different layout.
   No function call is involved, so no API layer can intercept it.

## Hard limits no software can lift

- **CPU instructions.** Windows 98 never enables AVX state saving. A program that uses AVX crashes the moment two
  threads both use it. That is why AVX must be hidden from the guest, after which programs fall back to SSE.
- **One CPU.** Windows 98 schedules on one core. Programs still run; they are just not parallel.
- **The 2 GB private address space** and the **shared arena.** Both can be worked around partly
  (see [Core techniques](04-Core-Techniques.md#memory-above-2-gb)).
- **Kernel-level features** like real object security, ALPC, or a kernel-mode sandbox. These can only be
  *answered* (accepted, refused or faked consistently), not truly provided.

## What "making it run" therefore means

For each thing a program needs, there are three possible answers:

1. **Provide it for real** on top of what 98 has. Example: SRW locks built from events.
2. **Emulate it well enough**, keeping NT's documented contract. Example: NT process ids, a PEB that looks right.
3. **Fail it properly**: return the exact error NT returns when the feature is absent, so the program takes its
   own fallback path. Example: `SetProcessMitigationPolicy` → `ERROR_NOT_SUPPORTED`.

What you must **never** do is return "success" with garbage. That turns an easy, visible failure into a crash
far away, which costs days to trace. This rule runs through the whole project (see
[Design decisions](06-Design-Decisions.md)).
