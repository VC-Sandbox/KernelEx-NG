# 4. Core techniques

These are the problems that needed more than "write the missing function". Each section covers the problem,
what Windows 98 offers, the solution, and its limits.

## A PEB for NT code

**Problem.** NT code reads the Process Environment Block directly. `mov eax, fs:[30h]`, then for example
`[eax+18h]` = process heap or `[eax+10h]` = process parameters. On Windows 98, `fs:[30h]` points to the
*process database* (PDB). `PDB+0x10` is the termination status (`0x103`), so Windows 10's `ucrtbase.dll`
dereferenced address `0x10B` and crashed.

**Why not just change `fs:[30h]`?** KernelEx itself and Windows 98's KERNEL32 read the PDB through that same
slot. Changing it would break the system.

**Solution (`peb_ext.c`).** Patch the *instructions* instead of the data:
- Every module built for NT 6+ (OS or subsystem version ≥ 6, private arena, not ours) is scanned once, before
  its own code runs.
- `mov reg, fs:[30h]` (6 or 7 bytes) is rewritten to `call kex_peb_<reg>` plus `nop`s. The helper loads the
  address of an **emulated Windows 10 PEB**, without touching the flags, like the original `mov`.
- The emulated PEB has real contents: process parameters (image path, command line, current directory,
  environment), process heap, OS version from the profile, a loader-lock object, and `Ldr` module lists that
  `LoadLibrary` keeps up to date.

**When the patch runs.** At the right moment: an API-set DLL's DllMain runs before the DllMain of the module that
imports it, so it patches its importer. DLLs loaded later are patched by kexnt's `LoadLibrary`.

**Limits.** Rare forms (`push fs:[30h]`, `cmp`, TEB→PEB through another register) are counted, not patched.
Offline, 5,003 sites in 28 Windows 10 DLLs were all checked to lie on real instruction boundaries.

## Vectored exception handling

**Problem.** `AddVectoredExceptionHandler` (VEH) is used by the MSVC runtime, Chromium, Firefox and many others.
Windows 98 has only frame-based SEH.

**Reverse engineering.** Windows 98 SE has exactly one user-mode exception dispatcher in KERNEL32. Both software
exceptions (`RaiseException`) and hardware ones (a ring-0 callback sets the client EIP to it) pass through it.
Its prologue is a fixed byte sequence.

**Solution (`veh_ext.c`).**
- The first 6 bytes of the dispatcher are replaced with a jump, written atomically with one `cmpxchg8b`. The
  jump goes to a small permanent stub.
- The stub looks up, with plain loads only (no locks, no allocation, because exceptions can happen anywhere),
  whether the *current process* has VEH handlers. It reads them through a slot in KernelEx's per-process storage.
- **No handlers** (every Windows 98 program): it runs the original dispatcher.
- **Handlers present:** they are called in order. `EXCEPTION_CONTINUE_EXECUTION` resumes at the possibly-changed
  CONTEXT through KERNEL32's own "continue" routine (the one it uses for debuggers). Anything else falls through
  to the normal path.
- If the KERNEL32 build is unknown, nothing is patched. Registration still succeeds, and the fact is logged.

The same hook gives the **crash logger** its place: kexnt registers an observing handler first, which writes
`KEXCRASH_<program>.LOG` and always continues the search.

## Locks without kernel support

**Problem.** SRW locks, condition variables, `InitOnce` and `WaitOnAddress` need keyed events or a futex.
Windows 98 has only events, mutexes and semaphores.

**Solution (`sync_ext.c`): a parking lot.**
- A hash table of wait queues, keyed by address. Each waiting thread sleeps on its own auto-reset event, created
  lazily and kept in TLS.
- The waiter checks the value and enqueues itself *under the bucket lock*. A waker changes the value *before*
  taking that lock. So a wake-up can never be lost: the classic futex contract.
- On top of the parking lot:
  - `WaitOnAddress`: exact semantics.
  - **SRW**: one pointer-sized word (exclusive bit, waiters bit, shared count).
  - **Condition variables**: a sequence counter.
  - `InitOnce`, and later `RtlRunOnce`.

**Limits (deliberate).** SRW prefers readers and wakes all waiters (98 has one CPU, so fairness costs more than
it gains). FLS is per thread, not per fiber.

## Fiber local storage

Every MSVC runtime since 2005 calls `FlsAlloc` at start-up. `fls_ext.c` implements it with one Windows 98 TLS slot
per thread, pointing to a block of values. A global list of blocks lets `FlsFree` run the destructor for every
thread, as NT does. Destructors run on `DLL_THREAD_DETACH`.

## Static TLS in DLLs loaded later

**Problem.** Windows 98 sets up `__declspec(thread)` / `thread_local` data only for DLLs loaded at process start.
`chrome.dll` is loaded later, has six TLS callbacks and relies on Vista's behaviour. Without that, its first
`thread_local` access read another module's slot.

**Solution (`tls_ext.c`).**
- On `LoadLibrary`, allocate a TLS slot and write it to the module's `AddressOfIndex`.
- Give every existing thread a copy of the template.
- Hook thread start so that new threads get theirs.
- Fire the module's TLS callbacks.

On 98, `fs:[2Ch]` points at the same per-thread slot array that `TlsSetValue` writes, so compiled code finds the
data.

## Named pipes

**Problem.** Windows 98 can open pipes on an NT server but cannot create one. Chromium's Mojo IPC and Crashpad
need pipe servers.

**Solution (`pipe_ext.c`).**
- **Each pipe end is a named event.** That makes it a real kernel handle, so `CloseHandle`, `DuplicateHandle` and
  inheritance into child processes all work natively.
- The data goes through ring buffers in a shared-arena block.
- kexnt recognises a pipe handle by the address of its kernel object, which is the same in every 9x process.
- Liveness ("is the other end still open?") comes from the named object's reference count.
- Overlapped I/O and completion ports are wired in (`iocp_ext.c`).

## Shared memory with NT rules

**Problems in Chromium's shared-memory code (`shm_ext.c`).**
- `CreateFileMapping` must reset the last error to 0. Windows 98 left a stale `ERROR_ALREADY_EXISTS`, and
  Chromium treats that as fatal.
- Security descriptors and `PAGE_EXECUTE_*` flags must be accepted. Windows 98 rejects them, so they are mapped
  down.
- Read-only duplicates of a section must work.
- **Two views of one section in one process** are needed, and Windows 98 cannot do that from user mode.
  `KEXALIAS.VXD` creates the second view in ring 0.

A related problem was **file views that follow `WriteFile`** (`fview_ext.c`). SQLite reads a database through a
read-only mapping of the same handle it writes with. On NT those share one cache; on 98 they do not, so every
fresh Chromium profile broke. A read-only view of a file opened for writing therefore becomes a private copy that
kexnt updates on every `WriteFile`.

## Memory above 2 GB

**Problem.** A *large-address-aware* 32-bit program gets 4 GB on 64-bit Windows. On 98 it has 2 GB, and
Discord's tab in Chrome ran out.

**Solution (`laa_ext.c`).** When the private 2 GB cannot hold a reservation, it is placed in the **shared arena**
(0x80000000–0xBFFFFFFF) with an undocumented `VA_SHARED` flag. Probes measured that commit, decommit and protect
work there like private memory, but **Windows does not free those blocks when the process dies**. So kexnt keeps a
system-wide table of lent blocks and their owners, and sweeps the blocks of ended processes. The rules prefer a
leak over a wrong free:
- only reservations, at most 32 MB each;
- the arena always keeps at least 128 MB free;
- a block is freed only if Windows still shows exactly that allocation.

## Process ids

**Problem.** A Windows 98 process id is an obfuscated pointer with the top bit set (0xFFFxxxxx). NT ids are
small positive numbers. Firefox passes its id to children as text and reads it back with `strtol`, which saturated
to 0x7FFFFFFF, so the IPC endpoint check failed.

**Solution (`pid_ext.c`).** Modern programs see every id with the top bit cleared. That covers about 25 functions:
`GetCurrentProcessId`, Toolhelp, `GetWindowThreadProcessId`, pipes, jobs, and more. Ids handed in get the bit set
again. Inside kexnt, ids stay real. Windows 98 programs (through the gates) see the real ids.

## An NTDLL that can be read

**Problem.** Windows 98's NTDLL exports almost nothing. kexnt's NTDLL functions reach programs through KernelEx's
`GetProcAddress`. But Chromium's sandbox **parses NTDLL's export table itself** to find the functions it patches
in a child process, and found none.

**Solution (`ntfacade_ext.c`).** For modern programs, `GetModuleHandle("ntdll.dll")` returns a **facade**: a
private block shaped like a PE image. Its export directory lists kexnt's NTDLL gates plus Windows 98 NTDLL's own
exports. The gates the sandbox patches are generated in the byte shape of NT system-call stubs. Every API that is
given the facade handle (`GetProcAddress`, `GetModuleFileName`, `FreeLibrary`) works on the real NTDLL.

## Child processes and handle inheritance

**Problem.** Chromium launches children with `SetHandleInformation(HANDLE_FLAG_INHERIT)` plus a handle list, and
passes the handle *numbers* on the command line. On 98, `SetHandleInformation` always fails.

**Solution (`procspawn_ext.c`).** Windows 98 keeps the inherit bit inside the process handle table entry itself,
and `CreateProcess` copies inheritable entries to the *same* slot numbers in the child. kexnt sets and clears that
bit in place, after checking the table layout.

## Guarded GDI/USER calls

Mypal crashed three times at one instruction with garbage in ESI/EDI right after a few GDI calls: a Windows
98/KernelEx call returned with registers changed. kexnt now calls about 1,100 USER32/GDI32/WINMM functions
through a **guard** (`gdiguard_ext.c`, generated `guard_gen.c`). The guard calls the implementation that would
have run anyway, then restores ESP/EBX/ESI/EDI/EBP and logs a line if they had changed. The same layer feeds the
profiler and the hang detector ("has anything been drawn yet?").

## Layered (translucent) windows

Windows 98 cannot blend a window with what is behind it, but it **can shape** a window. kexnt's
`UpdateLayeredWindow` (`layered_ext.c`) builds a window region from the alpha channel. Pixels below half opacity
are cut out, and rows with the same runs are merged into rectangles. Menus and popups then get their rounded
shape without black corners.

The update can come from a thread that does not own the window (Firefox's Renderer thread). Any move or region
change is then **queued for the owner thread** instead of sending it a message and waiting, because that wait
deadlocked Firefox (see [case studies](09-Case-Studies.md#firefox-115-froze-at-its-first-popup)).

## Memory status that matches NT

Windows 98 counts only completely unused pages as "available". The disk cache (VCACHE) takes almost everything
else, although it gives pages back on demand. Chromium saw "critical memory pressure" all the time and threw its
caches away every 5 s. `memstat_ext.c` counts the cache above its minimum as available, as NT does with its
standby list, reading 98's own performance counters.
