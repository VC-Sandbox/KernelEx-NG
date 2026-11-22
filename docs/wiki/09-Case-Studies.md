# 9. Case studies

Real bugs from the project, each told as **symptom → evidence → cause → fix**. They show the method more clearly
than any rule.

## Firefox 115 froze at its first popup

- **Symptom.** Firefox drew its window, then stopped repainting and taking input whenever a popup (the URL bar
  dropdown, a menu) appeared.
- **Evidence.**
  1. A thread dump (`kextest only hangdump`) was symbolised with Mozilla's published symbols for that exact build.
  2. **Main thread:** `nsWindow::OnPaint` → `WebRenderLayerManager::FlushRendering` → a *synchronous* IPC to the
     compositor, waiting.
  3. **Compositor thread:** `FlushRendering` → `WebRenderAPI::WaitFlushed`, waiting for the Renderer.
  4. **Renderer thread:** `RenderCompositorSWGL::EndFrame` → `RedrawTransparentWindow` → `UpdateLayeredWindow` →
     KernelEx 4.5's implementation. The return address on the stack was the instruction right after
     `call MoveWindow`.
- **Cause.** `MoveWindow` on a window owned by another thread sends that thread messages and waits for the
  answer. The owner was the main thread, which was waiting for the Renderer. Each thread was waiting for the
  other, so it was a deadlock.
- **Fix.** kexnt's `UpdateLayeredWindow` does the move and the blit itself:
  - no move when the position and size are unchanged;
  - a move requested by another thread is **queued** for the owner thread and applied at its next USER call,
    with a `WM_NULL` posted to wake it.
  - A kextest check reproduces the pattern: one thread blocks, another updates its window, and the call must
    return within 2 s.

## Firefox 115 child processes could not talk to the parent

- **Symptom.** Content processes started and then failed an assertion in the parent's IPC endpoint code.
- **Evidence.** The command line of the child held the parent's process id 4294401411. Mozilla's code reads it
  back with `strtol`, which saturates at 0x7FFFFFFF.
- **Cause.** Windows 98 process ids have the top bit set. NT ids never do, and programs rely on that.
- **Fix.** NT-style ids for modern programs everywhere an id leaves or enters the system (`pid_ext.c`).

## A loaded DLL was "not found" when asked for with LOAD_LIBRARY_SEARCH_SYSTEM32
- **Symptom.** Supermium with its own `DWrite.dll` (Microsoft's DWriteCore, relinked against Supermium's
  `pwrp_k32.dll`) logged `LoadLibrary failed: pwrp_k32.dll flags 00000800 error 126`, although the DLL is already
  loaded: DWrite imports it.
- **Cause.** NT checks the list of loaded modules before searching any folder, whatever `LOAD_LIBRARY_SEARCH_*` flags
  are passed. kexnt's handling of `SEARCH_SYSTEM32` and `SEARCH_APPLICATION_DIR` only looked in those folders.
- **Fix** (`loader_ext.c`). A bare name that is already loaded resolves to that module, with its reference count
  raised, before any folder is searched.
- **Not yet enough for DWrite.** Supermium's DirectWrite still fails in `GetSystemFontCollection` with
  `DWRITE_E_UNEXPECTED` (probe `dwf.c`), although every font file analyzes fine on its own. The Windows 10 DWrite
  finds 12 families on the same system. The failure is in DWriteCore's bounds-checked reader while it builds the
  collection, not in plain font file I/O. Until that is found, the DWrite KnownDLLs redirect stays.

## A program's own api-ms-win-*.dll files would not load (bundled-DLL rule)
- **Goal.** Programs such as Mypal and Firefox 52 ship Microsoft's app-local `api-ms-win-*.dll`, `ucrtbase.dll` and
  `vcruntime140.dll`. They must load those files, not copies redirected from SYSTEM.
- **Cause 1, measured (`probes/rlc.c`).** The second `api-ms` DLL failed with error 11. All of them ask
  for base 0x10000000, have an empty relocation directory and do **not** have "relocations stripped" set.
  - NT moves such a DLL, since there is nothing to fix up.
  - Windows 98's KERNEL32 (0xBFF87A7A) moves a DLL only when its relocation directory is larger than 4 bytes.
  - The same file with a directory size of 8 loaded at 0x00C80000.
- **Fix 1.** A KERNEL32 patch (`veh_ext.c`, "DLLs without relocations") also moves a DLL when "relocations
  stripped" is clear and it was built for NT 5+ (MajorSubsystemVersion). DLLs built for Windows 9x keep the old rule.
  - Checked: Mypal's DLL → moved; the same DLL marked subsystem 4.0 → error 11; with "relocations stripped" → error 11.
  - This replaces the build-125 workaround that loaded a moved temp copy (Visual C++ 2010 setup's
    `SetupResources.dll`, subsystem 5.1, is covered).
- **Cause 2, measured.** Windows reported "The UCRTBASE.DLL file is linked to missing export
  API-MS-WIN-CORE-HEAP-L1-1-0.DLL:HeapQueryInformation", although KernelEx provides that function.
  - A DLL outside SYSTEM has no KernelEx API table, so KernelEx resolves its forwarders itself
    (core/resolver.cpp `OriExportFromOrdinal`: GetModuleHandle + GetProcAddress).
  - That GetProcAddress call comes from KernelEx.dll, a shared module, and shared modules always get the plain
    Windows 98 API.
- **Fix 2.** For forwarding DLLs built for NT 5+, the call is made from a stub in a shared page that belongs to no
  module. KernelEx then uses its documented fallback: the program EXE's configuration, which is what a direct
  `kernel32` import gets, as on NT.
  - Result: Mypal's own `ucrtbase`, `vcruntime140` and `msvcp140` load from its folder (explicit LoadLibrary).
- **Cause 3, measured.** At Mypal's start Windows reported "The VCRUNTIME140.DLL file is linked to missing export
  API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL:terminate".
  - That forwarder points to `ucrtbase`, which nothing imports directly. NT loads a forwarder's target on demand.
  - Loading it during the new process's import resolution deadlocked the whole system. This happened with
    LoadLibrary and also with KernelEx's own `MRLoadTree` method.
  - GetProcAddress at the same point is fine: probe `fwe.c` imports through Mypal's forwarder DLL at process start.
- **Fix 3** (`fwdload_pic.c`). A forwarder whose target is not loaded becomes a 10-byte thunk. Its first call, made
  outside the loader, loads the target (the program's own folder is searched first), resolves the function with
  the program's configuration and rewrites the thunk into a direct jump.
  - The code runs in every process, so it is position independent and copied into a shared page. The build
    (`check_pic.py`) fails if it ever needs relocations.
  - Limitation: a forwarded data export imported before its target loads would get the thunk's address. The CRT
    sets forward only two (`_mbcasemap`, `__dcrt_initial_narrow_environment`), and no Mypal module imports them.
- **Result.** The api-set KnownDLLs redirect and the loader's `apiset_redirect` are removed.
  - Mypal and Pale Moon load every `api-ms`, `ucrtbase`, `vcruntime140` and `msvcp140` file they ship from their
    own folder, and Mypal opens HTTPS pages.
  - Mypal's start used 184 thunks, 50 of them called, and loaded `ucrtbase` once.
  - Firefox 115 and kextest (835/0) are unchanged.
  - Firefox 52 still crashes, as it did before this work: a use-after-free in firefox.exe while starting a content
    process.
- **Boot.** All patches are installed at every boot (RunServices `KexNGLoader`: `rundll32 KEXNT.DLL,KexNGBoot`),
  before the first program maps its DLLs, and again when a modern program starts.

## Basilisk: noise and grey lines in the title-bar icons
- **Symptom.** In Basilisk's tab strip (drawn into the caption), the transparent pixels of the "+" new-tab icon showed
  as white or coloured noise, and the tab-edge image in the top-left corner showed grey diagonal lines. The noise
  changed from run to run.
- **Evidence.** A traced AlphaBlend pass-through showed the icon *source* bitmaps already held non-zero data in pixels
  that should have been fully transparent (for example 0x44662f at the top left). Probe `probes/dibz.c`
  dirtied and freed some DIB sections, then created new ones: on Windows 98 a new 16x16 or 24x24 DIB section had every
  byte non-zero (left-over heap data), while 64x64 and larger came out zeroed.
- **Cause.** NT always returns zero-filled memory from `CreateDIBSection` (no section handle) and programs rely on it,
  drawing only the opaque parts of an icon into a fresh 32-bit DIB and compositing the whole bitmap with its alpha.
  Windows 98 hands out small DIBs from a heap without clearing them.
- **Fix.** `kex_CreateDIBSection` (`gdiguard_ext.c`) zero-fills the bits of new uncompressed DIB sections that are not
  backed by a file mapping, for modern programs. After the fix the probe reads zero at every size and the title bar is
  clean over repeated starts.

## Basilisk / Pale Moon: labels lost their last character, tab titles came out in pieces

- **Symptom.** "Cu" for "Cut", "Cop" for "Copy", "Search or enter addres", and the tab title "Restore   S".
- **Ruled out by measurement.**
  - GDI text widths: three measuring methods agree (probe `textw.c`).
  - DirectWrite: disabling it changed nothing.
  - Gecko cropping the text: it draws the full string.
- **Evidence** (new opt-in trace `KexNG\TextTrace=1`, which logs every `ExtTextOutW` with its glyphs, advances and
  font):
  - The labels are drawn in **MS Serif**, a Windows 98 bitmap font.
  - The options are 0x2010: glyph indices plus **`ETO_PDY`**. That Windows 2000 flag makes `lpDx` hold an x *and* a
    y advance per glyph: `7 0 5 0 4 0 ...`.
- **Causes.**
  1. Windows 98 does not know `ETO_PDY` and reads the pairs as x advances, so every second glyph gets 0.
  2. Windows 98 does not draw a bitmap-font glyph whose advance is 0. Probe `etog.c` with "Copy": an array ending in
     0 loses the "y"; TrueType is not affected. Gecko ends every run with a 0 advance (NT ignores the last advance).
- **Fix** (`gdiguard_ext.c`, in this order):
  1. `ETO_PDY` pairs are converted to plain x advances and the flag is cleared.
  2. For bitmap fonts only, a final advance of 0 is raised to the font's widest character, in a private copy.
- **Lesson.** A first fix that only did step 2 broke the page text, because it changed a y value inside an
  unconverted pair array. The trace of the real arguments showed why.

## Basilisk: the window "smeared" when restored or dragged

- **Symptom** (found with your hint: restore the window, then drag it). Thin lines of the window stayed on the
  desktop at its old edges, and parts of the UI did not update.
- **Evidence**, using a new optional trace (`KexNG\WinPosTrace=1`) that logs each move's `WINDOWPOS` after the
  program handled it, plus every blit into a top-level window:
  - Basilisk does **not** suppress repainting: its flags are normal, with no `SWP_NOREDRAW` or `SWP_NOCOPYBITS`.
  - The device contexts it draws with are **not** stale: their origin and clip always matched the window.
  - Its **compositor thread keeps blitting into the window while Windows is moving it**, between
    `WM_WINDOWPOSCHANGING` and `WM_WINDOWPOSCHANGED`, on a different thread from the one the move runs on.
- **Cause.** Windows NT serialises other threads' drawing against a window move; Windows 98 does not. A blit that
  lands between the move copying the window's pixels and the new visible region taking effect leaves pixels at the
  old position.
- **Fix** (`gdiguard_ext.c`). kexnt's always-on message hook notes which top-level window is being moved. A
  `BitBlt`, `StretchDIBits` or `SetDIBitsToDevice` into that window from another thread waits until the move is
  done, for at most 200 ms.
- **Measured.** Before the fix, 2 of 2 drags left stray pixels (24 and 264). After it, 5 of 5 drags left none, and
  Restore was clean too.

## K-Lite Codec Pack: "Setup: Interface not supported", then a silent rollback

There were three separate causes, each proven before the fix:

1. **ShellLink without `IPropertyStore`.**
   - Inno Setup 6 casts the shortcut object to `IPropertyStore` to set Windows 7 taskbar properties.
   - A probe (`probes/slq.c`) showed Windows 98's ShellLink answers `IShellLinkA/W` and `IPersistFile`
     only.
   - Fix: kexnt wraps ShellLink objects with a small property store; the shortcut itself is still made by
     Windows 98.
2. **No task dialogs.**
   - Inno 6.4 shows *every* question through `TaskDialogIndirect` (COMCTL32 6). Without it, the answer is "Abort",
     so one optional DLL that could not register rolled back the whole install.
   - Fix: a real task dialog built from an in-memory dialog template (`taskdlg_ext.c`).
   - First attempt failed: kexnt called Windows 98's own `DialogBoxIndirectParamW`, which is an empty stub. It now
     uses KernelEx's Unicode implementation.
3. **Windows Media Player crashed in `LAVVIDEO.AX`.**
   - EAX = 0x103: NT code read `fs:[18h]`→`[+30h]` and got Windows 98's process database.
   - In a Windows 98 program (WMP), kexnt's PEB patcher ran only when an `api-ms` shell loaded. DirectShow loads
     LAVVideo later through OLE32, so it was never patched.
   - Fix: once kexnt patches NT modules in a process, its DLL-entry hook is switched on, so every later NT 6+ DLL is
     patched before its DllMain.
   - Then H.264, HEVC, VP9 (WebM/MKV) and AV1 played in WMP 6.4.

**Method note:** read the installer's own log (`/LOG=`); it names the failing step exactly.

## Pale Moon: "bookmarks and history ... in use by another application"

Two Windows 98 differences, both inside SQLite's write-ahead log (WAL), which Places uses:

1. **Shared one-byte locks.**
   - SQLite's WAL index (`-shm`) is locked one byte at a time. Every connection holds the byte at 0x80 *shared*.
   - kexnt's shared-lock emulation needed a range to pick a random byte from, so a one-byte shared lock became an
     exclusive one, and the second connection got "busy".
   - Found with kexnt's lock trace (`KexNG\LockTrace=1`).
   - Fix: a shared table of one-byte shared locks across processes, keyed by the file's path.
2. **Growing a file that another handle has locked.**
   - Since 3.4x, SQLite opens the `-shm` file twice: one handle per connection holds the locks, and a shared
     handle grows and maps the file.
   - Windows 98's `SetEndOfFile` refuses (error 33) while another handle holds a byte-range lock in the file; NT
     does not.
   - Found by building the test tool against the *same* SQLite version Pale Moon ships (3.54.1). The older 3.38 in
     the repo passed, which hid the bug.
   - Fix: when `SetEndOfFile` is refused this way, this process's locks on that file (other handles) are lifted
     for the call and taken again, under the cross-process mutex.

Places then created its database, and both the bookmarks toolbar and the address bar worked.
**Method notes.**
- The test tool had been running KernelEx 4.5's old functions, because it lacked the "modern program" marker
  and the gate sent it the old code. Check that a test exercises the code you think it does.
- Test against the library version the program actually uses.

## Firefox 115 turned every address into a web search

- **Symptom.** Typing `http://example.com/` and pressing Enter started a Google search for that text.
- **Evidence.** The Browser Console (Ctrl+Shift+J) showed the URI fixup service failing in its constructor:
  `URIFixup.sys.mjs:263` → `nsIExternalProtocolService.externalProtocolHandlerExists` →
  `NS_ERROR_NOT_AVAILABLE` (0x80040111).
- **Cause.** Mozilla's Windows code answers that question with the Vista shell class
  `ApplicationAssociationRegistration`, created once with `CoCreateInstance`. Windows 98 has no such class, so
  the pointer stays NULL and every protocol query fails. Without the fixup service, all input is treated as a
  search.
- **Fix.** kexnt's `CoCreateInstance` answers that class with a small object (`assoc_ext.c`). Its answers come
  from `HKEY_CLASSES_ROOT`, the same data Windows 98's shell uses. Firefox 115 then loaded HTTPS pages.
- **Method note.** One look at the program's own error console replaced hours of guessing.

## Firefox 115 died at start with c06d007e

- **Evidence.** The crash code `c06d007e` is the MSVC delay-load "module not found" exception. Just before it,
  kexnt logged `LoadLibrary failed: AVRT.dll`.
- **Fix.** A stub `avrt.dll`. It returns a success handle but does *not* raise thread priority: on one CPU, a
  time-critical thread could starve the whole system.

## The full test froze Windows at [DirectWrite]

- **Symptom.** The full kextest froze Windows at the same section every time. The section alone passed.
- **Wrong leads.** Earlier changes to the TLS code, and differences between two VM images. Experiments ruled both
  out: build 130's code hung the same way, and the image difference was only a diagnostics setting.
- **Evidence.** A lock-wait probe showed what happened:
  1. With tracing on, `ExitProcess` killed the trace-flusher thread while it held the trace-file lock.
  2. The next trace line spun forever on that lock.
  3. Separately, the VxD-call trace hook combined with the profiler's `SuspendThread` froze the system.
- **Fix.** Bounded log locks: drop the line after a timeout. The VxD-call trace is not installed while profiling.
  The lesson is that diagnostics must never block.

## Chromium blue-screened Windows 98

- **Symptom.** "Fatal exception 0D at 0028:BFF713DB" right after `chrome.dll` started.
- **Evidence.** The address is KERNEL32's VxDCall gate. The calls just before it were `VirtualProtect` /
  `VirtualAlloc` with addresses in the **shared arena**. Windows 98 accepts those; NT refuses them for user mode.
  A second cause was the PEB patcher itself, which wrote into `chrome.dll`'s code with `VirtualProtect`.
- **Fix.** `mem_ext.c` gives these calls NT's limits. The patcher writes through `WriteProcessMemory` instead of
  changing protections on huge images.

## chrome.dll ran with its relocations not applied

- **Evidence.** Code pushed the *unrelocated* address of its CRT initializer table. The module sat at 0x10010000
  instead of 0x10000000.
- **Cause.** One of our own small DLLs used the linker's default base 0x10000000. Windows 98 moved `chrome.dll`
  (277 MB) but did not apply its 10 MB of relocations.
- **Fix.** Every DLL we build gets its own base (`dll_base.py`). `reloc_ext.c` detects an unapplied move by
  sampling fixup sites and applies the relocations itself.

## Every fresh Chromium profile was broken

- **Symptom.** "Profile error occurred". SQLite logged "Failed to set up eq_classes table".
- **Cause.** SQLite in memory-mapped mode reads through a read-only view of the same file it writes with
  `WriteFile`. On NT both use one cache. On 98 the view shows stale data.
- **Fix.** A read-only view of a writable handle becomes a private copy that kexnt updates on each `WriteFile`
  (`fview_ext.c`).

## Mypal's address bar did nothing

There were two causes, both found from the browser's own error console:
1. Mozilla's `OS.File.stat()` opens a **directory** with `CreateFile`, which Windows 98 cannot do. The search
   service died on it, and the address bar with it. Fix: `dirhandle_ext.c`.
2. SQLite takes a **shared** lock with `LockFileEx`. KernelEx made every lock exclusive, so two connections to one
   database excluded each other. Fix: `lockfile_ext.c`, which uses SQLite's own Windows 95 scheme (each reader
   locks one random byte).

(Pale Moon shows the same symptom, but these fixes do not reach it. That is open work.)

## Chrome was slow: 44% of the time in one function

- **Evidence.** `KEXPROF_chrome.LOG` showed 44% of samples in `chrome.dll`'s `SwitchToThread` wrapper and in
  Windows 98's "not implemented" stub behind it.
- **Cause.** Windows 98's `SwitchToThread` returns at once without giving up the CPU. Every spin-wait in Chromium
  spun out its full time slice on a one-CPU machine.
- **Fix.** `yield_ext.c`: `Sleep(0)`, and every 8th call `Sleep(1)` so that lower-priority threads also run.

## Discord voice crashed the browser

- **Evidence.** `c000001d` (illegal instruction) at `CHROME.DLL+10db8f9`. That instruction is `VZEROUPPER`, an AVX
  instruction in the Opus encoder.
- **Cause.** Opus picks its AVX2 code by asking the CPU only. Windows 98 never enables AVX state.
- **Fix.** Not in code: hide AVX from the guest. A kextest check now reports "AVX advertised but not usable".

## The VM crawled while Firefox ran

- **Symptom.** Input, screen and the test agent froze for minutes at a time.
- **Evidence.**
  1. Sampling the guest's EIP through the QEMU monitor: about 95% of the time was spent on `rep outsw` to port
     0x1F0, the IDE driver writing in PIO mode.
  2. QEMU's trace of written sectors, mapped through the FAT32 tables: all writes went to `WIN386.SWP` (the swap
     file), and the data was zeros.
  3. A memory probe: 89 MB of 1 GB swap left.
- **Cause.** Firefox's memory forced Windows 98 to page out, and paging went at about 130 KB/s through PIO.
- **Fix (in progress).** VM settings, not KernelEx code: conservative swap use, more RAM, and possibly DMA.
