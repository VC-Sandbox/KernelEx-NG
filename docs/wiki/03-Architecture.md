# 3. KernelEx-NG architecture

## The layers

```
 Modern program (chrome.exe, firefox.exe, vc_redist.exe, ...)   32-bit, built for NT 5 – 10
   │  imports KERNEL32 / NTDLL / USER32 / ... / api-ms-win-* / bcrypt / dwmapi ...
   ▼
 api-ms-win-*.dll (116)    API-set shells: lazy jump thunks + forwarders           (generated)
 stub DLLs (31)            bcrypt, dwmapi, winhttp, avrt, d3d11 ...                 (generated + hand code)
   ▼
 KernelEx resolver (KERNELEX.DLL)   picks an implementation per calling program
   ▼
 kexnt.dll    ~2,000 functions in 63 modules (*_ext.c), each behind a GATE        ← KernelEx-NG
 kexver.dll   version profiles (Windows 7 … 11 / Server 2025)                     ← KernelEx-NG
 kexbases / kexbasen   KernelEx's own XP-level functions
   ▼
 Windows 98 SE  KERNEL32 / USER32 / GDI32 / ADVAPI32 ...  (+ KEXALIAS.VXD helper)
```

## kexnt.dll

`kexnt.dll` is the heart of the project. It is a KernelEx API library built with MinGW from `new_stubs/*.c`.

- **What it publishes:** every exported `kex_<Name>@N` symbol becomes a function `<Name>`.
  `kexnt_targets.txt` says under which system DLL(s) each name is published, mirroring where Windows 10
  exports it. Today it publishes about 360 KERNEL32, 270 NTDLL, 670 USER32, 340 GDI32, 170 WINMM and 70 ADVAPI32
  names, and a few hundred more across 25 other DLLs.
- **Imports only KERNEL32 and ADVAPI32.** They live in the shared arena and KernelEx never re-routes them.
  Anything else (USER32, GDI32, WS2_32, …) is reached at run time with `kex_sysproc(dll, name)`.
  [Why](06-Design-Decisions.md#kexnt-imports-only-kernel32-and-advapi32).
- **No C runtime.** It links with `-nostdlib` and supplies its own `memcpy`, `strlen`, … (`kexnt_crt.c`).
- **Loads at 0x6A000000**, keeps its `.reloc` section, and has no ASLR/NX flags: Windows 98 needs relocatable
  DLLs and ignores the flags.

## Gates: Windows 98 programs are left alone

KernelEx applies one configuration to every 32-bit program, including plain Windows 98 programs. Early builds
therefore routed Notepad's `ReadFile` through kexnt too. Since build 89, every function kexnt publishes is a
**gate**, a few generated instructions (`gen_apitable.py`, `gate_ext.c`):

- The first call in a process **decides once**: is this a *modern* program? It is if the EXE's subsystem version
  is 5.0 or later, or the user gave it an NT profile on the KernelEx tab.
- **Modern program:** the gate jumps straight into kexnt's function. That costs one compare and a jump.
- **Windows 98 program:** the gate jumps to what the program would have got *without* kexnt: KernelEx's
  version, or Windows 98's own. kexnt's DllMain then does nothing in that process: no TLS slots, no hooks, no
  logs.

That is how the rule "no effect on native 9x programs" is enforced, rather than just hoped for.

A few NTDLL gates are generated in the **shape of an NT system-call stub** (`mov eax,id; mov edx,X; call edx;
ret N`). The reason is that Chromium's sandbox checks that shape before it patches a function. See
[case studies](09-Case-Studies.md).

## API-set DLLs

Windows 7+ programs import `api-ms-win-core-synch-l1-2-0.dll` and similar names. On Windows 10 these are virtual
names resolved by the loader. On 98 they must be real files.

- The tables come from **Windows 10 21H2's own API-set forwarders** (`gen_apisets.py`). For each export, the
  generator picks the first of: kexnt, the native Windows 98 DLL, a KernelEx function. That gives 116 DLLs.
- Plain PE forwarders do not work for functions KernelEx supplies, because KernelEx resolves forwarders in its
  own context and returns the native stub. So each entry that targets a system DLL is a **lazy jump thunk**
  (`gen_apiset_thunks.py`). On first call it does `GetProcAddress` *from the API-set DLL itself*, which is a
  normal module with the program's configuration, then patches its own jump. Entries that point into
  kexnt/ucrtbase stay real forwarders.
- Each shell also statically imports one function from each target DLL ("anchor"), so the Windows 98 loader maps
  the targets first.
- An API-set DLL's DllMain is the first code that runs for a modern module. It uses that moment to apply the
  **PEB patch** to the importing module (see [Core techniques](04-Core-Techniques.md#a-peb-for-nt-code)).

The C-runtime API sets (`api-ms-win-crt-*`) forward to `ucrtbase.dll`, which is the user's own Windows 10 copy;
it is never shipped.

## Stub DLLs

`stubs/stubs.txt` lists functions of DLLs that Windows 98 does not have. Each line gives a behaviour:
- `val:N`: return a constant;
- `err:`: fail with a given error;
- the name of a hand-written function in `stubs/<dll>.c`.

`stubs/gen_stubs.py` generates one small DLL per name. KEXSETUP copies a stub into `SYSTEM` **only if Windows has
no DLL of that name**, so a real DLL is never replaced. Examples:
- `dwmapi.dll`: no compositor, so "composition disabled";
- `bcrypt.dll`: real random numbers and hashes on top of the CryptoAPI;
- `avrt.dll`: a success handle, but the thread priority is not raised;
- `d3d11.dll` / `dxgi.dll`: "no device", so programs fall back to software rendering.

## Version profiles

`kexver.dll` is a second API library. It holds 10+ implementations of each version function (`GetVersion*`,
`VerifyVersionInfo*`, `RtlGetVersion`, `GetProductInfo`) and works the KernelEx way: KEXSETUP adds
configurations to `core.ini` that bind each name to one of them. The KernelEx tab then lists:
- Windows 7 SP1
- Windows 8 and 8.1
- Windows 10 1507 … 21H2
- Windows Server 2016 / 2019 / 2022
- Windows 11 24H2 and Server 2025

The same profile is also reported by:
- the emulated PEB;
- the *file version* of `kernel32.dll`, `kernelbase.dll` and `ntdll.dll` (`filever_ext.c`), because Chromium
  reads that file version instead of asking.

## KEXSETUP

`tests/kexsetup.c` installs, updates and uninstalls (`/u`), logging everything to `kexsetup.log`. It does the
following:
- copies `kexnt.dll` into the KernelEx folder, or schedules the copy through `WININIT.INI` if the file is in use;
- appends `,KEXNT` to every `contents=` line of `core.ini`, keeping a backup;
- registers KnownDLLs entries;
- copies the API-set DLLs, the stub DLLs and the user's own Windows 10 DLLs;
- adds the version profiles;
- raises KernelEx 4.5's shared heap from 1 MB to 8 MB (byte-pattern checked, with a backup);
- replaces the KernelEx tab with an extended one ("report real OS to websites");
- adjusts a few of KernelEx's built-in program rules, for example the Firefox setup rule.

## KEXALIAS.VXD

A small ring-0 helper (`vxd_alias/`, built with Open Watcom). It gives a section a **second view** at another
address, which Windows 98 cannot do from user mode. Chromium's shared memory needs it. A built copy is kept in
the repository so the normal build does not need Watcom.

## Where a call goes

Here is the path of a call to `AcquireSRWLockExclusive` from `chrome.dll`:

1. Windows 98's loader resolves the import through `ExportFromName`, which is hooked by KernelEx.
2. KernelEx sees that `chrome.exe` has a configuration whose library list ends in `kexnt`. kexnt's table has
   `AcquireSRWLockExclusive` under KERNEL32, so the address of its **gate** is used.
3. At the first call, the gate decides "modern program" (`chrome.exe` has subsystem 6.0). From then on it jumps
   directly to `kex_AcquireSRWLockExclusive@4` in `sync_ext.c`.
4. That function uses the parking lot built on Windows 98 events (see
   [Core techniques](04-Core-Techniques.md#locks-without-kernel-support)).
