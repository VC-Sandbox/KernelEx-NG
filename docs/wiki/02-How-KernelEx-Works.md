# 2. How KernelEx works

KernelEx (by Xeno86, 2008–2011; 4.6 beta by Ley0k) is the base KernelEx-NG builds on. KernelEx-NG does not
replace it: it plugs into it. Its sources are in this repository (`core/`, `apilibs/`, `vxd/`, ...).

## The components

| Component | Role |
|---|---|
| `VKRNLEX.VXD` (`vxd/`) | Ring-0 driver. At boot it finds KERNEL32's internal loader routines in memory by byte patterns and redirects eight of them through a jump table. |
| `KERNELEX.DLL` (`core/`) | The resolver. Loaded early into the shared arena, it takes over those eight routines. |
| `kexbases.dll`, `kexbasen.dll` (`apilibs/`) | API libraries: about 1,500 replacement and added functions (XP level). |
| auxiliary DLLs (`auxiliary/`) | Whole DLLs 98 lacks (psapi, pdh, uxtheme, userenv, …), loaded from the KernelEx folder. |
| `sheet.dll` | The **KernelEx tab** in a program's Properties: pick a compatibility mode per program. |
| `core.ini` | Defines the *configurations*: which API libraries a mode uses and which version it reports. |

## The trick: owning the import resolver

Every time a program imports a function, statically at load or with `GetProcAddress`, Windows 98's KERNEL32
looks up the name with `ExportFromName` or `ExportFromOrdinal`. KernelEx hooks those routines. For each lookup:

1. It finds the **calling module** and its **configuration**: the per-program setting, inherited from the parent
   process, or the default.
2. If the **target** is a system DLL (KERNEL32, USER32, …) and the configuration has an override for that name,
   it returns the override's address instead.
3. Otherwise it returns the real export.

So a program asking for `KERNEL32!GetVersionExA` can get Windows XP's answer, while the next program gets the
real one. Nothing on disk is patched, and KERNEL32 stays untouched.

## API libraries

An API library is a DLL exporting `get_api_table()`. The function returns, per system DLL, a sorted list of
`name → address`. `core.ini` lists the libraries of each configuration (`contents=std,kexbases,kexbasen`).
When two libraries provide the same name, the later one wins.

**KernelEx-NG's `kexnt.dll` is one more API library**, added last to every configuration. That one decision is
what makes the project possible without rebuilding KernelEx's core (which needs Visual C++ 6).

## Version spoofing

Each configuration binds `GetVersionEx` and its relatives to an implementation that reports a chosen Windows
version. KernelEx 4.5 stops at Windows 2008 (6.0). KernelEx-NG adds `kexver.dll` with profiles up to Windows 11
24H2 and Server 2025 (see [Architecture](03-Architecture.md#version-profiles)).

## Limits of KernelEx that KernelEx-NG had to work around

- Its API ceiling is XP / Vista RTM. It has no SRW locks, condition variables, FLS, VEH, API sets or the
  `*Ex` locale functions.
- Several functions are **hollow stubs** that return success without doing anything. Example:
  `NtQuerySystemInformation`. Others are always-failing stubs, such as `CreateNamedPipe` and
  `ConvertSidToStringSid`.
- Its forwarder resolution runs in KERNELEX.DLL's own context (shared arena), so a PE forwarder to a
  KernelEx-only function resolves to the *native* Windows 98 function. API-set DLLs therefore cannot be plain
  forwarders (see [Architecture](03-Architecture.md#api-set-dlls)).
- It only applies API tables to modules loaded from the **system folder**. DLLs it redirects to its own folder
  (pdh, psapi, …) do not get the extra functions unless `GetProcAddress` is helped
  (`knowndll_ext.c`).
- Its shared heap is capped at 1 MB, which limits the number of configurations. KEXSETUP raises it to 8 MB on
  4.5.x.
