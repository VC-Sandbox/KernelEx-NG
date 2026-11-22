# 7. Build system

Everything KernelEx-NG adds is built by one Makefile (`new_stubs/Makefile`) with a MinGW-w64 cross compiler for
i686, GCC or clang (llvm-mingw). The original KernelEx parts are not rebuilt.

## Pipeline

```
*_ext.c ──gcc──► build/*.o ──► kexnt.def (every kex_<Name>@N becomes export <Name>, plus kexnt_alias.def)
                                   │
            kexnt_targets.txt ─────┼─► gen_apitable.py ─► kexnt_apitable.c (API table + gates) ─► kexnt.dll
                                   │
apisets.txt / apisets_crt.txt ─────┴─► gen_apiset_thunks.py / deps ─► build/api-ms-win-*.dll (116)
stubs/stubs.txt ─► stubs/gen_stubs.py ─► build/stubs/*.dll (31)
data/*_guard.txt ─► gen_guard.py ─► guard_gen.c   (checked in)
tests/*.c ─► kextest.exe, kexsetup.exe, kexdbg.exe, kexroute.exe, kexcfg.exe, keximp.exe, ...
kexver.c ─► kexver.dll    sheet/ ─► sheet.dll    psapi/ userenv/ audio/ ─► replacement DLLs
                         │
                         ▼
check_nosse.py (fails on SSE) ─► build/iso/ + README.TXT ─► kexng.iso (xorriso or tools/mkiso.py)
```

## Targets

| Command | Result |
|---|---|
| `make` | all DLLs and tools in `build/` |
| `make iso` | the above plus `build/kexng.iso` |
| `make check` | prints the export table of every built DLL |
| `make verify WIN98_DLLS=<dir>` | checks every import of every built file against the Windows 98 SE CD's DLLs |
| `make apisets RE_OUT=<dir>` | regenerates `apisets.txt` from Windows 10 API-set dumps (needs the RE dumps) |
| `make vxd WATCOM=<dir>` | rebuilds `KEXALIAS.VXD` with Open Watcom |
| `make clean` | removes `build/` |

Variables: `CROSS=i686-w64-mingw32-` (compiler prefix), `WIN10_DLLS=<dir>` (your own Windows 10 DLLs on a
private CD), `UCRT_CC=<ucrt gcc>` (builds `ucrttest.exe`).

## Important flags and why

| Flag | Why |
|---|---|
| `-march=i686 -mno-sse` | runs on any 9x-era CPU |
| `-Wl,--subsystem,windows:4.0`, OS version 4.0 | Windows 98 loads only images it considers its own version |
| `--disable-dynamicbase --disable-nxcompat` | no ASLR/NX flags (meaningless on 98) |
| `--enable-reloc-section` | Windows 98 must be able to relocate a DLL |
| `--file-alignment,4096 --section-alignment,4096` | page-aligned sections, which the 9x loader handles reliably |
| `-nostdlib` for kexnt | no msvcrt import (see [design decisions](06-Design-Decisions.md#kexnt-imports-only-kernel32-and-advapi32)) |
| `-lkernel32 -ladvapi32` only | the only allowed imports |

## Two toolchain traps (clang / lld)

- `-fno-tree-loop-distribute-patterns` is GCC-only. Without it, GCC turns `strlen`-style loops into calls to
  `strlen`, which then call themselves. kexnt's CRT file is built `-ffreestanding -fno-builtin` for the same reason.
- lld writes i386 forwarders from a `.def` file with a broken DLL name (`_kexnt.Name`). With clang, forwarders are
  therefore passed as `-Xlink=-export:` options. The result was checked to be byte-identical to the GCC build.

## Build numbers

`new_stubs/kexng_build.h` holds `KEXNG_BUILD`. Every tool prints it, so a log always says which build produced
it. It is raised once per test round.
