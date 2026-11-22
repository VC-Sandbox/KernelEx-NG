# 10. Status and limitations

State at build 131–132. For the per-build details, see `new_stubs/ARCHITECTURE.md`.

## Programs

| Program | State |
|---|---|
| Chromium/Chrome 159 (ia32) | starts, browses, downloads, file dialogs, translucent menus; Discord web works and voice connects (AVX must be hidden); child processes and IPC work |
| Mypal 29 | works (address bar, history, web fonts) |
| Firefox 52.9 ESR | installs; browser start was crashing (older notes) |
| Firefox 115 ESR | installs, starts, address bar and popups work, loads HTTPS pages |
| Firefox 160 | installs; Win10-mode sandbox stubs need more work |
| Pale Moon 35 | installs, starts, loads pages; Places (bookmarks/history) and address bar work |
| Basilisk, Supermium 150 | partly; Supermium needs `--no-sandbox` for now |
| Visual C++ 2010 / 2013 / 2015–2022 redistributables | install; programs using them start |
| K-Lite Codec Pack 20.2 + Windows Media Player | installs (Icaros thumbnail add-on cannot register - choose "Ignore"); WMP plays H.264/HEVC MP4, VP9 WebM/MKV, AV1 MKV |
| VLC 3 | plays |
| .NET Framework 4.0 | installs (`dotNetFx40_Full_x86_x64.exe /q /norestart`); console programs (LINQ, tasks, regular expressions, HTTP), runtime hosting and WinForms run. WinForms needs Microsoft's own `gdiplus.dll` (for example from the Windows XP GDI+ update KB975337) in `C:\WINDOWS\SYSTEM`; KernelEx-NG's small gdiplus stub is not enough. .NET 4.5 and later are untested |

## What cannot be fixed in a user-mode layer

- **AVX** and anything else that needs OS support for CPU state.
- **More than one CPU.**
- **Real security:** users, ACLs, integrity levels and sandboxes. They are answered consistently (one user with
  full rights), not enforced. Browser sandboxes give no protection on Windows 98.
- **DirectX 10+ / Direct3D 11 hardware rendering.** The stub DLLs report "no device", so programs fall back to
  software.
- **64-bit programs.**

## Known weak spots

- **Memory.** 2 GB per process, a shared arena for everything shared, and slow paging. Modern browsers are heavy.
  Give the VM a fixed 2 GB swap file and as much RAM as Windows 98 tolerates.
- **Disk speed in QEMU.** Without DMA, disk I/O is PIO and very slow under load.
- **Windows 98's 16-bit resource heaps** (USER/GDI "system resources") can run out with very complex UIs.
- **Timing-dependent behaviour.** Windows 98 schedules differently. Code that "works on NT" by luck may not.
- **KernelEx 4.6 beta** as an installed base has not been tested.

## Safety

This software modifies the running Windows 98 kernel's behaviour:
- exception dispatcher hook;
- loader behaviour;
- memory placement in the shared arena;
- a ring-0 helper driver.

A bug can freeze or crash the whole system and corrupt open files. **Use a VM with snapshots.**
