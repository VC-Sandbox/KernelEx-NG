#!/usr/bin/env python3
"""dll_base.py <name> <all names...>: preferred image base for one of our small DLLs.
Every api-ms-win-* shell and stub DLL gets its own 256 KB slot from 0x5A000000 up (sorted name order), so
none of them sits at the linker default 0x10000000. Windows 98 relocates a DLL whose base is taken; for a
very large DLL (chrome.dll, preferred base 0x10000000) that relocation was not applied (2026-11-01 run).
Build 111: moved from 0x5A000000 (256 KB slots) to 0x6C400000 (128 KB slots, every one of these DLLs is under
0x18000 bytes). At 0x5A000000 they cut Chrome's renderer address space in two: chrome.dll ends at 0x214B0000 and
the hole above it stopped at 0x5A140000 (908.5 MB), so windows93.net's 1 GB ArrayBuffer reservation failed 16x
(build 110 KEXCRASH address map). Now the hole runs up to kexver.dll at 0x69000000 (about 1147 MB)."""
import sys, os
name = os.path.basename(sys.argv[1]).lower()
names = sorted({os.path.basename(n).lower() for n in sys.argv[2:]} | {name})
print(hex(0x6C400000 + names.index(name) * 0x20000))
