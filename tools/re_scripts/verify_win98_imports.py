#!/usr/bin/env python3
"""verify_win98_imports.py - check that every import of the given PE files exists on Windows 98 SE.

Usage:
  python3 verify_win98_imports.py --win98 DIR_WITH_WIN98_DLLS [--ours BUILD_DIR] FILE [FILE...]

--win98 : folder with the ORIGINAL Win98 SE system DLLs (extract them from the CD CABs -
          copies taken from a running VM can be corrupted, see ARCHITECTURE.md Track S).
--ours  : folder with our own built DLLs; imports satisfied by them count as OK.
Also checks the PE header fields Win98 cares about (subsystem/OS version <= 4.x, i386).
Exit code 0 = all imports resolvable, 1 = something missing.
"""
import argparse
import os
import sys

try:
    import pefile
except ImportError:
    sys.exit("pip install pefile")


def exports_of(path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    names, ords, fwds = set(), set(), []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            ords.add(s.ordinal)
            if s.name:
                names.add(s.name.decode())
            if s.forwarder:
                fwds.append((s.name.decode() if s.name else s.ordinal, s.forwarder.decode()))
    return names, ords, fwds


def load_dir(d):
    table = {}
    if d and os.path.isdir(d):
        for f in os.listdir(d):
            if f.lower().endswith((".dll", ".drv")):
                try:
                    table[f.lower()] = exports_of(os.path.join(d, f))
                except Exception as e:  # noqa: BLE001
                    print(f"[warn] {f}: {e}")
    return table


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--win98", required=True)
    ap.add_argument("--ours")
    ap.add_argument("--kex", help="kex_inventory.json: forwarders to APIs KernelEx adds at runtime count as OK")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    win98 = load_dir(a.win98)
    if "kernel32.dll" not in win98:
        sys.exit(f"no kernel32.dll in {a.win98} - point --win98 at the extracted Win98 SE DLLs")
    ours = load_dir(a.ours)
    kex = {}
    if a.kex:
        import json
        for dll, libs in json.load(open(a.kex)).items():
            for lib in libs.values():
                kex.setdefault(dll.lower() + ".dll", set()).update(n.rstrip("*/") for n, _ in lib.get("named", []))
    bad = nkex = 0
    for f in a.files:
        pe = pefile.PE(f)
        oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER
        hdr = []
        if fh.Machine != 0x14C:
            hdr.append("not i386")
        if oh.MajorSubsystemVersion > 4 or oh.MajorOperatingSystemVersion > 4:
            hdr.append(f"subsystem/os version {oh.MajorSubsystemVersion}.{oh.MinorSubsystemVersion}/"
                       f"{oh.MajorOperatingSystemVersion}.{oh.MinorOperatingSystemVersion} > 4.x (9x loader refuses)")
        missing = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode().lower()
            src = ours.get(dll) or win98.get(dll)
            for imp in entry.imports:
                key = imp.name.decode() if imp.name else imp.ordinal
                if src is None:
                    missing.append(f"{dll}!{key} (DLL not on Win98)")
                elif (imp.name and key not in src[0]) or (not imp.name and key not in src[1]):
                    missing.append(f"{dll}!{key}")
        # PE forwarders (api-set shells): the target must exist when the 9x loader resolves it
        for name, fwd in exports_of(f)[2]:
            tdll, _, tname = fwd.partition(".")
            tdll = tdll.lower() + ".dll"
            src = ours.get(tdll) or win98.get(tdll)
            if src is not None and tname in src[0]:
                continue
            if tname in kex.get(tdll, ()):
                nkex += 1
                continue
            missing.append(f"forwarder {name} -> {fwd} unresolvable")
        status = "OK " if not (missing or hdr) else "BAD"
        print(f"[{status}] {os.path.basename(f)}")
        for m in hdr + missing:
            print(f"      - {m}")
        bad += bool(missing or hdr)
    print(f"{len(a.files) - bad}/{len(a.files)} files load-clean on Win98 SE"
          + (f" ({nkex} forwarders rely on KernelEx runtime APIs)" if nkex else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
