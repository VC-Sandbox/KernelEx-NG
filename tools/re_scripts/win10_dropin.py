#!/usr/bin/env python3
"""win10_dropin.py - which genuine Windows 10 DLLs can load on Windows 98 SE + KernelEx + KernelEx-NG,
and exactly which functions each one still needs from us.

For every i386 DLL in --win10, every import is resolved the way the 9x loader + KernelEx would:
  api-ms-win-* / ext-ms-win-*  -> through OUR api-set shell in --ours (its forwarder target), if we
                                  build one; otherwise "no api-set shell"
  any DLL                       -> Win98 SE export (--win98), KernelEx override (--kex inventory),
                                  KernelEx-NG export (kexnt.dll / our DLLs in --ours), or another
                                  Windows 10 DLL that is itself a drop-in candidate (--win10)
Kernel-boundary DLLs (ntdll, win32u, kernelbase, kernel32, user32, gdi32, gdi32full) are reported
but never counted as usable: their code enters the NT kernel directly.

  python3 win10_dropin.py --win10 DIR --win98 DIR --ours BUILD --kex kex_inventory.json \
          [--targets ../../new_stubs/kexnt_targets.txt] -o dropin_report.md
No third-party modules.
"""
import argparse, collections, json, os, struct

KERNEL_BOUNDARY = {'ntdll', 'win32u', 'kernelbase', 'kernel32', 'user32', 'gdi32', 'gdi32full'}


class PE:
    def __init__(self, path):
        d = self.d = open(path, 'rb').read()
        pe = struct.unpack_from('<I', d, 0x3c)[0]
        self.machine = struct.unpack_from('<H', d, pe + 4)[0]
        nsec = struct.unpack_from('<H', d, pe + 6)[0]
        optsz = struct.unpack_from('<H', d, pe + 20)[0]
        opt = pe + 24
        self.pe32plus = struct.unpack_from('<H', d, opt)[0] == 0x20b
        dd = opt + (112 if self.pe32plus else 96)
        self.exp_rva, self.exp_size = struct.unpack_from('<II', d, dd)
        self.imp_rva = struct.unpack_from('<I', d, dd + 8)[0]
        self.dimp_rva = struct.unpack_from('<I', d, dd + 13 * 8)[0]
        self.secs = [struct.unpack_from('<8sIIII', d, opt + optsz + 40 * i) for i in range(nsec)]

    def off(self, rva):
        for _, vs, va, rs, ro in self.secs:
            if va <= rva < va + max(vs, rs):
                return ro + rva - va
        raise ValueError(hex(rva))

    def cstr(self, rva):
        o = self.off(rva)
        return self.d[o:self.d.index(b'\0', o)].decode('latin-1')

    def exports(self):
        """{name: forwarder-string-or-None}"""
        try:
            o = self.off(self.exp_rva) if self.exp_rva else None
        except ValueError:
            return {}
        if o is None or o + 40 > len(self.d):
            return {}
        _, _, _, _, _, base, nf, nn, af, an, ao = struct.unpack_from('<IIHHIIIIIII', self.d, self.off(self.exp_rva))
        res = {}
        for i in range(nn):
            name = self.cstr(struct.unpack_from('<I', self.d, self.off(an) + 4 * i)[0])
            idx = struct.unpack_from('<H', self.d, self.off(ao) + 2 * i)[0]
            rva = struct.unpack_from('<I', self.d, self.off(af) + 4 * idx)[0]
            res[name] = self.cstr(rva) if self.exp_rva <= rva < self.exp_rva + self.exp_size else None
        return res

    def imports(self):
        """[(dll, name-or-#ord, delayload)]"""
        out = []
        for rva, size, delay in ((self.imp_rva, 20, False), (self.dimp_rva, 32, True)):
            if not rva:
                continue
            p = self.off(rva)
            while True:
                if delay:
                    attr, name_rva, _, _, int_rva = struct.unpack_from('<IIIII', self.d, p)
                    rvabased = attr & 1
                    if not name_rva:
                        break
                    if not rvabased:   # old-style VA delay descriptors are rare; skip them
                        p += size; continue
                    thunk = int_rva
                else:
                    oft, _, _, name_rva, ft = struct.unpack_from('<IIIII', self.d, p)
                    if not name_rva:
                        break
                    thunk = oft or ft
                dll = self.cstr(name_rva).lower()
                t = self.off(thunk)
                while True:
                    v = struct.unpack_from('<I', self.d, t)[0]
                    if not v:
                        break
                    out.append((dll, '#%d' % (v & 0xffff) if v & 0x80000000 else self.cstr(v + 2), delay))
                    t += 4
                p += size
        return out


def base(n):
    n = n.lower()
    return n[:-4] if n.endswith(('.dll', '.drv', '.cpl')) else n


def load_dir(d):
    res = {}
    if d and os.path.isdir(d):
        for f in os.listdir(d):
            if f.lower().endswith(('.dll', '.drv')):
                try:
                    res[base(f)] = PE(os.path.join(d, f))
                except Exception:
                    pass
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--win10', required=True); ap.add_argument('--win98', required=True)
    ap.add_argument('--ours', required=True); ap.add_argument('--kex', required=True)
    ap.add_argument('--targets'); ap.add_argument('-o', default='dropin_report.md')
    a = ap.parse_args()

    w10, w98, ours = load_dir(a.win10), load_dir(a.win98), load_dir(a.ours)
    have = collections.defaultdict(set)
    for n, pe in w98.items():
        try:
            have[n] |= set(pe.exports())
        except Exception:
            pass
    for dll, libs in json.load(open(a.kex)).items():
        for lib in libs.values():
            for x in lib.get('named', []):
                have[base(dll)].add(x[0] if isinstance(x, list) else x)
    for n, pe in ours.items():
        if not n.startswith(('api-ms-', 'ext-ms-')):
            try:
                have[n] |= set(pe.exports())
            except Exception:
                pass
    if a.targets:                      # kexnt exports published under KERNEL32/NTDLL by KernelEx
        for line in open(a.targets):
            p = line.split()
            if len(p) >= 2 and not line.startswith('#'):
                for t in p[1].split(','):
                    have[base(t)].add(p[0])
    shells = {n: pe.exports() for n, pe in ours.items() if n.startswith(('api-ms-', 'ext-ms-'))}

    rows, detail = [], {}
    cand = {n for n, pe in w10.items() if pe.machine == 0x14c and not n.startswith(('api-ms-', 'ext-ms-'))}

    def resolve(dll, fn):
        """None if satisfied, else a reason string."""
        dll = base(dll)
        if dll.startswith(('api-ms-', 'ext-ms-')):
            if dll not in shells:
                return 'no api-set shell ' + dll
            fwd = shells[dll].get(fn)
            if fwd is None:
                return 'not in our ' + dll if fn not in shells[dll] else None
            dll, fn = base(fwd.split('.', 1)[0]), fwd.split('.', 1)[1]
        if fn in have.get(dll, ()):
            return None
        if dll in cand and dll not in KERNEL_BOUNDARY and fn in w10[dll].exports():
            return None                # provided by another genuine Win10 DLL loaded alongside
        return '%s!%s' % (dll, fn)

    for n in sorted(cand):
        imps = w10[n].imports()
        miss = [(d, f, dl, r) for d, f, dl in imps for r in [resolve(d, f)] if r]
        hard = [m for m in miss if not m[2]]
        nt = sum(1 for d, f, _ in imps if base(d) in ('ntdll', 'win32u') and f[:2] in ('Nt', 'Zw'))
        rows.append((n, len(imps), len(hard), len(miss) - len(hard), nt))
        detail[n] = miss

    rows.sort(key=lambda r: (r[0] in KERNEL_BOUNDARY, r[2]))
    with open(a.o, 'w') as o:
        o.write('# Windows 10 DLLs as drop-ins on Windows 98 SE + KernelEx + KernelEx-NG\n\n')
        o.write('"missing" = static imports nothing provides yet (the DLL will not load). '
                '"delay" = delay-load imports (fail only when called). '
                '"Nt calls" = direct NT system-call wrappers it imports.\n\n')
        o.write('| DLL | imports | missing | delay missing | Nt calls | verdict |\n|---|---|---|---|---|---|\n')
        for n, tot, hard, dly, nt in rows:
            v = ('kernel boundary - reimplement, do not load' if n in KERNEL_BOUNDARY else
                 'loads now' if hard == 0 else 'close (<= 10)' if hard <= 10 else 'needs work')
            o.write('| %s | %d | %d | %d | %d | %s |\n' % (n, tot, hard, dly, nt, v))
        for n, *_ in rows:
            if n in KERNEL_BOUNDARY or not detail[n]:
                continue
            o.write('\n## %s\n\n' % n)
            by = collections.defaultdict(list)
            for d, f, dl, r in detail[n]:
                by[r.split('!')[0] if '!' in r else r].append(f + (' (delay)' if dl else ''))
            for k in sorted(by, key=lambda k: -len(by[k])):
                o.write('- **%s** (%d): %s\n' % (k, len(by[k]), ', '.join(sorted(set(by[k])))))
    for n, tot, hard, dly, nt in rows:
        print('%-22s imports %4d  missing %4d  delay-missing %4d  Nt %3d%s' %
              (n, tot, hard, dly, nt, '  [kernel boundary]' if n in KERNEL_BOUNDARY else ''))
    print('report:', a.o)


if __name__ == '__main__':
    main()
