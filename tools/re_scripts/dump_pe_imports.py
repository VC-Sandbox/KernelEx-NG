#!/usr/bin/env python3
"""dump_pe_imports.py - dump imports/exports of PE files (DLL/EXE) to JSON.

Usage: python dump_pe_imports.py <file-or-folder> [-o out.json] [-r]
Uses pefile if installed, otherwise a built-in raw PE32/PE32+ parser.
"""
import argparse, json, os, struct, sys

PE_EXT = ('.dll', '.exe', '.sys', '.drv', '.ocx', '.cpl', '.vxd', '.node')
MACHINES = {0x14c: 'i386', 0x8664: 'x64', 0xaa64: 'arm64', 0x1c4: 'arm'}


class RawPE(object):
    """Minimal PE parser: headers, sections, import/delay-import/export tables."""
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.d = f.read()
        d = self.d
        if d[:2] != b'MZ':
            raise ValueError('not MZ')
        self.pe = struct.unpack_from('<I', d, 0x3c)[0]
        if d[self.pe:self.pe + 4] != b'PE\0\0':
            raise ValueError('not PE')
        fh = self.pe + 4
        (self.machine, nsec, self.timestamp, _, _, opt_size,
         self.characteristics) = struct.unpack_from('<HHIIIHH', d, fh)
        oh = fh + 20
        self.magic = struct.unpack_from('<H', d, oh)[0]
        self.is64 = self.magic == 0x20b
        if self.is64:
            self.image_base = struct.unpack_from('<Q', d, oh + 24)[0]
            dd = oh + 112
        else:
            self.image_base = struct.unpack_from('<I', d, oh + 28)[0]
            dd = oh + 96
        self.os_ver = struct.unpack_from('<HH', d, oh + 40)
        self.subsys_ver = struct.unpack_from('<HH', d, oh + 48)
        self.size_of_image = struct.unpack_from('<I', d, oh + 56)[0]
        self.subsystem, self.dll_chars = struct.unpack_from('<HH', d, oh + 68)
        ndd = struct.unpack_from('<I', d, dd - 4)[0]
        self.dirs = [struct.unpack_from('<II', d, dd + 8 * i) for i in range(min(ndd, 16))]
        self.sections = []
        so = oh + opt_size
        for i in range(nsec):
            name, vsize, va, rsize, raw = struct.unpack_from('<8sIIII', d, so + 40 * i)
            self.sections.append((name.rstrip(b'\0').decode('latin1'), va, vsize, raw, rsize))

    def off(self, rva):
        for _, va, vs, raw, rs in self.sections:
            if va <= rva < va + max(vs, rs):
                return rva - va + raw
        return rva if rva < len(self.d) else None

    def cstr(self, rva):
        o = self.off(rva)
        if o is None:
            return None
        e = self.d.find(b'\0', o)
        return self.d[o:e].decode('latin1')

    def _thunks(self, rva):
        out, ptr = [], self.off(rva)
        if ptr is None:
            return out
        size, fmt = (8, '<Q') if self.is64 else (4, '<I')
        flag = 1 << (63 if self.is64 else 31)
        while ptr + size <= len(self.d):
            v = struct.unpack_from(fmt, self.d, ptr)[0]
            if not v:
                break
            if v & flag:
                out.append({'name': None, 'ordinal': v & 0xffff, 'hint': None})
            else:
                o = self.off(v & 0x7fffffff)
                hint = struct.unpack_from('<H', self.d, o)[0] if o is not None else None
                out.append({'name': self.cstr((v & 0x7fffffff) + 2), 'ordinal': None, 'hint': hint})
            ptr += size
            if len(out) > 65535:
                break
        return out

    def imports(self):
        res = []
        if len(self.dirs) > 1 and self.dirs[1][0]:
            o = self.off(self.dirs[1][0])
            while o is not None and o + 20 <= len(self.d):
                oft, _, _, name, ft = struct.unpack_from('<IIIII', self.d, o)
                if not (oft or name or ft):
                    break
                res.append({'dll': self.cstr(name), 'delay': False, 'functions': self._thunks(oft or ft)})
                o += 20
        if len(self.dirs) > 13 and self.dirs[13][0]:
            o = self.off(self.dirs[13][0])
            while o is not None and o + 32 <= len(self.d):
                attrs, name, _, _, int_rva = struct.unpack_from('<IIIII', self.d, o)[:5]
                if not name:
                    break
                base = 0 if attrs & 1 else self.image_base   # old VC6 delay tables use VAs
                res.append({'dll': self.cstr(name - base), 'delay': True,
                            'functions': self._thunks(int_rva - base)})
                o += 32
        return res

    def exports(self):
        if not self.dirs or not self.dirs[0][0]:
            return None
        erva, esize = self.dirs[0]
        o = self.off(erva)
        if o is None or o + 40 > len(self.d):
            return None
        (_, _, _, _, name, base, nfunc, nname, af, an, ao) = struct.unpack_from('<IIHHIIIIIII', self.d, o)
        u32 = lambda rva, i: struct.unpack_from('<I', self.d, self.off(rva) + 4 * i)[0]
        names = {}
        for i in range(min(nname, 65536)):
            try:
                idx = struct.unpack_from('<H', self.d, self.off(ao) + 2 * i)[0]
                names[idx] = self.cstr(u32(an, i))
            except (TypeError, struct.error):
                break
        funcs = []
        for i in range(min(nfunc, 65536)):
            try:
                rva = u32(af, i)
            except (TypeError, struct.error):
                break
            if not rva:
                continue
            fwd = self.cstr(rva) if erva <= rva < erva + esize else None
            funcs.append({'name': names.get(i), 'ordinal': base + i, 'rva': rva, 'forwarder': fwd})
        return {'dll_name': self.cstr(name), 'ordinal_base': base, 'functions': funcs}

    def tls_callbacks(self):
        if len(self.dirs) <= 9 or not self.dirs[9][0]:
            return 0
        o = self.off(self.dirs[9][0])
        fmt, sz = ('<Q', 8) if self.is64 else ('<I', 4)
        cb_va = struct.unpack_from(fmt, self.d, o + 3 * sz)[0]
        if not cb_va:
            return 0
        p, n = self.off(cb_va - self.image_base), 0
        while p is not None and struct.unpack_from(fmt, self.d, p)[0]:
            n, p = n + 1, p + sz
        return n


def dump_with_pefile(path):
    import pefile
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY[k] for k in (
        'IMAGE_DIRECTORY_ENTRY_IMPORT', 'IMAGE_DIRECTORY_ENTRY_EXPORT',
        'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT', 'IMAGE_DIRECTORY_ENTRY_TLS')])
    imps = []
    for attr, delay in (('DIRECTORY_ENTRY_IMPORT', False), ('DIRECTORY_ENTRY_DELAY_IMPORT', True)):
        for e in getattr(pe, attr, []) or []:
            imps.append({'dll': e.dll.decode('latin1'), 'delay': delay, 'functions': [
                {'name': i.name.decode('latin1') if i.name else None,
                 'ordinal': None if i.name else i.ordinal, 'hint': getattr(i, 'hint', None)}
                for i in e.imports]})
    exp = None
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        ed = pe.DIRECTORY_ENTRY_EXPORT
        exp = {'dll_name': pe.get_string_at_rva(ed.struct.Name).decode('latin1'),
               'ordinal_base': ed.struct.Base, 'functions': [
                   {'name': s.name.decode('latin1') if s.name else None, 'ordinal': s.ordinal,
                    'rva': s.address, 'forwarder': s.forwarder.decode('latin1') if s.forwarder else None}
                   for s in ed.symbols]}
    raw = RawPE(path)  # headers/TLS via raw parser for uniform output
    return raw, imps, exp, [w for w in pe.get_warnings() if 'xport' in w]


def _named(exp):
    return sum(1 for f in exp['functions'] if f['name']) if exp else -1


def dump_file(path, force_raw=False):
    warnings = []
    if not force_raw:
        try:
            raw, imps, exp, warnings = dump_with_pefile(path)
            parser = 'pefile'
        except ImportError:
            force_raw = True
    if force_raw:
        raw = RawPE(path)
        imps, exp, parser = raw.imports(), raw.exports(), 'raw'
    export_parser = parser
    if parser == 'pefile':
        # pefile's anti-malware sanity checks can silently truncate or drop the export
        # table of old Win9x system DLLs. Cross-check with the raw parser, keep the richer one.
        try:
            rexp = raw.exports()
        except Exception as e:
            rexp, warnings = None, warnings + ['raw export parse failed: %s' % e]
        if _named(rexp) > _named(exp):
            warnings.append('pefile export table incomplete (%d named) - using raw parser (%d named)'
                            % (max(_named(exp), 0), _named(rexp)))
            exp, export_parser = rexp, 'raw'
    return {
        'path': os.path.abspath(path), 'name': os.path.basename(path), 'parser': parser,
        'machine': MACHINES.get(raw.machine, hex(raw.machine)), 'pe32plus': raw.is64,
        'is_dll': bool(raw.characteristics & 0x2000), 'timestamp': raw.timestamp,
        'image_base': hex(raw.image_base), 'size_of_image': raw.size_of_image,
        'os_version': '%d.%d' % raw.os_ver, 'subsystem_version': '%d.%d' % raw.subsys_ver,
        'subsystem': raw.subsystem, 'dll_characteristics': hex(raw.dll_chars),
        'sections': [{'name': s[0], 'va': hex(s[1]), 'vsize': s[2], 'raw_size': s[4]} for s in raw.sections],
        'tls_callbacks': raw.tls_callbacks(), 'imports': imps, 'exports': exp,
        'export_parser': export_parser, 'warnings': warnings,
    }


def iter_pe(target, recursive):
    if os.path.isfile(target):
        yield target
        return
    for root, dirs, files in os.walk(target):
        for f in sorted(files):
            if f.lower().endswith(PE_EXT):
                yield os.path.join(root, f)
        if not recursive:
            break


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('target')
    ap.add_argument('-o', '--output', default='-')
    ap.add_argument('-r', '--recursive', action='store_true')
    ap.add_argument('--raw', action='store_true', help='force built-in parser')
    a = ap.parse_args()
    out, errors = [], []
    for p in iter_pe(a.target, a.recursive):
        try:
            rec = dump_file(p, a.raw)
            out.append(rec)
            n = _named(rec['exports'])
            sys.stderr.write('[ok] %s  (exports: %s named)\n' % (p, n if n >= 0 else 'none'))
            for w in rec['warnings']:
                sys.stderr.write('     [warn] %s\n' % w)
        except Exception as e:  # keep going on malformed files
            errors.append({'path': p, 'error': str(e)})
            sys.stderr.write('[err] %s: %s\n' % (p, e))
    doc = {'tool': 'dump_pe_imports', 'version': 1, 'files': out, 'errors': errors}
    text = json.dumps(doc, indent=1)
    if a.output == '-':
        print(text)
    else:
        with open(a.output, 'w') as f:
            f.write(text)
        sys.stderr.write('wrote %s (%d files, %d errors)\n' % (a.output, len(out), len(errors)))


if __name__ == '__main__':
    main()
