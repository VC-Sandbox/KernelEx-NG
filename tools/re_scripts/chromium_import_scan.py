#!/usr/bin/env python3
"""chromium_import_scan.py - aggregate every unique DLL import of a Chrome/Electron install.

Usage: python chromium_import_scan.py "C:\\path\\to\\chrome-win" -o chromium_manifest.json
Writes a master manifest: dll -> function -> {count, importers, delay}. Also prints
a summary and warns about non-i386 binaries (Win98 runs only 32-bit x86).
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dump_pe_imports import dump_file, iter_pe


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('root')
    ap.add_argument('-o', '--output', default='chromium_manifest.json')
    ap.add_argument('--include-local', action='store_true',
                    help='also list imports satisfied by DLLs shipped in the scanned folder')
    a = ap.parse_args()
    bins, dlls, local = [], {}, set()
    paths = list(iter_pe(a.root, True))
    for p in paths:
        local.add(os.path.basename(p).lower())
    for p in paths:
        try:
            info = dump_file(p)
        except Exception as e:
            sys.stderr.write('[err] %s: %s\n' % (p, e))
            continue
        rel = os.path.relpath(p, a.root)
        bins.append({'file': rel, 'machine': info['machine'], 'subsystem_version': info['subsystem_version'],
                     'tls_callbacks': info['tls_callbacks'], 'num_imports': sum(len(i['functions']) for i in info['imports'])})
        if info['machine'] != 'i386':
            sys.stderr.write('[warn] %s is %s - cannot run on Win98 (need ia32 build)\n' % (rel, info['machine']))
        for imp in info['imports']:
            dll = (imp['dll'] or '?').lower()
            if dll in local and not a.include_local:
                continue
            ent = dlls.setdefault(dll, {'importers': set(), 'functions': {}})
            ent['importers'].add(rel)
            for fn in imp['functions']:
                key = fn['name'] or ('#%d' % fn['ordinal'])
                f = ent['functions'].setdefault(key, {'count': 0, 'importers': [], 'delay': True})
                if rel not in f['importers']:
                    f['importers'].append(rel)
                    f['count'] += 1
                f['delay'] = f['delay'] and imp['delay']
    out = {'tool': 'chromium_import_scan', 'version': 1, 'root': os.path.abspath(a.root), 'binaries': bins,
           'dlls': {d: {'importers': sorted(v['importers']), 'functions': dict(sorted(v['functions'].items()))}
                    for d, v in sorted(dlls.items())}}
    out['summary'] = {'binaries': len(bins), 'dlls': len(dlls),
                      'unique_functions': sum(len(v['functions']) for v in dlls.values())}
    with open(a.output, 'w') as f:
        json.dump(out, f, indent=1)
    print('Scanned %(binaries)d binaries: %(dlls)d system DLLs, %(unique_functions)d unique imports' % out['summary'])
    for d, v in sorted(dlls.items(), key=lambda kv: -len(kv[1]['functions'])):
        print('  %-48s %5d functions' % (d, len(v['functions'])))
    print('Manifest written to', a.output)


if __name__ == '__main__':
    main()
