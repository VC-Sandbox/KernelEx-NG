#!/usr/bin/env python3
"""compare_api_gaps.py - prioritized gap report: required APIs minus provided APIs.

Usage:
  python compare_api_gaps.py --provided win98_dump.json [--provided kex_inventory.json ...]
                             --required chromium_manifest.json -o gaps.md [--json gaps.json]
Accepted formats (auto-detected):
  provided: dump_pe_imports output (exports), docs/kex_inventory.json, or {"dll": ["fn", ...]}
  required: chromium_import_scan manifest, dump_pe_imports output (imports), or {"dll": ["fn", ...]}
api-ms-win-* / ext-ms-win-* names are mapped to their host DLL (kernel32, ucrtbase, ...).
"""
import argparse, fnmatch, json, sys

APISET_HOSTS = [('api-ms-win-crt-', 'ucrtbase.dll'), ('api-ms-win-security-', 'advapi32.dll'),
                ('api-ms-win-eventing-', 'advapi32.dll'), ('api-ms-win-shcore-', 'shcore.dll'),
                ('api-ms-win-core-winrt', 'combase.dll'), ('api-ms-win-core-com-', 'combase.dll'),
                ('api-ms-win-ntuser-', 'user32.dll'), ('api-ms-win-gdi-', 'gdi32.dll'),
                ('api-ms-win-power-', 'powrprof.dll'), ('api-ms-win-core-', 'kernel32.dll'),
                ('ext-ms-win-', 'kernel32.dll')]
ORDINAL_HEAVY = {'comctl32.dll', 'shell32.dll', 'shlwapi.dll'}


def norm(dll, map_apisets=True):
    d = (dll or '?').lower()
    if not d.endswith(('.dll', '.exe', '.drv', '.sys')):
        d += '.dll'
    if map_apisets:
        for pfx, host in APISET_HOSTS:
            if d.startswith(pfx):
                return host
    return d


def load_provided(path, m):
    doc, prov = json.load(open(path)), {}
    if doc.get('tool') == 'dump_pe_imports':
        for f in doc['files']:
            ex = f.get('exports')
            named = [e['name'] for e in ex['functions'] if e['name']] if ex else []
            # these DLLs legitimately export most APIs by ordinal only
            if (not named or len(named) * 2 < len(ex['functions'])) and \
                    norm(f['name'], False) not in ORDINAL_HEAVY:
                sys.stderr.write('[warn] %s: %s - its APIs will show up as false gaps; re-dump it\n' % (
                    f['name'], 'no export table parsed' if not named else
                    'only %d of %d exports have names' % (len(named), len(ex['functions']))))
            if ex:
                s = prov.setdefault(norm(f['name'], False), set())
                s.update(named)
                # '#N' entries let ordinal imports resolve; the meaning of an
                # ordinal can differ between 9x and NT, so matches are reported
                s.update('#%d' % e['ordinal'] for e in ex['functions'])
    elif all(isinstance(v, dict) for v in doc.values()):            # kex_inventory.json
        for dll, libs in doc.items():
            s = prov.setdefault(norm(dll, False), set())
            for lib in libs.values():
                s.update(n.rstrip('*/') for n, _ in lib.get('named', []))
    else:
        for dll, fns in doc.items():
            prov.setdefault(norm(dll, False), set()).update(fns)
    return prov


def load_required(path, m, skip_non_i386=True, ignore=(), exclude=()):
    doc, req = json.load(open(path)), {}
    bad = set()
    if skip_non_i386 and doc.get('tool') == 'chromium_import_scan':
        bad = {b['file'] for b in doc.get('binaries', []) if b.get('machine') != 'i386'}
        if bad:
            sys.stderr.write('[info] %s: skipping %d non-i386 binaries (cannot run on Win98)\n' % (path, len(bad)))
    def add(dll, fn, n=1, who=None, prio=None):
        if norm(dll, False) in ignore:
            return
        if who is not None:
            who = [w for w in (who if isinstance(who, list) else [who]) if w not in bad
                   and not any(fnmatch.fnmatch(w.lower(), x.lower()) for x in exclude)]
            if not who:
                return
            n = len(who)
        e = req.setdefault((norm(dll, m), fn), {'count': 0, 'importers': set(), 'orig_dlls': set(), 'priority': prio})
        e['count'] += n
        e['orig_dlls'].add(dll.lower())
        if who:
            e['importers'].update(who if isinstance(who, list) else [who])
    if doc.get('tool') == 'chromium_import_scan':
        for dll, v in doc['dlls'].items():
            for fn, info in v['functions'].items():
                add(dll, fn, info['count'], info['importers'])
    elif doc.get('tool') == 'dump_pe_imports':
        for f in doc['files']:
            for imp in f['imports']:
                for fn in imp['functions']:
                    add(imp['dll'], fn['name'] or '#%d' % fn['ordinal'], 1, f['name'])
    else:
        for dll, fns in doc.items():
            for fn in fns:
                add(dll, fn)
    return req


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--provided', action='append', required=True)
    ap.add_argument('--required', action='append', required=True)
    ap.add_argument('-o', '--output', default='-')
    ap.add_argument('--json')
    ap.add_argument('--no-apiset-map', action='store_true')
    ap.add_argument('--include-non-i386', action='store_true',
                    help='also count imports of x64/arm64 binaries (default: skipped)')
    ap.add_argument('--ignore-dll', action='append', default=['node.exe', 'electron.exe'],
                    help='host-executable imports to ignore (native .node modules import from node.exe)')
    ap.add_argument('--exclude-importer', action='append', default=[], metavar='GLOB',
                    help='drop binaries matching GLOB, e.g. "*interactive_ui_tests.exe" "*dxcompiler.dll"')
    a = ap.parse_args()
    ignore = {norm(d, False) for d in a.ignore_dll}
    m = not a.no_apiset_map
    prov, req = {}, {}
    for p in a.provided:
        for k, v in load_provided(p, m).items():
            prov.setdefault(k, set()).update(v)
    for p in a.required:
        for k, v in load_required(p, m, not a.include_non_i386, ignore, a.exclude_importer).items():
            e = req.setdefault(k, {'count': 0, 'importers': set(), 'orig_dlls': set(), 'priority': None})
            e['count'] += v['count']; e['importers'] |= v['importers']; e['orig_dlls'] |= v['orig_dlls']
    gaps = [(dll, fn, e) for (dll, fn), e in req.items() if fn not in prov.get(dll, ())]
    gaps.sort(key=lambda g: (-g[2]['count'], g[0], g[1]))
    lines = ['# API gap report', '', 'Required: %d unique APIs, missing: %d (%.1f%%)' % (
        len(req), len(gaps), 100.0 * len(gaps) / max(1, len(req))), '']
    per_dll = {}
    for dll, fn, e in gaps:
        per_dll[dll] = per_dll.get(dll, 0) + 1
    lines += ['## Missing per DLL', '', '| DLL | missing | DLL provided? |', '|---|---|---|']
    lines += ['| %s | %d | %s |' % (d, n, 'yes' if d in prov else '**NO (whole DLL missing)**')
              for d, n in sorted(per_dll.items(), key=lambda kv: -kv[1])]
    lines += ['', '## Missing APIs (sorted by number of importing binaries)', '',
              '| # | DLL | Function | importers | imported as |', '|---|---|---|---|---|']
    for i, (dll, fn, e) in enumerate(gaps, 1):
        lines.append('| %d | %s | %s | %d | %s |' % (i, dll, fn, e['count'], ', '.join(sorted(e['orig_dlls']))))
    by_ord = sorted((dll, fn) for (dll, fn) in req if fn.startswith('#') and fn in prov.get(dll, ()))
    if by_ord:
        lines += ['', '## Ordinal imports resolved by ordinal number only', '',
                  'The ordinal exists in the provided DLL, but 9x and NT ordinals can name different',
                  'functions (e.g. NT shell32 #680 = IsUserAnAdmin). Verify each one by hand.', '']
        lines += ['- %s %s' % p for p in by_ord]
    text = '\n'.join(lines) + '\n'
    if a.output == '-':
        sys.stdout.write(text)
    else:
        open(a.output, 'w').write(text)
    if a.json:
        json.dump([{'dll': d, 'function': f, 'count': e['count'], 'importers': sorted(e['importers']),
                    'imported_as': sorted(e['orig_dlls'])} for d, f, e in gaps], open(a.json, 'w'), indent=1)
    sys.stderr.write('%d gaps of %d required APIs\n' % (len(gaps), len(req)))


if __name__ == '__main__':
    main()
