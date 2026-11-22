#!/usr/bin/env python3
# Usage: chrome_gaps.py [core1.dll,core2.exe,...]
# Paths come from the environment (defaults relative to this source tree):
#   KEX_CD98   folder of Win98 SE reference DLLs extracted from the CD CABs
#   KEX_KEX45  KernelEx 4.5.2 install folder (optional: pdh/psapi/userenv/... it ships)
#   KEX_MANIFEST  chromium_import_scan.py output   KEX_MISS_OUT  where to write the gap list
import json, struct, sys, os, glob, re
HERE=os.path.dirname(os.path.abspath(__file__)); SRC=os.path.normpath(os.path.join(HERE,'..','..'))
CD98=os.environ.get('KEX_CD98', os.path.expanduser('~/cd98'))
KEX45=os.environ.get('KEX_KEX45', '')
MANIFEST=os.environ.get('KEX_MANIFEST', os.path.join(SRC,'..','analysis','chromium_manifest.json'))
MISS_OUT=os.environ.get('KEX_MISS_OUT', os.path.join(SRC,'..','analysis','chrome_miss.json'))
def exports(path):
    try: return _exports(path)
    except Exception: return set()
def _exports(path):
    d=open(path,'rb').read()
    pe=struct.unpack_from('<I',d,0x3c)[0]; nsec=struct.unpack_from('<H',d,pe+6)[0]; optsz=struct.unpack_from('<H',d,pe+20)[0]
    opt=pe+24; exp_rva=struct.unpack_from('<I',d,opt+96)[0]
    if not exp_rva: return set()
    secs=[struct.unpack_from('<8sIIII',d,opt+optsz+40*i) for i in range(nsec)]
    def off(rva):
        for n,vs,va,rs,ro in secs:
            if va<=rva<va+max(vs,rs): return ro+rva-va
    ob,nf,nn,af,an=struct.unpack_from('<IIIII',d,off(exp_rva)+16)
    out=set('#%d'%(ob+i) for i in range(nf) if struct.unpack_from('<I',d,off(af)+4*i)[0])
    for i in range(nn):
        o=off(struct.unpack_from('<I',d,off(an)+4*i)[0]); out.add(d[o:d.index(b'\0',o)].decode('latin1'))
    return out
have={}
def add(dll,names): have.setdefault(dll.lower(),set()).update(names)
for p in glob.glob(os.path.join(CD98,'*')):
    add(os.path.basename(p),exports(p))
for p in ['pdh.dll','psapi.dll','userenv.dll','uxtheme.dll','wtsapi32.dll','msimg32.dll']:
    if KEX45 and os.path.exists(os.path.join(KEX45,p)): add(p,exports(os.path.join(KEX45,p)))
k452=set(json.load(open(os.path.join(SRC,'docs','kex452_names.json'))))
B=os.path.join(SRC,'new_stubs','build')+'/'
kexnt=exports(B+'kexnt.dll')
routed={}
for l in open(os.path.join(SRC,'new_stubs','kexnt_targets.txt')):
    l=l.split('#')[0].split()
    if len(l)==2:
        for t in l[1].split(','): routed.setdefault(t.lower()+'.dll',set()).add(l[0])
for p in glob.glob(B+'api-ms-*.dll')+glob.glob(B+'stubs/*.dll')+glob.glob(B+'stubs/*.cpl'): add(os.path.basename(p),exports(p))
man=json.load(open(MANIFEST))
core=sys.argv[1].split(',') if len(sys.argv)>1 else None
miss={}
for dll,v in man['dlls'].items():
    dl=dll.lower()
    for fn,x in v['functions'].items():
        imps=[i.split('\\')[-1] for i in x['importers']]
        if core: imps=[i for i in imps if i in core]
        if not imps: continue
        ok = fn in have.get(dl,()) or fn in routed.get(dl,()) or (dl in('kernel32.dll','user32.dll','gdi32.dll','advapi32.dll','ntdll.dll','shell32.dll','ole32.dll','comdlg32.dll','winspool.drv','version.dll','shlwapi.dll','comctl32.dll','oleaut32.dll','ws2_32.dll','winmm.dll','iphlpapi.dll','secur32.dll','crypt32.dll','msimg32.dll','usp10.dll') ) and fn in k452
        if not ok:
            miss.setdefault(dl,[]).append((fn,x['delay'],imps))
json.dump(miss,open(MISS_OUT,'w'),indent=1)
for dl in sorted(miss,key=lambda k:-len(miss[k])):
    st=[f for f,dly,_ in miss[dl] if not dly]
    print(f"{dl}: {len(miss[dl])} missing ({len(st)} static){'  [DLL absent]' if dl not in have else ''}")
