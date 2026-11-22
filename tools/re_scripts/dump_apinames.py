#!/usr/bin/env python3
"""Collect names a KernelEx api library provides: scan data for {char *name, void *code} pairs
(DECL_API entries), grouping consecutive runs; the run is preceded in an apilib_api_table by the lib name."""
import struct, sys, json, re
def scan(path):
    d=open(path,'rb').read()
    pe=struct.unpack_from('<I',d,0x3c)[0]; nsec=struct.unpack_from('<H',d,pe+6)[0]; optsz=struct.unpack_from('<H',d,pe+20)[0]
    opt=pe+24; base=struct.unpack_from('<I',d,opt+28)[0]
    secs=[struct.unpack_from('<8sIIII',d,opt+optsz+40*i) for i in range(nsec)]
    def sec_of(va):
        rva=va-base
        for n,vs,sva,rs,ro in secs:
            if sva<=rva<sva+max(vs,rs): return n.rstrip(b'\0'),ro+rva-sva
        return None,None
    def cs(va):
        n,o=sec_of(va)
        if n is None or n==b'.text': return None
        e=d.find(b'\0',o); s=d[o:e]
        return s.decode() if re.fullmatch(rb'[A-Za-z_][A-Za-z0-9_@]{2,80}',s) else None
    runs=[]; 
    for n,vs,sva,rs,ro in secs:
        if n.rstrip(b'\0') not in (b'.rdata',b'.data'): continue
        i=ro; cur=[]
        while i+8<=ro+rs:
            a,b=struct.unpack_from('<II',d,i)
            nm=cs(a); sn,_=sec_of(b)
            if nm and sn==b'.text': cur.append(nm); i+=8; continue
            if len(cur)>=3: runs.append(cur)
            cur=[]; i+=4
        if len(cur)>=3: runs.append(cur)
    return [r for r in runs if r==sorted(r)]
if __name__=='__main__':
    s=set()
    for f in sys.argv[1:]:
        for r in scan(f): s.update(r)
    print(json.dumps(sorted(s)))

def scan_movs(path):
    """4.5.2 builds some tables at run time: mov dword [tbl+i], offset name / mov [tbl+i+4], offset fn."""
    d=open(path,'rb').read()
    pe=struct.unpack_from('<I',d,0x3c)[0]; nsec=struct.unpack_from('<H',d,pe+6)[0]; optsz=struct.unpack_from('<H',d,pe+20)[0]
    opt=pe+24; base=struct.unpack_from('<I',d,opt+28)[0]
    secs=[struct.unpack_from('<8sIIII',d,opt+optsz+40*i) for i in range(nsec)]
    def sec_of(va):
        rva=va-base
        for n,vs,sva,rs,ro in secs:
            if sva<=rva<sva+max(vs,rs): return n.rstrip(b'\0'),ro+rva-sva
        return None,None
    out=set()
    for m in re.finditer(rb'\xC7\x05(....)(....)\xC7\x05(....)(....)',d,re.S):
        dst1,imm1,dst2,imm2=[struct.unpack('<I',g)[0] for g in m.groups()]
        if dst2!=dst1+4: continue
        n,o=sec_of(imm1); n2,_=sec_of(imm2)
        if n not in (b'.rdata',b'.data') or n2!=b'.text': continue
        s=d[o:d.find(b'\0',o)]
        if re.fullmatch(rb'[A-Za-z_][A-Za-z0-9_@]{2,80}',s): out.add(s.decode())
    return out
if __name__=='__main__' and '--movs' in sys.argv: pass
