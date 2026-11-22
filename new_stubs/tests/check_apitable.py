#!/usr/bin/env python3
"""Static check of kexnt.dll's KernelEx api table: walks get_api_table()'s data in the PE image and
verifies every entry is sorted (strcmp) and points at the same code as the same-named export.
No third-party modules (pefile is not needed)."""
import struct, sys
d = open(sys.argv[1],'rb').read()
pe = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, pe+6)[0]; optsz = struct.unpack_from('<H', d, pe+20)[0]
opt = pe+24; base = struct.unpack_from('<I', d, opt+28)[0]
exp_rva = struct.unpack_from('<I', d, opt+96)[0]
secs=[struct.unpack_from('<8sIIII', d, opt+optsz+40*i) for i in range(nsec)]
def off(rva):
    for n,vs,va,rs,ro in secs:
        if va <= rva < va+max(vs,rs): return ro + rva - va
    raise ValueError(hex(rva))
rd=lambda rva,n: d[off(rva):off(rva)+n]
def cstr_rva(rva):
    o=off(rva); return d[o:d.index(b'\0',o)].decode()
_,_,_,_,_,obase,nf,nn,af,an,ao = struct.unpack_from('<IIHHIIIIIII', d, off(exp_rva))
funcs=[struct.unpack_from('<I',d,off(af)+4*i)[0] for i in range(nf)]
exp={}
for i in range(nn):
    nrva=struct.unpack_from('<I',d,off(an)+4*i)[0]; o=struct.unpack_from('<H',d,off(ao)+2*i)[0]
    exp[cstr_rva(nrva)]=funcs[o]
code=rd(exp['get_api_table'],6)
assert code[0]==0xB8 and code[5]==0xC3, code.hex()
p=struct.unpack('<I',code[1:5])[0]-base; bad=0
while True:
    lib,named,cnt,ords,ocnt=struct.unpack('<IIiIi',rd(p,20)); p+=20
    if not lib: break
    names=[]
    for i in range(cnt):
        nva,addr=struct.unpack('<II',rd(named-base+8*i,8)); n=cstr_rva(nva-base); names.append(n)
        a=addr-base; c=rd(a,13)
        if c[0]==0x83 and c[1]==0x3D and c[6]==2 and c[7]==0x0F and c[8]==0x84:   # build 89 gate thunk: cmp; je real
            a=a+13+struct.unpack('<i',c[9:13])[0]; gates=globals().get('gates',0)+1; globals()['gates']=gates
        if n in exp and exp[n]!=a: print('  MISMATCH',n); bad+=1   # cdecl MSVCRT entries are table-only (not exported)
    if names!=sorted(names): print('  NOT SORTED', cstr_rva(lib-base)); bad+=1
    print(f"{cstr_rva(lib-base)}: {cnt} names, {ocnt} ordinals")
print(f"gate thunks: {globals().get('gates',0)}")
print('OK' if not bad else f'{bad} problems')
sys.exit(1 if bad else 0)
