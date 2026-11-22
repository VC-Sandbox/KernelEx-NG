import struct, sys
def info(path):
    d=open(path,'rb').read()
    pe=struct.unpack_from('<I',d,0x3c)[0]; nsec=struct.unpack_from('<H',d,pe+6)[0]; optsz=struct.unpack_from('<H',d,pe+20)[0]
    opt=pe+24; exp_rva,_,imp_rva=struct.unpack_from('<III',d,opt+96)
    secs=[struct.unpack_from('<8sIIII',d,opt+optsz+40*i) for i in range(nsec)]
    def off(rva):
        for n,vs,va,rs,ro in secs:
            if va<=rva<va+max(vs,rs): return ro+rva-va
    cs=lambda rva: d[off(rva):d.index(b'\0',off(rva))].decode()
    imps={}
    if imp_rva:
        o=off(imp_rva)
        while True:
            ilt,_,_,name,iat=struct.unpack_from('<IIIII',d,o); o+=20
            if not name: break
            t=ilt or iat; fs=[]
            while True:
                e=struct.unpack_from('<I',d,off(t))[0]; t+=4
                if not e: break
                fs.append('#%d'%(e&0xffff) if e&0x80000000 else cs(e+2))
            imps[cs(name)]=fs
    exps=[]
    if exp_rva:
        nn,an=struct.unpack_from('<I4xI',d,off(exp_rva)+24)
        exps=[cs(struct.unpack_from('<I',d,off(an)+4*i)[0]) for i in range(nn)]
    return imps,exps
if __name__=='__main__':
    for p in sys.argv[1:]:
        i,e=info(p); print(p, {k:len(v) if len(v)>6 else v for k,v in i.items()}, 'exports',len(e))
