#!/usr/bin/env python3
"""check_pic.py kexnt.dll nm-output: fail if a base relocation lies inside [kxpic_section_start, kxpic_fwd_end)
(those bytes are copied into a shared page at run time, fwdload_pic.c)."""
import struct, sys
d = open(sys.argv[1], 'rb').read()
syms = {}
for line in open(sys.argv[2]):
    p = line.split()
    if len(p) == 3: syms[p[2].lstrip('_').split('@')[0]] = int(p[0], 16)
lo, hi = syms['kxpic_section_start'], syms['kxpic_fwd_end']
o = struct.unpack_from('<I', d, 0x3c)[0]; base = struct.unpack_from('<I', d, o + 0x34)[0]
n = struct.unpack_from('<H', d, o + 6)[0]; so = o + 0x18 + struct.unpack_from('<H', d, o + 0x14)[0]
secs = [struct.unpack_from('<IIII', d, so + i * 40 + 8) for i in range(n)]
def off(r):
    for vs, va, rs, rp in secs:
        if va <= r < va + max(vs, rs): return r - va + rp
rva, size = struct.unpack_from('<II', d, o + 0x18 + 0x60 + 5 * 8)
p, end, bad = off(rva), off(rva) + size, []
while p < end:
    page, blk = struct.unpack_from('<II', d, p)
    if blk < 8: break
    for i in range((blk - 8) // 2):
        e = struct.unpack_from('<H', d, p + 8 + 2 * i)[0]
        a = base + page + (e & 0xFFF)
        if e >> 12 and lo <= a < hi: bad.append(hex(a))
    p += blk
if hi - lo > 4096 - 320: sys.exit('check_pic: kxpic code is %d bytes, the page has room for %d' % (hi - lo, 4096 - 320))
if bad: sys.exit('check_pic: base relocations inside the position-independent kxpic code: ' + ' '.join(bad))
print('check_pic: kxpic code %d bytes, no relocations' % (hi - lo))
