#!/usr/bin/env python3
"""gen_l_intl.py <out> [check.nlp]: the Windows NT casing table file l_intl.nls, generated from the Unicode Character
Database that ships with Python (no Microsoft data), limited to characters of Unicode 3.2 (Windows XP's time).

Windows 98 has no l_intl.nls. The .NET 2.0 runtime (mscorwks.dll COMNlsInfo::CreateOSCasingTableMemorySection, used for
the invariant culture when the OS reports NT) maps <system folder>\\l_intl.nls; without it TextInfo's set-up fails and no
.NET 2.0-3.5 program starts ("TypeInitializationException: System.Globalization.TextInfo").

Layout read by the runtime: WORD 1, WORD N (words of the upper-case table + 1), upper-case table, WORD M (words of the
lower-case table + 1), lower-case table. Each table is an NLS 8:4:4 table: 256 WORD offsets (in WORDs from the table
start) to 16-entry second-level blocks, whose entries are offsets to 16-entry third-level blocks holding the delta
(mapped - code point, mod 65536) for each character. Simple (one-to-one) case mappings of the Basic Multilingual Plane.

With a second argument, the generated mappings are compared with the default tables of .NET's l_intl.nlp (from
mscorlib.dll's resources) and the differences counted - a check only, nothing from it is used.
"""
import struct, sys, unicodedata

OLD = unicodedata.ucd_3_2_0          # the Unicode of Windows XP's time: characters added later keep no mapping

def mapping(upper):
    out = [0] * 0x10000
    for c in range(0x10000):
        if 0xD800 <= c <= 0xDFFF:
            continue
        ch = chr(c)
        m = ch.upper() if upper else ch.lower()
        if len(m) == 1 and m != ch and ord(m) <= 0xFFFF and OLD.category(ch) != 'Cn' and OLD.category(m) != 'Cn':
            out[c] = (ord(m) - c) & 0xFFFF
    return out

def table_844(delta):
    """8:4:4 table as a list of WORDs (offsets relative to the table start, in WORDs)."""
    l3_blocks, l3_index = [], {}
    l2_blocks, l2_index = [], {}
    l1 = []
    for hi in range(256):
        l2 = []
        for mid in range(16):
            base = (hi << 8) | (mid << 4)
            blk = tuple(delta[base:base + 16])
            if blk not in l3_index:
                l3_index[blk] = len(l3_blocks); l3_blocks.append(blk)
            l2.append(l3_index[blk])
        l2 = tuple(l2)
        if l2 not in l2_index:
            l2_index[l2] = len(l2_blocks); l2_blocks.append(l2)
        l1.append(l2_index[l2])
    l2_start = 256
    l3_start = l2_start + 16 * len(l2_blocks)
    words = [l2_start + 16 * i for i in l1]
    for blk in l2_blocks:
        words += [l3_start + 16 * j for j in blk]
    for blk in l3_blocks:
        words += list(blk)
    assert len(words) < 0xFFFF
    return words

def lookup(words, c):
    l2 = words[c >> 8]; l3 = words[l2 + ((c >> 4) & 15)]; return words[l3 + (c & 15)]

def main():
    up, lo = table_844(mapping(True)), table_844(mapping(False))
    data = [1, len(up) + 1] + up + [len(lo) + 1] + lo
    open(sys.argv[1], 'wb').write(struct.pack('<%dH' % len(data), *data))
    print('l_intl.nls: %d bytes (upper %d words, lower %d words)' % (2 * len(data), len(up), len(lo)))
    if len(sys.argv) > 2:
        d = open(sys.argv[2], 'rb').read()
        w = struct.unpack_from('<%dH' % (len(d) // 2), d)
        nu, nl = struct.unpack_from('<II', d, 40), None
        u_off, l_off = struct.unpack_from('<I', d, 40)[0] // 2, struct.unpack_from('<I', d, 44)[0] // 2
        diff_u = sum(1 for c in range(0x10000) if (lookup(w[u_off:], c) != lookup(up, c)))
        diff_l = sum(1 for c in range(0x10000) if (lookup(w[l_off:], c) != lookup(lo, c)))
        print('compared with %s: %d upper-case and %d lower-case mappings differ (of 65536)' % (sys.argv[2], diff_u, diff_l))

if __name__ == '__main__':
    main()
