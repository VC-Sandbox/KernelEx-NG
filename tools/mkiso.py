#!/usr/bin/env python3
"""mkiso.py - minimal ISO 9660 + Joliet writer (one flat directory), no dependencies.

Used instead of xorriso to build the KernelEx-NG test CD. Windows 98 reads the Joliet
tree (long names); the ISO 9660 tree gets unique 8.3 names as a fallback.

  python3 mkiso.py -V KEXNG -o kexng.iso <dir>
"""
import argparse, os, struct, time

SECTOR = 2048


def both16(v): return struct.pack('<H', v) + struct.pack('>H', v)
def both32(v): return struct.pack('<I', v) + struct.pack('>I', v)


def dir_date(t):
    return bytes([t.tm_year - 1900, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, 0])


def vol_date(t):
    return time.strftime('%Y%m%d%H%M%S', t).encode() + b'00' + b'\x00'


def dir_record(name_bytes, lba, size, is_dir, t):
    n = len(name_bytes)
    rec = bytearray(33 + n + (1 if n % 2 == 0 else 0))
    rec[0] = len(rec)
    rec[2:10] = both32(lba)
    rec[10:18] = both32(size)
    rec[18:25] = dir_date(t)
    rec[25] = 2 if is_dir else 0
    rec[28:32] = both16(1)
    rec[32] = n
    rec[33:33 + n] = name_bytes
    return bytes(rec)


def pack_records(records):
    """Lay records out in sectors; a record never crosses a sector boundary."""
    out = bytearray()
    for r in records:
        room = SECTOR - (len(out) % SECTOR)
        if len(r) > room:
            out += b'\x00' * room
        out += r
    if len(out) % SECTOR:
        out += b'\x00' * (SECTOR - len(out) % SECTOR)
    return bytes(out)


def short_names(names):
    """Unique uppercase 8.3 names (d-characters) for the ISO 9660 tree."""
    used, res = set(), {}
    for n in names:
        base, ext = os.path.splitext(n)
        clean = lambda s: ''.join(c for c in s.upper() if c.isalnum() or c == '_')
        b, e = clean(base)[:8] or 'FILE', clean(ext)[:3]
        cand, i = b, 1
        while (cand, e) in used:
            suffix = '~%d' % i
            cand = (b[:8 - len(suffix)] + suffix).replace('~', '_')
            i += 1
        used.add((cand, e))
        res[n] = (cand + ('.' + e if e else '') + ';1').encode('ascii')
    return res


def build(src, out, volid):
    t = time.localtime()
    files = sorted(f for f in os.listdir(src) if os.path.isfile(os.path.join(src, f)))
    for f in files:
        if len(f) > 64:
            raise SystemExit('name too long for Joliet: ' + f)
    sn = short_names(files)

    # Layout: 0-15 system, 16 PVD, 17 SVD, 18 terminator, 19-22 path tables, then dirs, then data.
    lba = 19
    pt_l, pt_m, jpt_l, jpt_m = lba, lba + 1, lba + 2, lba + 3
    lba += 4

    def dir_size(name_map):
        recs = [dir_record(b'\x00', 0, 0, True, t), dir_record(b'\x01', 0, 0, True, t)]
        recs += [dir_record(name_map[f], 0, 0, False, t) for f in files]
        return len(pack_records(recs))

    jn = {f: (f + ';1').encode('utf-16-be') for f in files}
    root_sz, jroot_sz = dir_size(sn), dir_size(jn)
    root_lba = lba; lba += root_sz // SECTOR
    jroot_lba = lba; lba += jroot_sz // SECTOR

    data_lba, sizes = {}, {}
    for f in files:
        sizes[f] = os.path.getsize(os.path.join(src, f))
        data_lba[f] = lba
        lba += max(1, (sizes[f] + SECTOR - 1) // SECTOR)
    total = lba

    def root_dir(name_map, own_lba, own_sz):
        recs = [dir_record(b'\x00', own_lba, own_sz, True, t), dir_record(b'\x01', own_lba, own_sz, True, t)]
        recs += [dir_record(name_map[f], data_lba[f], sizes[f], False, t) for f in files]
        return pack_records(recs)

    def path_table(root, big):
        e = bytearray(10)
        e[0] = 1
        e[2:6] = struct.pack('>I' if big else '<I', root)
        e[6:8] = struct.pack('>H' if big else '<H', 1)
        return bytes(e) + b'\x00' * (SECTOR - 10)

    def vd(kind, root_lba_, root_sz_, ptl, ptm, joliet):
        d = bytearray(SECTOR)
        d[0] = kind; d[1:6] = b'CD001'; d[6] = 1
        if joliet:
            enc = lambda s, n: (s.encode('utf-16-be') + ' '.encode('utf-16-be') * n)[:n]
            d[88:91] = b'%/E'
        else:
            enc = lambda s, n: (s.encode('ascii') + b' ' * n)[:n]
        d[8:40] = enc('WIN32', 32); d[40:72] = enc(volid, 32)
        d[80:88] = both32(total)
        d[120:124] = both16(1); d[124:128] = both16(1); d[128:132] = both16(SECTOR)
        d[132:140] = both32(10)
        d[140:144] = struct.pack('<I', ptl); d[148:152] = struct.pack('>I', ptm)
        d[156:190] = dir_record(b'\x00', root_lba_, root_sz_, True, t)
        for off, n in ((190, 128), (318, 128), (446, 128), (574, 128), (702, 37), (739, 37), (776, 37)):
            d[off:off + n] = enc('', n)
        d[813:830] = vol_date(t); d[830:847] = vol_date(t)
        d[847:864] = b'0' * 16 + b'\x00'; d[864:881] = b'0' * 16 + b'\x00'
        d[881] = 1
        return bytes(d)

    with open(out, 'wb') as o:
        o.write(b'\x00' * SECTOR * 16)
        o.write(vd(1, root_lba, root_sz, pt_l, pt_m, False))
        o.write(vd(2, jroot_lba, jroot_sz, jpt_l, jpt_m, True))
        term = bytearray(SECTOR); term[0] = 255; term[1:6] = b'CD001'; term[6] = 1
        o.write(bytes(term))
        o.write(path_table(root_lba, False)); o.write(path_table(root_lba, True))
        o.write(path_table(jroot_lba, False)); o.write(path_table(jroot_lba, True))
        o.write(root_dir(sn, root_lba, root_sz)); o.write(root_dir(jn, jroot_lba, jroot_sz))
        for f in files:
            with open(os.path.join(src, f), 'rb') as i:
                data = i.read()
            pad = max(1, (len(data) + SECTOR - 1) // SECTOR) * SECTOR - len(data)
            o.write(data + b'\x00' * pad)
        assert o.tell() == total * SECTOR
    print('wrote %s: %d files, %d KB' % (out, len(files), total * 2))


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('src'); ap.add_argument('-o', required=True); ap.add_argument('-V', default='KEXNG')
    a = ap.parse_args()
    build(a.src, a.o, a.V)
