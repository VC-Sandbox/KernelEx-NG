#!/usr/bin/env python3
"""Fail the build if a binary for the test CD contains SSE/MMX code outside the known, harmless places.
KernelEx-NG must run on any Windows 98 CPU (86Box Pentium/Pentium II has no SSE).
Allowed: kexnt's _libm_sse2_* replacements (only SSE2 programs call them), mingw's __matherr / __mingw_raise_matherr
(only run after a math-library error). usage: check_nosse.py OBJDUMP file..."""
import re, subprocess, sys
ALLOWED = {'_kex_c_libm_sqrt', '_kex_c_libm_exp', '_kex_c_libm_pow', '_kex_c_libm_log', '_kex_c_libm_log10',
           '__matherr', '___mingw_raise_matherr',
           '_simd_round'}   # kextest SSE test: only reached after CPUID says the CPU has SSE
bad = 0
for f in sys.argv[2:]:
    out = subprocess.run([sys.argv[1], '-d', f], capture_output=True, text=True).stdout
    fn = '?'
    hits = {}
    for line in out.splitlines():
        m = re.match(r'^[0-9a-f]+ <(.*)>:$', line)
        if m: fn = m.group(1); continue
        if re.search(r'%xmm|%mm[0-7]', line) and fn not in ALLOWED:
            hits[fn] = hits.get(fn, 0) + 1
    for k, v in hits.items():
        print(f"check_nosse: {f}: {v} SSE/MMX instruction(s) in {k}"); bad += 1
sys.exit(1 if bad else 0)
