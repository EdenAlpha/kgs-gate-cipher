#!/usr/bin/env python3
"""M11a: static recon of the cmd-5 envelope fault.
- callers of 0x66f09c0 (the faulting fn)
- what PLT 0x8b34bb0 is (the validated-read helper in 0x66eca24)
- the envelope ctor family + vtable 0x977ad48 slots
"""
import json
import numpy as np
import struct

SO = '/home/z/my-project/apk_lab/libUE4.so'
AN = '/home/z/my-project/apk_lab/analysis'

TARGET = 0x66f09c0

# -- bl map: find callers of TARGET ----------------------------------------
bl = np.load(f'{AN}/bl_map.npz')
sites = bl['bl_site']
tgts = bl['bl_target']
hits = sites[tgts == TARGET]
print(f'BL callers of {TARGET:#x} ({len(hits)}):')
for h in hits[:60]:
    print(f'  bl @ {h:#x}')

# also tail-call map (fgraph2)
try:
    fg = np.load(f'{AN}/fgraph2.npz')
    e = fg['entries']
    lo = np.searchsorted(e, TARGET, 'left')
    hi = np.searchsorted(e, TARGET, 'right')
    if lo < hi and e[lo] == TARGET:
        s = fg['src'][lo:hi]
        d = fg['dst'][lo:hi]
        th = s[d == TARGET]
        print(f'B tail-callers of {TARGET:#x} ({len(th)}):')
        for h in th[:40]:
            print(f'  b  @ {h:#x}')
except Exception as ex:
    print('fgraph2:', ex)

# -- plt map: identify 0x8b34bb0 -------------------------------------------
plt = json.load(open(f'{AN}/plt_map.json'))
for k, v in plt.items():
    a = int(k, 16)
    if a in (0x8b34bb0, 0x8b34ce0, 0x8b34e60, 0x8b35310):
        print(f'PLT {a:#x} = {v}')

# -- read vtable 0x977ad48 with correct segment mapping -------------------
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan import v2o

f = open(SO, 'rb')
def rd(va, n):
    o = v2o(va)
    f.seek(o)
    return f.read(n)

for vt in (0x977ad48,):
    slots = struct.unpack('<16Q', rd(vt, 128))
    print(f'vtable @{vt:#x}:')
    for i, s in enumerate(slots):
        print(f'  +{i*8:#04x} = {s:#x}')
