#!/usr/bin/env python3
"""M11a part 2: decode the envelope vtable 0x977ad48 from packed relocs,
find the real function in slot +0x18, and find virtual callers of 0x66f09c0."""
import numpy as np
import struct

AN = '/home/z/my-project/apk_lab/analysis'
pr = np.load(f'{AN}/packed_relocs.npz')
off = pr['offset']
sym = pr['sym']
rt = pr['rtype']
ad = pr['addend']

# R_AARCH64_RELATIVE = 1027 typically; check types present
import collections
print('reloc types:', collections.Counter(rt.tolist()).most_common(8))

VT = 0x977ad48
lo = np.searchsorted(off, VT, 'left')
hi = np.searchsorted(off, VT + 0x80, 'left')
print(f'relocs in [{VT:#x}, {VT+0x80:#x}):')
for i in range(lo, hi):
    print(f'  {off[i]:#x}: type={rt[i]} sym={sym[i]} addend={ad[i]:#x}')

# does any reloc ADDEND equal 0x66f09c0? (virtual registration)
hits = np.where((ad == 0x66f09c0) | (sym == 0x66f09c0))[0]
print(f'\nrelocs referencing 0x66f09c0 ({len(hits)}):')
for i in hits[:40]:
    print(f'  at {off[i]:#x}: type={rt[i]} sym={sym[i]} addend={ad[i]:#x}')
