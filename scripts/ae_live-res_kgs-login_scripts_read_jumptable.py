#!/usr/bin/env python3
"""Read the bootstrap SM's 12-entry jump table at 0xc905b8 and map states."""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

JT = 0xC905B8
BASE = 0x7DC71B4          # offsets are relative to this

with open(SO, "rb") as f:
    f.seek(JT)                       # .rodata: offset == vaddr
    raw = f.read(12 * 2)

print(f"jump table @ {JT:#x} (12 x u16, base {BASE:#x})")
print("=" * 60)
for i in range(12):
    off = struct.unpack_from("<H", raw, i * 2)[0]
    print(f"  state {i:2d}: +{off:#06x}  -> {BASE + off * 4:#x}")
