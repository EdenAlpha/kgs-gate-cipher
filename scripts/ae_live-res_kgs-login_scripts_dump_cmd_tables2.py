#!/usr/bin/env python3
"""Dump the command tables using the RELOCATION ADDENDS (the file is zeros).

Each table entry is 24 bytes = 3 relocated pointers.  The addend is the
target VA, so we can read exactly what each field points at.
"""
from __future__ import annotations

import struct

import numpy as np

NPZ = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode"
       r"\peerlink_work\apk_lab\analysis\packed_relocs.npz")
SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")

data = open(SO, "rb").read()

pr = np.load(NPZ, allow_pickle=True)
off = pr["offset"].astype(np.int64)
rtype = pr["rtype"]
add = pr["addend"].astype(np.int64)
m = rtype == 1027
MAP = {int(o): int(a) for o, a in zip(off[m], add[m])}
print(f"loaded {len(MAP):,} RELATIVE slots", flush=True)


def rd_str(va: int):
    try:
        b0 = data[va]
        if b0 & 1:
            n = struct.unpack_from("<Q", data, va + 8)[0]
            p = struct.unpack_from("<Q", data, va + 0x10)[0]
            if not (0 < n <= 512) or p >= len(data):
                return None
            raw = data[p:p + n]
        else:
            n = b0 >> 1
            if n == 0 or n > 22:
                return None
            raw = data[va + 1:va + 1 + n]
        if not all(32 <= c < 127 for c in raw):
            return None
        return raw.decode()
    except Exception:
        return None


def cell(slot: int) -> str:
    tgt = MAP.get(slot)
    if tgt is None:
        v = struct.unpack_from("<Q", data, slot)[0] if slot + 8 <= len(data) else 0
        return "0" if v == 0 else f"raw={v:#x}"
    s = rd_str(tgt)
    if s is not None:
        return f"{s!r}"
    if 0x2800000 <= tgt < 0x8C00000:
        return f"fn@{tgt:#x}"
    return f"ptr@{tgt:#x}"


def dump(base: int, count: int, stride: int, label: str):
    print(f"\n=== {label}  base={base:#x} count={count} stride={stride} ===",
          flush=True)
    for i in range(count):
        row = []
        for j in range(0, stride, 8):
            row.append(f"+{j:#04x}={cell(base + i * stride + j)}")
        print(f"  [{i:3d}] " + "  ".join(row), flush=True)


# CMD_GET_SERVER_ENV slots at 0x980b2a8..0x980b308 (24B stride)
dump(0x980B2A8, 5, 0x18, "CMD_GET_SERVER_ENV row group")
# CMD_LOGIN slots at 0x980de88..0x980e050
dump(0x980DE88, 24, 0x18, "CMD_LOGIN row group")

# scan for other rows with a string in +0x10 and a fn in +0x00
print("\n\n=== full scan: 24B rows with (fn, ?, str) ===", flush=True)
seen = 0
for base in sorted(MAP):
    if (base & 0x1F) != 0x10:            # only rows ending at +0x10
        continue
    s = rd_str(MAP.get(base, 0))
    if not s or not s.startswith("CMD_"):
        continue
    row = [cell(base - 0x10), cell(base - 0x08), cell(base)]
    print(f"  {base - 0x10:#x}  " + "  ".join(row), flush=True)
    seen += 1
    if seen > 40:
        break
print(f"  ({seen} rows)", flush=True)
