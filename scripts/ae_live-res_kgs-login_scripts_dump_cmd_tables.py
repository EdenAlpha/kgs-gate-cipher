#!/usr/bin/env python3
"""Dump the command dispatch tables the reverse-reloc map found.

CMD_GET_SERVER_ENV -> slots 0x980b2a8..0x980b308  (24-byte stride)
CMD_LOGIN          -> slots 0x980de88..0x980e050  (24-byte stride)

Each slot holds a pointer to the same string, so these are struct arrays
where one field is the command name.  Dump each entry fully: the adjacent
fields will be the handler, the path, the script, flags -- exactly what we
have been unable to see.
"""
from __future__ import annotations

import struct

NPZ = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode"
       r"\peerlink_work\apk_lab\analysis\packed_relocs.npz")
SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")

data = open(SO, "rb").read()


def rd_str(va: int):
    """Read a libc++ std::string at a file vaddr (post-relocation we treat
    the addend as the string vaddr)."""
    try:
        b0 = data[va]
    except Exception:
        return None
    try:
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


def resolve(va: int):
    """A slot may hold a relocated pointer (addend) or inline data."""
    if va + 8 > len(data):
        return None, ""
    v = struct.unpack_from("<Q", data, va)[0]
    s = rd_str(v) if 0 < v < len(data) else None
    return v, s


def dump_table(base: int, count: int, stride: int, label: str):
    print(f"\n=== {label} @ {base:#x}  ({count} x {stride}B) ===", flush=True)
    for i in range(count):
        row = []
        for j in range(0, stride, 8):
            va = base + i * stride + j
            if va + 8 > len(data):
                break
            v = struct.unpack_from("<Q", data, va)[0]
            s = rd_str(v) if 0 < v < len(data) else None
            if s is not None:
                row.append(f"+{j:#04x}={s!r}")
            elif v == 0:
                row.append(f"+{j:#04x}=0")
            elif 0x2800000 <= v < 0x8c00000:
                row.append(f"+{j:#04x}=fn@{v:#x}")
            elif v < 0x20000:
                row.append(f"+{j:#04x}={v}")
            else:
                row.append(f"+{j:#04x}={v:#x}")
        print(f"  [{i:3d}] " + "  ".join(row), flush=True)


def main():
    # CMD_GET_SERVER_ENV slots at 0x980b2a8..0x980b308 stride 0x18
    dump_table(0x980B2A8 - 0x18 * 4, 14, 0x18, "table A (CMD_GET_SERVER_ENV)")

    # CMD_LOGIN slots at 0x980de88..0x980e050 stride 0x18
    dump_table(0x980DE88 - 0x18 * 4, 30, 0x18, "table B (CMD_LOGIN)")

    # also: what is the stride REALLY?  try 8 and 32 around the same base
    for st in (8, 24, 32):
        print(f"\n--- stride {st} probe at 0x980de88 ---", flush=True)
        dump_table(0x980DE80, 6, st, f"stride {st}")


if __name__ == "__main__":
    main()
