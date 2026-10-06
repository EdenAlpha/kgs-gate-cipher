"""Hex-dump the config block and dereference every pointer-looking field to
recover the production host string."""
from __future__ import annotations

import os
import re
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "scripts"))
sys.path.insert(0, HERE)

CFG = 0xA4B0100
LEN = 0x400


def main():
    from peerlink.online_client import OnlineCore, REGISTRARS  # noqa

    core = OnlineCore(verbose=False)
    ok = 0
    for fn in REGISTRARS:
        try:
            core.call(fn)
            ok += 1
        except Exception:
            pass
    print(f"[dump2] {ok}/{len(REGISTRARS)} registrars ran")

    raw = bytes(core.uc.mem_read(core.base + CFG, LEN))
    print(f"\n=== raw {CFG:#x} .. {CFG + LEN:#x} ===")
    for i in range(0, len(raw), 16):
        row = raw[i:i + 16]
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        if row == b"\0" * 16:
            continue
        print(f"  {CFG + i:#011x}  "
              f"{' '.join(f'{b:02x}' for b in row)}  {ascii_}")

    print("\n=== dereferenced pointers ===")
    for i in range(0, LEN - 7, 8):
        (v,) = struct.unpack_from("<Q", raw, i)
        if v == 0:
            continue
        # pointer into our mapped image, or into the emulated heap
        if not ((core.base <= v < core.base + 0x10000000) or
                (0x90000000000 <= v < 0x91000000000)):
            continue
        addr = v if v >= core.base else v
        try:
            blob = bytes(core.uc.mem_read(addr, 160))
        except Exception:
            continue
        n = blob.find(b"\0")
        if not (0 < n < 160):
            continue
        s = blob[:n]
        if not (3 <= n < 160):
            continue
        if not all(32 <= c < 127 for c in s):
            continue
        print(f"  cfg+{i:#06x} ({CFG + i:#x}) -> {v:#x}  "
              f"= {s.decode('ascii')!r}")

    if getattr(core, "_log", None):
        bad = [l for l in core._log if "FAULT" in l]
        print(f"\n{len(bad)} faults in log")
        for l in bad[:6]:
            print("   ", l)
    return 0


if __name__ == "__main__":
    sys.exit(main())
