#!/usr/bin/env python3
"""Read the static objects the URL builder references.

Builder 0x767eaf0 references these absolute addresses:
  0x97a2600   (stored into this->[0] early)
  0x97d4448   (stored into this->[0] late; +0x48 -> this->[0x110];
                +0x78 -> this->[0x130])
  0xaf6dad    (16 data bytes -> this->[0x139])
  0xa0026e    "CmdGetServerEnv.php"   (confirmed)
  0xb42c54    (8 bytes of text -> copied 4x into the request)

Dump each as qwords + strings.
"""
from __future__ import annotations

import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "scripts"))
sys.path.insert(0, HERE)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

ADDRS = [
    (0x97A2600, "early this->[0]"),
    (0x97A2648, "  +0x48"),
    (0x97A2678, "  +0x78"),
    (0x97D4448, "late this->[0]"),
    (0x97D4490, "  +0x48 -> this->[0x110]"),
    (0x97D44C0, "  +0x78 -> this->[0x130]"),
    (0xAF6DAD, "16 data bytes -> this->[0x139]"),
    (0xA0026E, "path literal"),
    (0xB42C54, "8 text bytes x4"),
]


def main():
    print("[statics] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    print("[statics] ready\n", flush=True)

    B = core.base

    for addr, note in ADDRS:
        print("=" * 74)
        print(f"{addr:#x}   {note}")
        print("=" * 74)
        try:
            raw = bytes(core.uc.mem_read(B + addr, 0x80))
        except Exception as e:
            print(f"  unreadable: {type(e).__name__}\n")
            continue
        for off in range(0, 0x80, 8):
            at = addr + off
            v = struct.unpack_from("<Q", raw, off)[0]
            if v == 0:
                continue
            sel = " >>" if off == 0 else "   "
            parts = [f"{at:#x}: {v:#018x}"]
            # ascii?
            bs = struct.pack("<Q", v)
            if all(32 <= c < 127 for c in bs):
                parts.append(f'ascii "{bs.decode()}"')
            # pointer to string?
            if B <= v < B + 0x100000000:
                try:
                    s = bytes(core.uc.mem_read(v, 48))
                except Exception:
                    s = b""
                z = s.find(b"\0")
                if z >= 4 and all(32 <= c < 127 for c in s[:z]):
                    parts.append(f"-> str {s[:z].decode()!r}")
                else:
                    parts.append(f"-> {v - B:#x}")
            print(f"  {sel} " + "  ".join(parts))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
