#!/usr/bin/env python3
"""Run the game's own login-body writer 0x76b1b28 and read what it produces.

0x76b1b28 is a member function that appends JSON into a growable byte buffer
laid out at this+0x118:

    +0x118  size
    +0x120  ptr
    +0x128  capacity

It reads its field values out of the same object.  We give it a zeroed object
and an empty buffer and let it build the request itself.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

BUILD = 0x76B1B28
COLLECT = 0x76B1530          # the function right before it (device info)


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def main() -> int:
    print("[body] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[body] booted", flush=True)

    obj = core.alloc(0x4000, b"\0" * 0x4000, name="login_obj")
    buf = core.alloc(0x20000, b"\0" * 0x20000, name="body_buf")
    core.write_u64(obj + 0x118, 0)
    core.write_u64(obj + 0x120, buf)
    core.write_u64(obj + 0x128, 0x20000)
    print(f"[body] obj={obj:#x} buf={buf:#x}", flush=True)

    for fn, name in ((BUILD, "build"),):
        try:
            r = core.call(fn, w0=obj, timeout_s=120,
                          max_insns=400_000_000)
        except Exception as e:
            print(f"[body] {name} -> EXC {e}", flush=True)
            break
        size = u64(core, obj + 0x118)
        print(f"[body] {name} -> err={r['error']} pc={r['pc']:#x} "
              f"x0={r['x0']:#x}  size={size}", flush=True)
        if size > 0x40000:
            print("[body]   size looks bogus, stopping", flush=True)
            break
        raw = bytes(core.uc.mem_read(buf, max(size, 1)))
        print(f"[body]   body = {raw[:1500]!r}", flush=True)
        if r["error"]:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
