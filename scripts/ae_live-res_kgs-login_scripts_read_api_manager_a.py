#!/usr/bin/env python3
"""What IS `a` in gate/gate_<a>.php?

The composer's caller passes x1 = SELF+0x70 where SELF is the ApiManager
(0x7b02148 builds it).  We have read +0x70 off the command object and the
task -- both empty.  The name lives on the ApiManager.  Build it with the
game's own constructor and read the field.

Then feed that exact value to the composer and print the URL.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn.arm64_const import (                      # noqa: E402
    UC_ARM64_REG_X1, UC_ARM64_REG_X2,
)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

APIMGR_CTOR = 0x7B02148       # builds ApiManager: +0x70 gets a std::string
COMPOSER = 0x7B099D0
CREATE = 0x7CDA280


def u64(core, a):
    try:
        return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]
    except Exception:
        return 0


def rd_str(core, addr):
    try:
        b0 = bytes(core.uc.mem_read(addr, 1))[0]
        if b0 & 1:
            n = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 8, 8)))[0]
            p = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 0x10, 8)))[0]
            if not (0 < n <= 512) or not p:
                return None
            raw = bytes(core.uc.mem_read(p, n))
        else:
            n = b0 >> 1
            if n == 0 or n > 22:
                return None
            raw = bytes(core.uc.mem_read(addr + 1, n))
        return raw.decode("utf-8", "replace")
    except Exception:
        return None


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(CREATE, timeout_s=60)
    B = core.base

    # ---- build the ApiManager with the game's own ctor ------------------
    mgr = core.alloc(0x800, b"\0" * 0x800, name="apimgr")
    r = core.call(APIMGR_CTOR, w0=mgr, timeout_s=180, max_insns=200_000_000)
    print(f"[a] ApiManager ctor -> obj={mgr:#x} err={r['error']}", flush=True)

    print("\n[a] ==== every decodable string on the ApiManager ====", flush=True)
    vals = []
    for off in range(0, 0x800, 8):
        s = rd_str(core, mgr + off)
        if s:
            print(f"    +{off:#06x}  {s!r}", flush=True)
            vals.append((off, s))

    a_val = None
    for off, s in vals:
        if off == 0x70:
            a_val = s
    print(f"\n[a] *** the value at +0x70 (this is `a`) = {a_val!r}", flush=True)

    if a_val is None:
        print("[a] +0x70 is empty; trying every string we found as `a`",
              flush=True)
        candidates = [s for _, s in vals]
    else:
        candidates = [a_val]

    # ---- feed each candidate to the composer and print the URL ----------
    def mk_str(core, t: bytes) -> int:
        buf = bytearray(32)
        if len(t) <= 22:
            buf[0] = len(t) << 1
            buf[1:1 + len(t)] = t
        else:
            buf[0] = 1
            struct.pack_into("<Q", buf, 8, len(t))
            ptr = core.alloc(len(t) + 1, t + b"\0", name="cstr")
            struct.pack_into("<Q", buf, 0x10, ptr)
        return core.alloc(32, bytes(buf), name="str")

    print("\n[a] ==== URLs the composer builds for each candidate ====",
          flush=True)
    for cand in candidates:
        out = core.alloc(64, b"\0" * 64, name="out")
        try:
            r = core.call(COMPOSER, w0=out,
                          x1=mk_str(core, cand.encode()),
                          x2=mk_str(core, b""),
                          timeout_s=60, max_insns=200_000_000)
        except Exception as e:
            print(f"    a={cand!r:24s} ERR {e}", flush=True)
            continue
        url = rd_str(core, out)
        print(f"    a={cand!r:24s} -> {url!r}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
