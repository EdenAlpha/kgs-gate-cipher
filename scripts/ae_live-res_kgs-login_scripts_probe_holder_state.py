#!/usr/bin/env python3
"""Trace the holder state byte through 0x812cf98 and 0x812d034.

0x812cf98 (called by the game as the third init) does:
    0x81306e8(holder) -> w20
    if (w20 != 0) { holder+0x8 = 8 ; ... ; holder+0x8 = 9 }   <- dead
    else            { holder+0x8 = 2 ; holder+0x51 = 1 ;
                      0x7b095f4(holder+0x58) ; 0x81309e8(...) }  <- live
So the branch is decided by 0x81306e8. We need it to return 0.

Print the holder state byte after each of the game's init calls, and what
0x81306e8 returns, so we can see which path we are on and what 0x81306e8
checks.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

INIT_1 = 0x812CF90        # holder+0x9  = w1
INIT_40 = 0x812CF88       # holder+0xa  = w1
INIT_MAIN = 0x812CF98     # the branching init
PROBE = 0x81306E8         # decides dead vs live
CHAN_CREATE = 0x812D034
B = 0x10000000000


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def rb(core, a):
    return bytes(core.uc.mem_read(a, 1))[0]


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[h] core booted", flush=True)

    holder = core.alloc(0xa00, b"\0" * 0xa00, name="holder")
    core.write_u8(holder + 0x8, 0)
    core.write_u8(holder + 0x9, 0)
    core.write_u8(holder + 0x51, 0)

    # what does the decider see?
    r = core.call(PROBE, w0=holder, timeout_s=60)
    print("[h] 0x81306e8 -> x0=%#x   (0 = LIVE branch wanted)"
          % r["x0"], flush=True)

    # fill the target string slot the game uses (holder+0x58 area)
    core.call(INIT_1, w0=holder, w1=1, timeout_s=30)
    print("[h] after init(1):   +0x8=%d +0x9=%d +0xa=%d +0x51=%d"
          % (rb(core, holder + 8), rb(core, holder + 9),
             rb(core, holder + 0xA), rb(core, holder + 0x51)), flush=True)
    core.call(INIT_40, w0=holder, w1=0x40, timeout_s=30)
    print("[h] after init(0x40):+0x8=%d +0x9=%d +0xa=%d"
          % (rb(core, holder + 8), rb(core, holder + 9),
             rb(core, holder + 0xA)), flush=True)

    r = core.call(INIT_MAIN, w0=holder, timeout_s=120, max_insns=300_000_000)
    print("[h] after init_main: err=%s x0=%#x  state(+0x8)=%d +0x51=%d"
          % (r["error"], r["x0"], rb(core, holder + 8),
             rb(core, holder + 0x51)), flush=True)

    r = core.call(CHAN_CREATE, w0=holder, timeout_s=120,
                  max_insns=300_000_000)
    print("[h] channel create -> x0=%#x  (1 = created, 0 = refused: state==8)"
          % r["x0"], flush=True)
    print("[h] state after create = %d" % rb(core, holder + 8), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
