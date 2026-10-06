#!/usr/bin/env python3
"""Why did state flip 2 -> 9 between runs?

game_grpc_full.py  (state=2, create=1  -- LIVE)
    creds; EXEC(0x8130620); holder[8]=0,[9]=0,[51]=0
    INIT_1(1); INIT_40(0x40); INIT_MAIN; CREATE

game_grpc_pump2.py (state=9, create=0  -- DEAD)
    same, but the loop also calls ENGINE_KICK/ENGINE_2/CHAN_STATE/CHAN_CONN

Differences to test one at a time, printing the holder state byte and the
decider 0x81306e8 result after every step, so we can see exactly which call
tips it from 2 to 9.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

B = 0x10000000000
CREDS = 0x677716C
EXEC = 0x8130620
DECIDER = 0x81306E8
INIT_1 = 0x812CF90
INIT_40 = 0x812CF88
INIT_MAIN = 0x812CF98
CHAN_CREATE = 0x812D034
CHAN_CONN = 0x812D0E4
CHAN_STATE = 0x812D1B4
CHAN_PEER = 0x812D1E4
ENGINE_KICK = 0x7B095B8
ENGINE_2 = 0x7B095F4


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def rb(core, a):
    return bytes(core.uc.mem_read(a, 1))[0]


def show(core, holder, tag):
    print("   %-22s +0x8=%-3d +0x9=%-3d +0x0a=%-4d +0x51=%-3d  decider=%#x"
          % (tag, rb(core, holder + 8), rb(core, holder + 9),
             rb(core, holder + 0xA), rb(core, holder + 0x51),
             u64(core, B + 0xA4CFA40)), flush=True)


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)

    holder = core.alloc(0xa00, b"\0" * 0xa00, name="holder")
    core.write_u8(holder + 0x8, 0)
    core.write_u8(holder + 0x9, 0)
    core.write_u8(holder + 0x51, 0)
    print("[d] fresh:", flush=True)
    show(core, holder, "fresh")

    core.call(CREDS, timeout_s=180, max_insns=500_000_000)
    show(core, holder, "after creds")

    r = core.call(EXEC, timeout_s=180, max_insns=600_000_000)
    print("   EXEC 0x8130620 -> x0=%#x" % r["x0"], flush=True)
    show(core, holder, "after EXEC")

    core.call(DECIDER, timeout_s=30)
    show(core, holder, "decider call")

    core.call(INIT_1, w0=holder, w1=1, timeout_s=30)
    show(core, holder, "after init(1)")
    core.call(INIT_40, w0=holder, w1=0x40, timeout_s=30)
    show(core, holder, "after init(0x40)")

    core.call(DECIDER, timeout_s=30)
    show(core, holder, "decider again")

    # 0x812cf98's live branch is entered when its decider is NULL *and* it
    # then sets +0x8=2, +0x51=1 and calls 0x7b095f4 / 0x81309e4. The dead
    # branch (state 8 then 9) is what we keep landing in, so try forcing the
    # precondition the live path needs and re-run.
    for pre in (0, 1):
        core.write_u8(holder + 0x8, 0)
        core.write_u8(holder + 0x51, pre)
        core.write_u8(holder + 0x9, 1)
        core.write_u8(holder + 0xA, 0x40)
        r = core.call(INIT_MAIN, w0=holder, timeout_s=180,
                      max_insns=400_000_000)
        show(core, holder, "INIT_MAIN with +0x51=%d" % pre)
        r = core.call(CHAN_CREATE, w0=holder, timeout_s=180,
                      max_insns=600_000_000)
        print("   CREATE(+0x51=%d) -> x0=%#x" % (pre, r["x0"]), flush=True)
        show(core, holder, "  after CREATE")

    core.write_u8(holder + 0x8, 0)
    core.write_u8(holder + 0x51, 0)
    core.write_u8(holder + 0x9, 1)
    core.write_u8(holder + 0xA, 0x40)
    r = core.call(INIT_MAIN, w0=holder, timeout_s=180, max_insns=400_000_000)
    show(core, holder, "after INIT_MAIN")

    r = core.call(CHAN_CREATE, w0=holder, timeout_s=180, max_insns=600_000_000)
    print("   CREATE -> x0=%#x" % r["x0"], flush=True)
    show(core, holder, "after CREATE")

    for label, fn in (("CHAN_PEER", CHAN_PEER), ("CHAN_STATE", CHAN_STATE),
                      ("CHAN_CONN", CHAN_CONN), ("ENGINE_KICK", ENGINE_KICK),
                      ("ENGINE_2", ENGINE_2)):
        try:
            r = core.call(fn, w0=holder, timeout_s=60, max_insns=200_000_000)
            print("   %-12s -> x0=%#x" % (label, r["x0"]), flush=True)
        except Exception as e:
            print("   %-12s EXC %s" % (label, type(e).__name__), flush=True)
        show(core, holder, "  after " + label)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
