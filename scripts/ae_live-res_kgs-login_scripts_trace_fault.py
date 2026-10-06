#!/usr/bin/env python3
"""Pin down the exact faulting instruction in the gRPC channel-create path.

The game reaches 0x812d034 (grpc channel create) and then branches to
0x1400000014000000 -- a value read from memory, i.e. a function pointer or
vtable slot that is still zero. We record the last ~40 instructions with
their register values so we can see which object field is unset and which
constructor is responsible.
"""
from __future__ import annotations

import collections
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM  # noqa: E402
from unicorn import UC_HOOK_CODE  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_PC  # noqa: E402

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

HOLDER_CTOR = 0x7DC24F4
CHAN_GATE = 0x7DC2578
B = 0x10000000000

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def wr_str(core, addr, text):
    raw = text.encode()
    p = core.alloc(len(raw) + 1, raw + b"\0", name="tgt")
    core.uc.mem_write(addr, b"\x01" + b"\0" * 7)
    core.write_u64(addr + 8, len(raw))
    core.write_u64(addr + 0x10, p)


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    core.call(HOLDER_CTOR, timeout_s=60)
    holder = u64(core, B + 0xA4B23E8)
    wr_str(core, B + 0xA4B23F0, "dns:///pes22-game.cs.konami.net:443/")

    ring = collections.deque(maxlen=60)
    state = {"n": 0}

    def on_code(uc, addr, size, ud):
        state["n"] += 1
        try:
            ins = bytes(uc.mem_read(addr, 4))
        except Exception:
            return
        w = struct.unpack("<I", ins)[0]
        # capture the source register value of an indirect branch
        extra = ""
        if (w & 0xFE000000) == 0xD6000000:
            rn = (w >> 5) & 0x1F
            from unicorn import arm64_const as A
            try:
                v = uc.reg_read(getattr(A, "UC_ARM64_REG_X%d" % rn))
            except Exception:
                v = -1
            extra = "  [x%d=%#x]" % (rn, v)
        ring.append((addr, w, extra))
        if len(ring) == ring.maxlen:
            for a2, w2, e2 in ring:
                try:
                    txt = next(md.disasm(struct.pack("<I", w2), a2))
                    dis = "%s %s" % (txt.mnemonic, txt.op_str)
                except Exception:
                    dis = "?"
                print("  %#012x: %-38s%s" % (a2, dis, e2), flush=True)
            ring.clear()
            print("  ---- 8< ----", flush=True)

    core.uc.hook_add(UC_HOOK_CODE, on_code, begin=B + 0x812C000,
                     end=B + 0x8287000)
    try:
        r = core.call(CHAN_GATE, timeout_s=120, max_insns=300_000_000)
        print("gate err=%s pc=%#x" % (r["error"], r["pc"]), flush=True)
    except Exception as e:
        print("EXC %s: %s" % (type(e).__name__, str(e)[:160]), flush=True)
    print("instructions executed: %d" % state["n"], flush=True)
    print("holder+8 = %#x" % u64(core, holder + 8), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
