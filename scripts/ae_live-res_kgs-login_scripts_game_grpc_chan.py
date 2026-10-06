#!/usr/bin/env python3
"""LET THE GAME DO IT — step 4: create the gRPC channel the game's way.

The real sequence, read off the game's own code at 0x67ffcbc:
    0x6777868  build the channel-args object from the target string
    0x812cda0  operator new(0xa00)                  -> the args holder
    0x812cf90  (w1=1)   init
    0x812cf88  (w1=0x40) init
    0x812cf98  init
    0x812d034  create the channel
    0x812d1e4 / 0x812d1b4 / 0x812d0e4  peer / state / connectivity
Our earlier attempt passed a raw string to the create call, which is why it
faulted. This builds it the way the game does.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn import UC_HOOK_CODE  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

BUILD_ARGS = 0x6777868
NEW_A00 = 0x812CDA0
INIT_1 = 0x812CF90
INIT_40 = 0x812CF88
INIT_X = 0x812CF98
CHAN_CREATE = 0x812D034
CHAN_PEER = 0x812D1E4
CHAN_STATE = 0x812D1B4
CHAN_CONN = 0x812D0E4

B = 0x10000000000
HOST = "pes22-game.cs.konami.net"
TARGET = "dns:///%s:443/" % HOST


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def rd_str(core, addr):
    try:
        b0 = bytes(core.uc.mem_read(addr, 1))[0]
        if b0 & 1:
            n = u64(core, addr + 8)
            p = u64(core, addr + 0x10)
            if n > 0x4000 or p == 0:
                return "<long>"
            return bytes(core.uc.mem_read(p, n)).decode("utf-8", "replace")
        return bytes(core.uc.mem_read(addr + 1, b0 >> 1)).decode("utf-8",
                                                                 "replace")
    except Exception as e:
        return "<err %s>" % e


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[g] core booted\n", flush=True)

    # a std::string holding the channel target
    raw = TARGET.encode()
    sp_ = core.alloc(len(raw) + 1, raw + b"\0", name="target_heap")
    sstr = core.alloc(32, b"\x01" + b"\0" * 7, name="target_str")
    core.write_u64(sstr + 8, len(raw))
    core.write_u64(sstr + 0x10, sp_)
    print("[g] target string = %r" % rd_str(core, sstr), flush=True)

    # 1. the game's args builder
    args = core.alloc(0x2000, b"\0" * 0x2000, name="args_ctx")
    try:
        r = core.call(BUILD_ARGS, w0=args, w1=sstr, timeout_s=120,
                      max_insns=300_000_000)
        print("[g] build_args -> err=%s x0=%#x" % (r["error"], r["x0"]),
              flush=True)
    except Exception as e:
        print("[g] build_args EXC %s: %s" % (type(e).__name__, str(e)[:150]),
              flush=True)
        return 1

    # 2. the 0xa00 args holder
    holder = core.alloc(0xa00, b"\0" * 0xa00, name="args_holder")
    print("[g] args holder = %#x" % holder, flush=True)

    # 3. the game's init trio + create, exactly as at 0x67ffd2c..0x67ffd54
    for label, fn, w1 in (("init(1)", INIT_1, 1), ("init(0x40)", INIT_40, 0x40),
                          ("init", INIT_X, 0)):
        try:
            r = core.call(fn, w0=holder, w1=w1, timeout_s=120,
                          max_insns=300_000_000)
            print("[g] %-9s %#x -> err=%s x0=%#x"
                  % (label, fn, r["error"], r["x0"]), flush=True)
        except Exception as e:
            print("[g] %-9s EXC %s: %s" % (label, type(e).__name__,
                                            str(e)[:150]), flush=True)
            return 1

    # 4. CREATE -- watch everything it writes
    sent = []

    def on_send(uc, c):
        try:
            buf = uc.reg_read(UC_ARM64_REG_X1)
            n = uc.reg_read(UC_ARM64_REG_X2)
            if 0 < n < 0x10000:
                blob = bytes(uc.mem_read(buf, n))
                sent.append(blob)
                print("[wire] >>> %d bytes: %r" % (len(blob), blob[:400]),
                      flush=True)
        except Exception:
            pass

    core.watch(0x8B35680, on_send, name="send")

    print("[g] CHANNEL CREATE ...", flush=True)
    try:
        r = core.call(CHAN_CREATE, w0=holder, timeout_s=300,
                      max_insns=900_000_000)
        print("[g] create -> err=%s pc=%#x x0=%#x" % (r["error"], r["pc"],
                                                      r["x0"]), flush=True)
    except Exception as e:
        print("[g] create EXC %s: %s" % (type(e).__name__, str(e)[:200]),
              flush=True)

    print("\n[g] writes: %d, bytes: %d"
          % (len(sent), sum(len(b) for b in sent)), flush=True)
    here = os.path.dirname(os.path.abspath(__file__))
    for i, b in enumerate(sent):
        open(os.path.join(here, "chan_wire_%d.bin" % i), "wb").write(b)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
