#!/usr/bin/env python3
"""LET THE GAME DO IT — the full correct init chain.

Root cause chain found by reading the game's own branch tests:

  0x81306e8   return *(0xa4cfa40)         <- the gRPC EXECUTOR singleton
  0x812cf98   the channel init branches on it:
                non-null -> state 8, then 9   (DEAD: "no executor")
                null     -> state 2, +0x51=1,
                            0x7b095f4(holder+0x58), 0x81309e4   (LIVE)
  0x812d034   channel create: returns 0 when state==8, 1 otherwise

So the executor must exist BEFORE the channel init, or every channel is born
dead -- which is exactly what we were seeing. The writer is
  0x8130620  a 28-byte "get or create"
and the higher-level "get" is 0x81304e8.

This runs, in the game's own order:
  1. creds        0x677716c
  2. executor     0x8130620   <- the missing piece
  3. channel init 0x812cf90 / 0x812cf88 / 0x812cf98
  4. channel      0x812d034
  5. the game's gRPC task 0x67ffcbc, which starts the stream
with the socket tapped at sendto/sendmsg.
"""
from __future__ import annotations

import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

B = 0x10000000000
CREDS = 0x677716C
EXEC_GET_OR_CREATE = 0x8130620
EXEC_GET = 0x81304E8
G_EXEC = B + 0xA4CFA40
INIT_1 = 0x812CF90
INIT_40 = 0x812CF88
INIT_MAIN = 0x812CF98
CHAN_CREATE = 0x812D034
CHAN_CONN = 0x812D0E4
CHAN_STATE = 0x812D1B4
CHAN_PEER = 0x812D1E4
TASK = 0x67FFCBC
METHOD = "/command_service.CommandService/CommandStream"
TARGET = "dns:///pes22-game.cs.konami.net:443/"

sent = []
net = []


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def u32(core, a):
    return struct.unpack("<I", bytes(core.uc.mem_read(a, 4)))[0]


def rb(core, a):
    return bytes(core.uc.mem_read(a, 1))[0]


def put_str(core, addr, text, name="s"):
    raw = text.encode()
    if len(raw) <= 22:
        core.uc.mem_write(addr, bytes([len(raw) << 1]) + raw +
                          b"\0" * (32 - 1 - len(raw)))
    else:
        p = core.alloc(len(raw) + 1, raw + b"\0", name=name + "_h")
        core.uc.mem_write(addr, b"\x01" + b"\0" * 7)
        core.write_u64(addr + 8, len(raw))
        core.write_u64(addr + 0x10, p)


def tap(core):
    def on_sendto(uc, c):
        try:
            buf = uc.reg_read(UC_ARM64_REG_X1)
            n = uc.reg_read(UC_ARM64_REG_X2)
            if 0 < n < 0x20000:
                b = core.safe_read(buf, n)
                if b:
                    sent.append(b)
                    print("[wire] sendto %d B: %r" % (len(b), b[:400]),
                          flush=True)
        except Exception:
            pass

    def on_sendmsg(uc, c):
        try:
            mh = uc.reg_read(UC_ARM64_REG_X1)
            raw = core.safe_read(mh, 48)
            iov = struct.unpack_from("<Q", raw, 16)[0]
            cnt = struct.unpack_from("<Q", raw, 24)[0]
            d = b""
            for i in range(min(cnt, 32)):
                e = core.safe_read(iov + i * 16, 16)
                base, ln = struct.unpack("<QQ", e)
                if ln:
                    d += core.safe_read(base, ln)
            if d:
                sent.append(d)
                print("[wire] sendmsg %d B: %r" % (len(d), d[:400]),
                      flush=True)
        except Exception:
            pass

    def on_conn(uc, c):
        try:
            net.append("connect")
            print("[net] connect(fd=%d)" % uc.reg_read(UC_ARM64_REG_X0),
                  flush=True)
        except Exception:
            pass

    for sym, cb in (("sendto_h", on_sendto), ("sendmsg_h", on_sendmsg),
                    ("write_h", on_sendto), ("connect_h", on_conn)):
        for a, n in core.stub_of.items():
            if n == sym:
                core.watch(a, cb, name=sym)
                break


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[g] core booted", flush=True)
    tap(core)

    # 1. creds
    core.call(CREDS, timeout_s=180, max_insns=500_000_000)
    print("[g] creds   = %#x" % u64(core, B + 0xA40B038), flush=True)

    # 2. THE MISSING PIECE: the executor
    print("[g] exec before = %#x" % u64(core, G_EXEC), flush=True)
    r = core.call(EXEC_GET_OR_CREATE, timeout_s=180, max_insns=600_000_000)
    print("[g] exec create -> err=%s x0=%#x" % (r["error"], r["x0"]),
          flush=True)
    print("[g] exec after  = %#x" % u64(core, G_EXEC), flush=True)
    r = core.call(EXEC_GET, timeout_s=60)
    print("[g] exec get    -> x0=%#x" % r["x0"], flush=True)

    # 3./4. a real channel
    holder = core.alloc(0xa00, b"\0" * 0xa00, name="holder")
    core.write_u8(holder + 0x8, 0)
    core.write_u8(holder + 0x9, 0)
    core.write_u8(holder + 0x51, 0)
    core.call(INIT_1, w0=holder, w1=1, timeout_s=30)
    core.call(INIT_40, w0=holder, w1=0x40, timeout_s=30)
    r = core.call(INIT_MAIN, w0=holder, timeout_s=180, max_insns=400_000_000)
    print("[g] channel init: err=%s x0=%#x  state=%d (+0x51=%d)"
          % (r["error"], r["x0"], rb(core, holder + 8),
             rb(core, holder + 0x51)), flush=True)
    r = core.call(CHAN_CREATE, w0=holder, timeout_s=180, max_insns=600_000_000)
    print("[g] CHANNEL CREATE -> x0=%#x  state=%d"
          % (r["x0"], rb(core, holder + 8)), flush=True)
    for label, fn in (("peer", CHAN_PEER), ("state", CHAN_STATE),
                      ("conn", CHAN_CONN)):
        try:
            rr = core.call(fn, w0=holder, timeout_s=60)
            print("[g] %-5s -> %#x" % (label, rr["x0"]), flush=True)
        except Exception as e:
            print("[g] %-5s EXC %s" % (label, type(e).__name__), flush=True)

    # 5. the game's own task, which starts the stream
    this = core.alloc(0x100, b"\0" * 0x100, name="task")
    put_str(core, this + 0x18, METHOD, "m")
    for i in range(20):
        before = len(sent)
        try:
            rr = core.call(TASK, w0=this, timeout_s=90, max_insns=300_000_000)
            print("[g] task %2d: x0=%#x state=%d case=%d handle=%#x writes=%d"
                  % (i, rr["x0"], u32(core, this + 8), u32(core, this + 0xC),
                     u64(core, this + 0x38), len(sent)), flush=True)
        except Exception as e:
            print("[g] task %2d EXC %s: %s" % (i, type(e).__name__,
                                               str(e)[:120]), flush=True)
            break
        if len(sent) > before:
            break

    total = sum(len(b) for b in sent)
    print("\n[g] RESULT: %d write(s), %d bytes, %d net events"
          % (len(sent), total, len(net)), flush=True)
    here = os.path.dirname(os.path.abspath(__file__))
    for i, b in enumerate(sent):
        open(os.path.join(here, "full_wire_%d.bin" % i), "wb").write(b)
        print("[g] wrote full_wire_%d.bin (%d B)" % (i, len(b)), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
