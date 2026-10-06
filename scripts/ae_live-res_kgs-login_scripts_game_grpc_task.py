#!/usr/bin/env python3
"""LET THE GAME DO IT — the whole thing in one call.

0x67ffcbc (940 bytes) is the game's complete gRPC task step: it builds the
channel args, allocates + inits the 0xa00 holder, creates the channel, reads
peer/state/connectivity, then -- in the case at +0x38 that our state selects
-- builds the request and starts the stream, and stores the call handle at
this+0x38 with a result flag at this+0x40.

Object layout, read off the disassembly:
    this+0x08   state (0 = not yet created)
    this+0x0c   sub-case index (jump table at 0xc6303c, 5 entries)
    this+0x10   w1 for the builder
    this+0x18   std::string flag byte; +0x19 = short data; +0x28 = long ptr
                 (the RPC method path: /command_service...CommandStream)
    this+0x30   the 0xa00 args holder
    this+0x38   the call handle the game creates  <-- we read this
    this+0x40   result flag
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

TASK_STEP = 0x67FFCBC        # the game's whole gRPC task step
CHAN_CONN = 0x812D0E4
HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"

sent = []


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def u32(core, a):
    return struct.unpack("<I", bytes(core.uc.mem_read(a, 4)))[0]


def put_str(core, addr, text, name="s"):
    """libc++ std::string at addr: flag byte at +0, data at +1, ptr at +0x10."""
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
                    print("[wire] sendto %d B: %r" % (len(b), b[:500]),
                          flush=True)
        except Exception:
            pass

    def on_sendmsg(uc, c):
        try:
            mh = uc.reg_read(UC_ARM64_REG_X1)
            raw = core.safe_read(mh, 48)
            iov = struct.unpack_from("<Q", raw, 16)[0]
            cnt = struct.unpack_from("<Q", raw, 24)[0]
            data = b""
            for i in range(min(cnt, 32)):
                e = core.safe_read(iov + i * 16, 16)
                base, ln = struct.unpack("<QQ", e)
                if ln:
                    data += core.safe_read(base, ln)
            if data:
                sent.append(data)
                print("[wire] sendmsg %d B: %r" % (len(data), data[:500]),
                      flush=True)
        except Exception:
            pass

    for sym, cb in (("sendto_h", on_sendto), ("sendmsg_h", on_sendmsg),
                    ("write_h", on_sendto)):
        for a, n in core.stub_of.items():
            if n == sym:
                core.watch(a, cb, name=sym)
                print("[g] tap %s @ %#x" % (sym, a), flush=True)
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

    this = core.alloc(0x100, b"\0" * 0x100, name="task")
    core.write_u32(this + 0x08, 0)          # state: not created
    core.write_u32(this + 0x0c, 0)          # sub-case 0
    core.write_u64(this + 0x10, 0)
    put_str(core, this + 0x18, METHOD, "method")
    print("[g] task method = %r" % METHOD, flush=True)

    # the game's function takes the target string from this+0x18 too in some
    # cases; also give it the channel target via +0x28 long-form slot
    t_raw = ("dns:///%s:443/" % HOST).encode()
    t_p = core.alloc(len(t_raw) + 1, t_raw + b"\0", name="tgt_h")
    put_str(core, this + 0x18, t_raw.decode(), "tgt")
    print("[g] task target = %s" % t_raw.decode(), flush=True)

    t0 = time.time()
    for i in range(8):
        print("[g] --- task step %d ---" % i, flush=True)
        try:
            r = core.call(TASK_STEP, w0=this, timeout_s=120,
                          max_insns=400_000_000)
            print("[g]   err=%s pc=%#x x0=%#x  state=%d case=%d handle=%#x "
                  "flag=%d" % (r["error"], r["pc"], r["x0"],
                               u32(core, this + 8), u32(core, this + 0xC),
                               u64(core, this + 0x38),
                               u32(core, this + 0x40)), flush=True)
            if r["error"]:
                break
        except Exception as e:
            print("[g]   EXC %s: %s" % (type(e).__name__, str(e)[:150]),
                  flush=True)
            break
        if sent:
            break
        if time.time() - t0 > 300:
            print("[g]   time up", flush=True)
            break

    total = sum(len(b) for b in sent)
    print("\n[g] RESULT: %d write(s), %d bytes" % (len(sent), total), flush=True)
    here = os.path.dirname(os.path.abspath(__file__))
    for i, b in enumerate(sent):
        open(os.path.join(here, "task_wire_%d.bin" % i), "wb").write(b)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
