#!/usr/bin/env python3
"""LET THE GAME DO IT — step the game, pump its epoll, repeat.

State so far (all real game code under Unicorn):
    creds 0xa40b038 built; channel created by 0x812d034 (x0=0 = success)
    the task's connectivity probe 0x812d1b4 returns NULL -> state=4
which just means "not connected yet". gRPC here is epoll-driven
(no thd_*/grpc_init/timerfd in the PLT), so between task steps we must run
the game's engine. This:
  * steps the gRPC task 0x67ffcbc
  * calls the game's own channel poller / connectivity pump
  * watches the real socket for the ClientHello
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
TASK = 0x67FFCBC
CHAN_CONN = 0x812D0E4
CHAN_STATE = 0x812D1B4
CHAN_PEER = 0x812D1E4
METHOD = "/command_service.CommandService/CommandStream"

sent = []
net_calls = []


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def u32(core, a):
    return struct.unpack("<I", bytes(core.uc.mem_read(a, 4)))[0]


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


def tap_net(core):
    def on_sendto(uc, c):
        try:
            buf = uc.reg_read(UC_ARM64_REG_X1)
            n = uc.reg_read(UC_ARM62 if False else UC_ARM64_REG_X2)
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
                print("[wire] sendmsg %d B: %r" % (len(d), d[:400]), flush=True)
        except Exception:
            pass

    def on_connect(uc, c):
        try:
            net_calls.append(("connect", uc.reg_read(UC_ARM64_REG_X0)))
            print("[net] connect(fd=%d)" % net_calls[-1][1], flush=True)
        except Exception:
            pass

    def on_epoll(uc, c):
        try:
            net_calls.append(("epoll", uc.reg_read(UC_ARM64_REG_X0)))
        except Exception:
            pass

    pairs = (("sendto_h", on_sendto), ("sendmsg_h", on_sendmsg),
             ("write_h", on_sendto), ("connect_h", on_connect),
             ("epoll_create1_h", on_epoll), ("epoll_create_h", on_epoll))
    for sym, cb in pairs:
        for a, n in core.stub_of.items():
            if n == sym:
                core.watch(a, cb, name=sym)
                break
    print("[g] taps: " + ", ".join(s for s, _ in pairs), flush=True)


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
    tap_net(core)

    core.call(CREDS, timeout_s=180, max_insns=500_000_000)
    print("[g] creds = %#x" % u64(core, B + 0xA40B038), flush=True)

    this = core.alloc(0x100, b"\0" * 0x100, name="task")
    put_str(core, this + 0x18, METHOD, "m")

    holder = core.alloc(0x100, b"\0" * 0x100, name="holder")

    for i in range(30):
        before = len(sent)
        # the game's task step
        try:
            r = core.call(TASK, w0=this, timeout_s=90, max_insns=300_000_000)
            st = u32(core, this + 8)
            handle = u64(core, this + 0x38)
            print("[g] step %2d: x0=%#x state=%d case=%d handle=%#x writes=%d"
                  % (i, r["x0"], st, u32(core, this + 0xC), handle,
                     len(sent)), flush=True)
        except Exception as e:
            print("[g] step %2d EXC %s: %s" % (i, type(e).__name__,
                                              str(e)[:120]), flush=True)
            break
        if handle:
            print("[g] *** the game created the call handle %#x ***" % handle,
                  flush=True)
        if len(sent) > before:
            break
        if time.time() and i % 5 == 4:
            print("[g]   (net calls so far: %r)" % (net_calls[-6:],),
                  flush=True)

    total = sum(len(b) for b in sent)
    print("\n[g] RESULT: %d write(s), %d bytes; net calls: %d"
          % (len(sent), total, len(net_calls)), flush=True)
    here = os.path.dirname(os.path.abspath(__file__))
    for i, b in enumerate(sent):
        open(os.path.join(here, "run_wire_%d.bin" % i), "wb").write(b)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
