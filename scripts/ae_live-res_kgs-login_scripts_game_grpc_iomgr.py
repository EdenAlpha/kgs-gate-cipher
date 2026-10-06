#!/usr/bin/env python3
"""LET THE GAME DO IT — run gRPC's OWN ev_posix poller.

Located by its own source-path string
  '.../grpc/src/core/lib/iomgr/ev_posix.cc' @ 0xabefbc
which is referenced from exactly one giant function:
  0x752c750 .. 0x753111c   (19,868 bytes)  <- gRPC's iomgr ev_posix
That is the code that takes the pending connect, calls the socket layer and
does the TLS handshake. The channel is already ALIVE (state=2); it just never
had its poller run.

So: build the channel, then call the poller in a loop, watching the socket.
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
G_EXEC = B + 0xA4CFA40
G_CREDS = B + 0xA40B038
CREDS = 0x677716C
INIT_1 = 0x812CF90
INIT_40 = 0x812CF88
INIT_MAIN = 0x812CF98
CHAN_CREATE = 0x812D034
CHAN_CONN = 0x812D0E4
CHAN_STATE = 0x812D1B4
CHAN_PEER = 0x812D1E4
ENGINE_KICK = 0x7B095B8
ENGINE_2 = 0x7B095F4
TASK = 0x67FFCBC
METHOD = "/command_service.CommandService/CommandStream"
# gRPC iomgr ev_posix (the poller), found via its own ev_posix.cc string
IOMGR_EV_POSIX = 0x752C750
IOMGR_HI = 0x753111C

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
                print("[wire] sendmsg %d B: %r" % (len(d), d[:400]), flush=True)
        except Exception:
            pass

    def on_conn(uc, c):
        try:
            fd = uc.reg_read(UC_ARM64_REG_X0)
            sa = uc.reg_read(UC_ARM64_REG_X1)
            ip = ".".join(str(b) for b in bytes(uc.mem_read(sa + 4, 4)))
            port = struct.unpack(">H", bytes(uc.mem_read(sa + 2, 2)))[0]
            net.append("connect")
            print("[net] connect fd=%d -> %s:%d" % (fd, ip, port), flush=True)
        except Exception:
            net.append("connect")
            print("[net] connect (raw)", flush=True)

    def on_epw(uc, c):
        try:
            fd = uc.reg_read(UC_ARM64_REG_X0)
            ms = uc.reg_read(UC_ARM64_REG_X3)
            net.append("epoll")
            if net.count("epoll") < 6:
                print("[net] epoll_wait fd=%d timeout=%d" % (fd, ms),
                      flush=True)
        except Exception:
            pass

    for sym, cb in (("sendto_h", on_sendto), ("sendmsg_h", on_sendmsg),
                    ("write_h", on_sendto), ("connect_h", on_conn),
                    ("epoll_wait_h", on_epw), ("poll_h", on_epw)):
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

    core.call(CREDS, timeout_s=180, max_insns=500_000_000)
    executor = core.alloc(0x200, b"\0" * 0x200, name="grpc_executor")
    core.write_u64(G_EXEC, executor)
    print("[g] creds=%#x executor=%#x" % (u64(core, G_CREDS),
                                          u64(core, G_EXEC)), flush=True)

    holder = core.alloc(0xa00, b"\0" * 0xa00, name="holder")
    core.write_u8(holder + 0x8, 0)
    core.write_u8(holder + 0x9, 0)
    core.write_u8(holder + 0x51, 0)
    core.call(INIT_1, w0=holder, w1=1, timeout_s=30)
    core.call(INIT_40, w0=holder, w1=0x40, timeout_s=30)
    core.call(INIT_MAIN, w0=holder, timeout_s=180, max_insns=400_000_000)
    r = core.call(CHAN_CREATE, w0=holder, timeout_s=180, max_insns=600_000_000)
    print("[g] channel created=%#x state=%d" % (r["x0"], rb(core, holder + 8)),
          flush=True)

    this = core.alloc(0x100, b"\0" * 0x100, name="task")
    put_str(core, this + 0x18, METHOD, "m")

    t0 = time.time()
    for i in range(30):
        before = len(sent)
        for label, fn, args in (
                ("kick", ENGINE_KICK, {}),
                ("e2", ENGINE_2, {}),
                ("iomgr_poll", IOMGR_EV_POSIX, {}),
                ("cstate", CHAN_STATE, {"w0": holder}),
                ("cconn", CHAN_CONN, {"w0": holder})):
            try:
                rr = core.call(fn, timeout_s=60, max_insns=300_000_000, **args)
                if rr["error"] and label == "iomgr_poll":
                    print("[g] %2d iomgr err=%s pc=%#x"
                          % (i, rr["error"], rr["pc"]), flush=True)
            except Exception as e:
                if label == "iomgr_poll":
                    print("[g] %2d iomgr EXC %s" % (i, type(e).__name__),
                          flush=True)
        try:
            rr = core.call(TASK, w0=this, timeout_s=90, max_insns=300_000_000)
            print("[g] %2d: task x0=%#x state=%d handle=%#x | chan=%d | "
                  "writes=%d net=%d"
                  % (i, rr["x0"], u32(core, this + 8),
                     u64(core, this + 0x38), rb(core, holder + 8),
                     len(sent), len(net)), flush=True)
        except Exception as e:
            print("[g] %2d task EXC %s" % (i, type(e).__name__), flush=True)
            break
        if len(sent) > before:
            print("[g] *** SOCKET WRITE ***", flush=True)
            break
        if time.time() - t0 > 420:
            print("[g] time up", flush=True)
            break

    total = sum(len(b) for b in sent)
    print("\n[g] RESULT: %d write(s), %d bytes, %d net events"
          % (len(sent), total, len(net)), flush=True)
    here = os.path.dirname(os.path.abspath(__file__))
    for i, b in enumerate(sent):
        open(os.path.join(here, "iomgr_wire_%d.bin" % i), "wb").write(b)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
