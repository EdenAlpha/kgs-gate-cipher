#!/usr/bin/env python3
"""LET THE GAME DO IT — with the ALooper helper in place.

Everything the game's own code needed, in its own order:
  1. ALooper installed (peerlink/alooper.py) -- the 7 libandroid imports
  2. creds      0x677716c
  3. executor   0xa4cfa40 (zeroed object -> the game's live branch)
  4. channel    0x812cf90 / 0x812cf88 / 0x812cf98 / 0x812d034
  5. RPC start  0x6777890  (returns the live call handle)
  6. the game drives ALooper_pollAll itself, through our real select()

We tap sendto/sendmsg/connect so any byte the game emits shows up.
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
RPC_START = 0x6777890
METHOD = "/command_service.CommandService/CommandStream"

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
            ip = ".".join(str(x) for x in bytes(uc.mem_read(sa + 4, 4)))
            port = struct.unpack(">H", bytes(uc.mem_read(sa + 2, 2)))[0]
            net.append("connect")
            print("[net] connect fd=%d -> %s:%d" % (fd, ip, port), flush=True)
        except Exception:
            net.append("connect")
            print("[net] connect (raw)", flush=True)

    for sym, cb in (("sendto_h", on_sendto), ("sendmsg_h", on_sendmsg),
                    ("write_h", on_sendto), ("connect_h", on_conn)):
        for a, n in core.stub_of.items():
            if n == sym:
                core.watch(a, cb, name=sym)
                break


def main() -> int:
    core = OnlineCore(verbose=True)
    core.install_netsplice()
    core.install_alooper()
    print("[g] ALooper wired: %s" % getattr(core, "_al_wired", None), flush=True)
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[g] core booted", flush=True)
    tap(core)

    core.call(CREDS, timeout_s=180, max_insns=500_000_000)
    ex = core.alloc(0x200, b"\0" * 0x200, name="exec")
    core.write_u64(G_EXEC, ex)
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

    callobj = core.alloc(0x200, b"\0" * 0x200, name="callobj")
    put_str(core, callobj + 0x18, METHOD, "m")
    r = core.call(RPC_START, w0=holder, w1=callobj, timeout_s=180,
                  max_insns=600_000_000)
    print("[g] RPC call handle=%#x" % r["x0"], flush=True)

    t0 = time.time()
    for i in range(40):
        before = len(sent)
        for label, fn, args in (("conn", CHAN_CONN, {"w0": holder}),
                                ("cstate", CHAN_STATE, {"w0": holder}),
                                ("cpeer", CHAN_PEER, {"w0": holder}),
                                ("kick", ENGINE_KICK, {}),
                                ("e2", ENGINE_2, {}),
                                ("task", TASK, {"w0": None})):
            if label == "task":
                continue
            try:
                core.call(fn, timeout_s=60, max_insns=300_000_000, **args)
            except Exception:
                pass
        print("[g] %2d: chan=%d polls=%d fired=%d fds=%d | writes=%d net=%d"
              % (i, rb(core, holder + 8), core._al_polls, core._al_fired,
                 len(core._al_fds) + len(core._al_cb_fds), len(sent),
                 len(net)), flush=True)
        for line in core._log[-14:]:
            if "ALooper" in line or "connect" in line:
                print("     | %s" % line, flush=True)
        if len(sent) > before:
            print("[g] *** SOCKET WRITE ***", flush=True)
            break
        if net:
            print("[g] *** NETWORK EVENT ***", flush=True)
        if time.time() - t0 > 300:
            print("[g] time up", flush=True)
            break

    total = sum(len(b) for b in sent)
    print("\n[g] RESULT: %d write(s), %d bytes, %d net, alopolls=%d afired=%d"
          % (len(sent), total, len(net), core._al_polls, core._al_fired),
          flush=True)
    here = os.path.dirname(os.path.abspath(__file__))
    for i, b in enumerate(sent):
        open(os.path.join(here, "alooper_wire_%d.bin" % i), "wb").write(b)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
