#!/usr/bin/env python3
"""Call the game's stream-start path directly.

The task step is stuck at state=1 because the case at 0x67ffdf4 needs
this+0x10 (the request/command id) and a built request object. Read off the
disassembly of that case:

  0x67ffdf4:  ldr w1, [x19, #0x10]        ; the id
              add x8, sp, #0x28
              sub x0, x29, #0x30
              bl 0x677ae80               ; build the request message
              add x1, x21, #8
              add x0, sp, #0x58
              bl 0x6800150
              add x0, sp, #0x60
              add x1, sp, #0x58
              bl 0x68001bc
              add x0, sp, #0x58
              bl 0x6800238
              add x0, sp, #0x28
              bl 0x66f08dc
              ldr x0, [sp, #0x68]
              add x8, sp, #0x28
              bl 0x6800288
              ldr x1, [sp, #0x68]
              mov x0, x20
              bl 0x6777890               ; <<< START THE STREAM
              str x0, [x19, #0x38]        ; call handle
              strb w1, [x19, #0x40]       ; result flag

So 0x6777890 is the function that opens the RPC. Call the case's own pieces
with the real fields set: this+0x10 = the command id, this+0x18 = method.
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
CREDS = 0x677716C
INIT_1 = 0x812CF90
INIT_40 = 0x812CF88
INIT_MAIN = 0x812CF98
CHAN_CREATE = 0x812D034
RPC_START = 0x6777890          # opens the RPC  <-- the target
RPC_START_ALT = 0x6777AEC     # the other case's starter
BUILD_REQ = 0x677AE80
CHAN_PEER = 0x812D1E4
CHAN_STATE = 0x812D1B4
CHAN_CONN = 0x812D0E4
ENGINE_KICK = 0x7B095B8
ENGINE_2 = 0x7B095F4
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
            ip = ".".join(str(b) for b in bytes(uc.mem_read(sa + 4, 4)))
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
    ex = core.alloc(0x200, b"\0" * 0x200, name="exec")
    core.write_u64(G_EXEC, ex)

    holder = core.alloc(0xa00, b"\0" * 0xa00, name="holder")
    core.write_u8(holder + 0x8, 0)
    core.write_u8(holder + 0x9, 0)
    core.call(INIT_1, w0=holder, w1=1, timeout_s=30)
    core.call(INIT_40, w0=holder, w1=0x40, timeout_s=30)
    core.call(INIT_MAIN, w0=holder, timeout_s=180, max_insns=400_000_000)
    r = core.call(CHAN_CREATE, w0=holder, timeout_s=180, max_insns=600_000_000)
    print("[g] channel created=%#x state=%d" % (r["x0"], rb(core, holder + 8)),
          flush=True)

    # 0x6777890 takes (x20 = the channel holder, x1 = the call object)
    # x20 at the call site is the value 0x67ffcf0 loaded: the creds object.
    # Try the holder first, then the creds object.
    for label, arg0 in (("holder", holder), ("creds", u64(core, B + 0xA40B038)),
                        ("executor", ex)):
        callobj = core.alloc(0x100, b"\0" * 0x100, name="callobj_%s" % label)
        put_str(core, callobj + 0x18, METHOD, "m_%s" % label)
        try:
            r = core.call(RPC_START, w0=arg0, w1=callobj, timeout_s=180,
                          max_insns=600_000_000)
            call_handle = r["x0"]
            print("[g] RPC_START(%s) -> err=%s call=%#x | writes=%d net=%d"
                  % (label, r["error"], call_handle, len(sent), len(net)),
                  flush=True)
        except Exception as e:
            print("[g] RPC_START(%s) EXC %s: %s"
                  % (label, type(e).__name__, str(e)[:150]), flush=True)
            continue
        if not call_handle:
            continue

        # The call object exists. Now drive the transport so the channel
        # goes connecting -> ready and the game writes the request.
        t0 = time.time()
        for i in range(25):
            before = len(sent)
            for fn, args in ((CHAN_CONN, {"w0": holder}),
                             (CHAN_STATE, {"w0": holder}),
                             (CHAN_PEER, {"w0": holder}),
                             (ENGINE_KICK, {}), (ENGINE_2, {})):
                try:
                    core.call(fn, timeout_s=45, max_insns=200_000_000, **args)
                except Exception:
                    pass
            try:
                r = core.call(RPC_START, w0=arg0, w1=callobj, timeout_s=90,
                              max_insns=300_000_000)
                print("[g]   %2d chan=%d conn=%#x call=%#x writes=%d net=%d"
                      % (i, rb(core, holder + 8),
                         0, r["x0"], len(sent), len(net)), flush=True)
            except Exception as e:
                print("[g]   %2d EXC %s" % (i, type(e).__name__), flush=True)
                break
            if len(sent) > before:
                print("[g]   *** SOCKET WRITE ***", flush=True)
                break
            if time.time() - t0 > 200:
                print("[g]   time up", flush=True)
                break
        if sent:
            break

    total = sum(len(b) for b in sent)
    print("\n[g] RESULT: %d write(s), %d bytes, %d net events"
          % (len(sent), total, len(net)), flush=True)
    here = os.path.dirname(os.path.abspath(__file__))
    for i, b in enumerate(sent):
        open(os.path.join(here, "rpc_wire_%d.bin" % i), "wb").write(b)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
