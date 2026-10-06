#!/usr/bin/env python3
"""LET THE GAME DO IT — the missing piece found.

0x6777868 (the args builder that every gRPC entry point calls first) is a
one-liner returning *(0xa40b038) -- the game's gRPC credentials object.
That global is NULL because the online-session init that builds it was never
run, so every higher-level call bailed at once.

The writer is 0x677716c, a 72-byte "get or create":
    if (*(0xa40b038)) return it;
    p = operator new(0x178);
    0x67771b4(p);            <- ctor
    return p;
and 0x67771b4 -> 0x67772e4 builds the actual TLS credentials (it even resets
*(0xa40b038) = 0 first, then fills the certs).

So: call 0x677716c, verify *(0xa40b038) is non-null, then re-run the whole
task step 0x67ffcbc and watch the socket.
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

CREDS_GET_OR_CREATE = 0x677716C
TASK_STEP = 0x67FFCBC
B = 0x10000000000
G_CREDS = B + 0xA40B038
HOST = "pes22-game.cs.konami.net"
METHOD = "/command_service.CommandService/CommandStream"

sent = []


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
            d = b""
            for i in range(min(cnt, 32)):
                e = core.safe_read(iov + i * 16, 16)
                base, ln = struct.unpack("<QQ", e)
                if ln:
                    d += core.safe_read(base, ln)
            if d:
                sent.append(d)
                print("[wire] sendmsg %d B: %r" % (len(d), d[:500]), flush=True)
        except Exception:
            pass

    for sym, cb in (("sendto_h", on_sendto), ("sendmsg_h", on_sendmsg),
                    ("write_h", on_sendto)):
        for a, n in core.stub_of.items():
            if n == sym:
                core.watch(a, cb, name=sym)
                break
    print("[g] socket taps installed", flush=True)


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

    print("[g] creds before = %#x" % u64(core, G_CREDS), flush=True)
    try:
        r = core.call(CREDS_GET_OR_CREATE, timeout_s=180,
                      max_insns=500_000_000)
        print("[g] creds builder: err=%s x0=%#x" % (r["error"], r["x0"]),
              flush=True)
    except Exception as e:
        print("[g] creds builder EXC %s: %s" % (type(e).__name__, str(e)[:200]),
              flush=True)
    creds = u64(core, G_CREDS)
    print("[g] creds after  = %#x" % creds, flush=True)
    if not creds:
        print("[g] still NULL - the ctor did not publish it", flush=True)

    # now the real thing
    this = core.alloc(0x100, b"\0" * 0x100, name="task")
    core.write_u32(this + 0x08, 0)
    core.write_u32(this + 0x0c, 0)
    put_str(core, this + 0x18, METHOD, "method")
    print("\n[g] driving the game's task step with method %s" % METHOD,
          flush=True)

    t0 = time.time()
    for i in range(10):
        try:
            r = core.call(TASK_STEP, w0=this, timeout_s=120,
                          max_insns=400_000_000)
            print("[g]   step %d: err=%s x0=%#x state=%d case=%d handle=%#x"
                  % (i, r["error"], r["x0"], u32(core, this + 8),
                     u32(core, this + 0xC), u64(core, this + 0x38)),
                  flush=True)
            if r["error"]:
                break
        except Exception as e:
            print("[g]   step %d EXC %s: %s" % (i, type(e).__name__,
                                                str(e)[:150]), flush=True)
            break
        if sent:
            break
        if time.time() - t0 > 240:
            break

    total = sum(len(b) for b in sent)
    print("\n[g] RESULT: %d write(s), %d bytes" % (len(sent), total), flush=True)
    here = os.path.dirname(os.path.abspath(__file__))
    for i, b in enumerate(sent):
        open(os.path.join(here, "creds_wire_%d.bin" % i), "wb").write(b)
        print("[g] wrote creds_wire_%d.bin" % i, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
