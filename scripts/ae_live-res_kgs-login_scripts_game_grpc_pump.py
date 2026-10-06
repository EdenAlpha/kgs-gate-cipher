#!/usr/bin/env python3
"""LET THE GAME DO IT — step 5: full run, then PUMP the engine.

Key discovery that unblocks this: this build of gRPC is THREADLESS. Its PLT
has no pthread_create path for gRPC, no thd_*, no timerfd, no grpc_init --
it has epoll (which the harness already wires to real sockets). So the I/O
engine is driven by polling, exactly like curl_multi_poll. That means:
  1. build args      0x6777868
  2. alloc/init      0x812cda0 / 0x812cf90 / 0x812cf88 / 0x812cf98
  3. create channel  0x812d034
  4. connectivity    0x812d1e4 (peer) 0x812d1b4 (state) 0x812d0e4
  5. poll the engine until the handshake starts and bytes hit the wire
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

BUILD_ARGS = 0x6777868
NEW_A00 = 0x812CDA0
INIT_1 = 0x812CF90
INIT_40 = 0x812CF88
INIT_X = 0x812CF98
CHAN_CREATE = 0x812D034
CHAN_PEER = 0x812D1E4
CHAN_STATE = 0x812D1B4
CHAN_CONN = 0x812D0E4

HOST = "pes22-game.cs.konami.net"
TARGET = "dns:///%s:443/" % HOST

sent = []


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def mk_target_str(core, text):
    raw = text.encode()
    p = core.alloc(len(raw) + 1, raw + b"\0", name="target_heap")
    s = core.alloc(32, b"\x01" + b"\0" * 7, name="target_str")
    core.write_u64(s + 8, len(raw))
    core.write_u64(s + 0x10, p)
    return s


def tap_sockets(core):
    """Log every byte the game hands to the socket layer.

    The game's TLS/gRPC output leaves through the sendto / sendmsg PLT
    stubs (the netsplice handlers), so tap those -- not an internal helper.
    """
    from unicorn.arm64_const import UC_ARM64_REG_X0

    def on_sendto(uc, c):
        try:
            buf = uc.reg_read(UC_ARM64_REG_X1)
            n = uc.reg_read(UC_ARM64_REG_X2)
            if 0 < n < 0x20000:
                blob = bytes(core.safe_read(buf, n))
                if blob:
                    sent.append(blob)
                    print("[wire] sendto %d bytes: %r" % (len(blob),
                                                           blob[:500]),
                          flush=True)
        except Exception:
            pass

    def on_sendmsg(uc, c):
        try:
            mh = uc.reg_read(UC_ARM64_REG_X1)
            raw = core.safe_read(mh, 48)
            iov_ptr = struct.unpack_from("<Q", raw, 16)[0]
            iov_cnt = struct.unpack_from("<Q", raw, 24)[0]
            data = b""
            for i in range(min(iov_cnt, 32)):
                ent = core.safe_read(iov_ptr + i * 16, 16)
                base, ln = struct.unpack("<QQ", ent)
                if ln:
                    data += core.safe_read(base, ln)
            if data:
                sent.append(data)
                print("[wire] sendmsg %d bytes: %r" % (len(data), data[:500]),
                      flush=True)
        except Exception:
            pass

    for name, cb in (("sendto", on_sendto), ("sendmsg", on_sendmsg),
                     ("write", on_sendto)):
        addr = core.stub_of and None
        try:
            sym = "%s_h" % name
            hits = [a for a, n in core.stub_of.items() if n == sym]
            if hits:
                core.watch(hits[0], cb, name=sym)
                print("[g] tapped %s at %#x" % (sym, hits[0]), flush=True)
        except Exception as e:
            print("[g] tap %s failed: %s" % (name, e), flush=True)


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

    sstr = mk_target_str(core, TARGET)
    args_ctx = core.alloc(0x2000, b"\0" * 0x2000, name="args_ctx")
    core.call(BUILD_ARGS, w0=args_ctx, w1=sstr, timeout_s=120,
              max_insns=300_000_000)

    holder = core.alloc(0xa00, b"\0" * 0xa00, name="args_holder")
    core.call(INIT_1, w0=holder, w1=1, timeout_s=60)
    core.call(INIT_40, w0=holder, w1=0x40, timeout_s=60)
    core.call(INIT_X, w0=holder, timeout_s=60)
    print("[g] args holder ready = %#x" % holder, flush=True)

    tap_sockets(core)

    r = core.call(CHAN_CREATE, w0=holder, timeout_s=300, max_insns=900_000_000)
    print("[g] channel create: err=%s x0=%#x" % (r["error"], r["x0"]),
          flush=True)
    if r["error"]:
        return 1

    for label, fn in (("peer", CHAN_PEER), ("state", CHAN_STATE),
                      ("connectivity", CHAN_CONN)):
        try:
            r = core.call(fn, w0=holder, timeout_s=60, max_insns=100_000_000)
            print("[g] %-13s -> x0=%#x" % (label, r["x0"]), flush=True)
        except Exception as e:
            print("[g] %-13s EXC %s" % (label, type(e).__name__), flush=True)

    print("[g] --- engine: polling for the handshake ---", flush=True)
    # The channel is lazy: connectivity state changes once the poller runs.
    # Re-enter the gate (0x7dc2578) which drives connect + returns state.
    CHAN_GATE = 0x7DC2578
    gctx = core.alloc(0x400, b"\0" * 0x400, name="gate_ctx")
    t0 = time.time()
    for i in range(12):
        try:
            r = core.call(CHAN_GATE, w0=gctx, timeout_s=45,
                          max_insns=200_000_000)
            print("[g]   poll %2d: err=%s x0=%#x  bytes=%d"
                  % (i, r["error"], r["x0"], sum(len(b) for b in sent)),
                  flush=True)
        except Exception as e:
            print("[g]   poll %2d: EXC %s: %s"
                  % (i, type(e).__name__, str(e)[:90]), flush=True)
        if sent:
            break
        if time.time() - t0 > 180:
            print("[g]   giving up (no traffic)", flush=True)
            break

    total = sum(len(b) for b in sent)
    print("\n[g] RESULT: %d write(s), %d bytes on the wire" % (len(sent), total),
          flush=True)
    here = os.path.dirname(os.path.abspath(__file__))
    for i, b in enumerate(sent):
        open(os.path.join(here, "chan_wire_%d.bin" % i), "wb").write(b)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
