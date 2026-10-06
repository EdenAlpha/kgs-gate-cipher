#!/usr/bin/env python3
"""LET THE GAME DO IT.

Run the game's OWN gRPC client (libUE4.so 0x7b0f690, the 2920-byte function
that stores the client vtable 0x9819b70 and runs the Def_ config loader
0x7b101f8) inside the Unicorn harness, with real sockets spliced in. The
game's BoringSSL, its gRPC core, its HTTP/2 and its MessagePack writer all
run for real, so whatever reaches the wire is the game's own output -- not
ours.

Then we read the exact bytes the game wrote to the socket.

Entry point decoded from the disassembly at 0x7b0f690:
    x0 = the gRPC client object (`this`)   [+0x08 owner, +0x10 config]
    x1 = a state struct                     [+0x68 state (0..5 jump table),
                                               +0x6c, +0x70/71/0x80 a string,
                                               +0x180 flag]
    state 0 (the "connect" case) does:
        bl 0x7b101f8            load Def_Online_gRPC_* into this+0x308/320/338
        this->vtable[5] (0x28)  open the channel with that config
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

GRPC_CLIENT_CTOR = 0x7B0F690      # the function that builds the client
CONFIG_LOADER = 0x7B101F8         # Def_Online_gRPC_* -> this+0x308/0x320/0x338


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def u16(core, a):
    return struct.unpack("<H", bytes(core.uc.mem_read(a, 2)))[0]


def i32(core, a):
    return struct.unpack("<i", bytes(core.uc.mem_read(a, 4)))[0]


def rd_str(core, addr):
    """libc++ std::string (short: byte0 = len<<1; long: bit0 set)."""
    try:
        b0 = bytes(core.uc.mem_read(addr, 1))[0]
        if b0 & 1:
            n = u64(core, addr + 8)
            p = u64(core, addr + 0x10)
            if n > 0x4000 or p == 0:
                return "<long n=%d>" % n
            return bytes(core.uc.mem_read(p, n)).decode("utf-8", "replace")
        return bytes(core.uc.mem_read(addr + 1, b0 >> 1)).decode("utf-8",
                                                                 "replace")
    except Exception as e:
        return "<err %s>" % e


def mk_str(core, text: bytes, name="str"):
    """libc++ std::string in the game's memory."""
    if len(text) <= 22:
        buf = bytearray(32)
        buf[0] = len(text) << 1
        buf[1:1 + len(text)] = text
        return core.alloc(32, bytes(buf), name=name)
    ptr = core.alloc(len(text) + 1, text + b"\0", name=name + "_heap")
    buf = bytearray(32)
    buf[0] = 1
    struct.pack_into("<Q", buf, 8, len(text))
    struct.pack_into("<Q", buf, 0x10, ptr)
    return core.alloc(32, bytes(buf), name=name)


def main() -> int:
    print("[game] booting the game's own core ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[game] core booted (base %#x)\n" % core.base, flush=True)

    # --- the gRPC client object ------------------------------------------
    # +0x00 vtable (game sets it), +0x08 owner, +0x10 config ptr,
    # +0x308/+0x320/+0x338 host/path/port written by the config loader
    this = core.alloc(0x400, b"\0" * 0x400, name="grpc_client")
    owner = core.alloc(0x200, b"\0" * 0x200, name="grpc_owner")

    # --- the state struct (x1) -------------------------------------------
    # +0x68 = state index into the 6-entry jump table; state 0 = "connect"
    state = core.alloc(0x200, b"\0" * 0x200, name="grpc_state")
    core.write_u64(state + 0x68, 0)          # state = 0 -> the connect case
    core.write_u64(state + 0x6c, 0)
    # +0x70/0x71/0x80 = a std::string (short form at +0x71)
    s = mk_str(core, b"/command_service.CommandService/CommandStream",
               "method_path")
    core.uc.mem_write(state + 0x71, bytes(core.uc.mem_read(s, 32)))

    # record the TLS bytes the game itself writes
    sent = []

    def on_send(uc, c):
        try:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            n = x1 if x2 == 0 else min(x1, 0x2000)
            if n > 0 and n < 0x4000:
                blob = bytes(uc.mem_read(x1, min(n, 0x2000)))
                sent.append(blob)
                print("[game] >>> game wrote %d bytes to a socket:\n%r"
                      % (len(blob), blob[:400]), flush=True)
        except Exception:
            pass

    print("[game] calling the game's gRPC client 0x7b0f690 "
          "(state=0/connect) ...", flush=True)
    try:
        r = core.call(GRPC_CLIENT_CTOR, w0=this, w1=state, timeout_s=180,
                      max_insns=400_000_000)
        print("[game] returned err=%s pc=%#x x0=%#x"
              % (r["error"], r["pc"], r["x0"]), flush=True)
    except Exception as e:
        print("[game] EXC %s: %s" % (type(e).__name__, str(e)[:200]),
              flush=True)

    print("\n[game] --- what the game's config loader produced ---",
          flush=True)
    print("  this+0x308 host = %r" % rd_str(core, this + 0x308), flush=True)
    print("  this+0x320 path = %r" % rd_str(core, this + 0x320), flush=True)
    print("  this+0x338 port = %d" % u16(core, this + 0x338), flush=True)
    print("  this+0x000 vtable = %#x" % u64(core, this), flush=True)
    print("  this+0x008 owner  = %#x" % u64(core, this + 8), flush=True)
    print("  this+0x010 config = %#x" % u64(core, this + 0x10), flush=True)
    print("  state+0x68 = %d" % u64(core, state + 0x68), flush=True)

    print("\n[game] bytes the game put on the wire: %d write(s), %d bytes"
          % (len(sent), sum(len(b) for b in sent)), flush=True)
    for i, b in enumerate(sent):
        print("  [%d] %d bytes: %r" % (i, len(b), b[:200]), flush=True)
        open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "game_wire_%d.bin" % i), "wb").write(b)
    print("[game] wrote game_wire_*.bin", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
