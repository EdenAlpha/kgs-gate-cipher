#!/usr/bin/env python3
"""Run the game's OWN gate-URL composer and print what it produces.

    0x7b099d0(out_string, a, b)

It reads the endpoint config itself (get_endpoint_config) and appends
"://", the host, the title path, then "gate/gate_" + a + ".php".

We supply only two ordinary strings; every other byte comes from the binary.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

COMPOSER = 0x7B099D0


def mk_str(core, text: bytes) -> int:
    """Lay out a libc++ std::string in guest memory and return its address."""
    buf = bytearray(32)
    if len(text) <= 22:                       # short form
        buf[0] = len(text) << 1
        buf[1:1 + len(text)] = text
    else:                                     # long form
        buf[0] = 1
        struct.pack_into("<Q", buf, 8, len(text))
        ptr = core.alloc(len(text) + 1, text + b"\0", name="cstr")
        struct.pack_into("<Q", buf, 0x10, ptr)
    return core.alloc(32, bytes(buf), name="str")


def rd_str(core, addr) -> str:
    b0 = bytes(core.uc.mem_read(addr, 1))[0]
    if b0 & 1:
        size = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 8, 8)))[0]
        ptr = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 0x10, 8)))[0]
        if size > 0x4000 or ptr == 0:
            return f"<long size={size} ptr={ptr:#x}>"
        return bytes(core.uc.mem_read(ptr, size)).decode("utf-8", "replace")
    return bytes(core.uc.mem_read(addr + 1, b0 >> 1)).decode("utf-8", "replace")


def main():
    print("[url] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[url] booted", flush=True)

    combos = [
        (b"ServerEnv", b""),
        (b"", b""),
        (b"CmdGetServerEnv", b""),
        (b"ServerEnv", b"gate"),
        (b"CmdGetServerEnv", b"gate"),
        (b"login", b""),
    ]
    for a, b in combos:
        out = core.alloc(64, b"\0" * 64, name="out")
        sa = mk_str(core, a)
        sb = mk_str(core, b)
        try:
            r = core.call(COMPOSER, w0=out, x1=sa, x2=sb,
                          timeout_s=60, max_insns=200_000_000)
        except Exception as e:
            print(f"[url] a={a!r} b={b!r} -> EXC {e}", flush=True)
            continue
        if r["error"]:
            print(f"[url] a={a!r} b={b!r} -> err={r['error']} "
                  f"pc={r['pc']:#x}", flush=True)
            continue
        try:
            s = rd_str(core, out)
        except Exception as e:
            s = f"<read fail {e}>"
        print(f"[url] a={a!r} b={b!r}\n       -> {s}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
