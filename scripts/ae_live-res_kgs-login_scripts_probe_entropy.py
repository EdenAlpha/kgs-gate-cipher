#!/usr/bin/env python3
"""Which import does the game's curl use for entropy?

libcurl seeds its RNG (and TLS) from the OS.  On Android that is normally
getrandom() or open/read on /dev/urandom.  We already implement fopen, but
the error says the seed never arrives -- so find the exact import it asks.
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
POST = 0x7D03C68
PUMP = 0x7D04350


def mk_str(core, text: bytes) -> int:
    buf = bytearray(32)
    buf[0] = len(text) << 1
    buf[1:1 + len(text)] = text
    return core.alloc(32, bytes(buf), name="str")


def rd_str(core, addr):
    b0 = bytes(core.uc.mem_read(addr, 1))[0]
    if b0 & 1:
        size = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 8, 8)))[0]
        ptr = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 0x10, 8)))[0]
        return bytes(core.uc.mem_read(ptr, size)).decode("utf-8", "replace")
    return bytes(core.uc.mem_read(addr + 1, b0 >> 1)).decode("utf-8", "replace")


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    B = core.base

    body = open("getserverenv_body.bin", "rb").read()
    out = core.alloc(64, b"\0" * 64, name="url")
    core.call(COMPOSER, w0=out, x1=mk_str(core, b"CMD_GET_SERVER_ENV"),
              x2=mk_str(core, b""), timeout_s=60, max_insns=200_000_000)
    url = rd_str(core, out)

    subreq = core.alloc(0x10200, b"\0" * 0x10200, name="subreq")
    core.write_u64(subreq, B + 0x98225A0)
    urlbuf = core.alloc(256, url.encode() + b"\0" * (256 - len(url)))
    bodybuf = core.alloc(len(body), body)
    ob, ol = core.alloc(8, b"\0" * 8), core.alloc(8, b"\0" * 8)
    exec_base = 0xA4000000000
    try:
        core.uc.mem_map(exec_base, 0x100000, 7)
        core.uc.mem_write(exec_base, struct.pack("<I", 0xD65F03C0))
    except Exception:
        pass

    snap = dict(getattr(core, "import_calls", {}))
    core.call(POST, w0=subreq, w1=urlbuf, x2=bodybuf, x3=len(body),
              w4=ob, w5=ol, x6=exec_base, x7=0,
              timeout_s=120, max_insns=200_000_000)
    r = core.call(PUMP, w0=subreq, timeout_s=120, max_insns=200_000_000)
    print(f"[probe] pump err={r['error']} x0={r['x0']:#x}", flush=True)

    diff = {}
    for k, v in getattr(core, "import_calls", {}).items():
        d = v - snap.get(k, 0)
        if d:
            diff[k] = d
    print("\n[probe] ALL imports during sender+pump:", flush=True)
    for k in sorted(diff):
        print(f"    {k:32s} +{diff[k]}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
