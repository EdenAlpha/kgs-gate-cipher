#!/usr/bin/env python3
"""Log every path the game's curl opens and every env var it asks for."""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn.arm64_const import (                      # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1,
)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402


def mk_str(core, t: bytes) -> int:
    buf = bytearray(32)
    buf[0] = len(t) << 1
    buf[1:1 + len(t)] = t
    return core.alloc(32, bytes(buf), name="s")


def rd_str(core, a):
    b0 = bytes(core.uc.mem_read(a, 1))[0]
    if b0 & 1:
        n = struct.unpack("<Q", bytes(core.uc.mem_read(a + 8, 8)))[0]
        p = struct.unpack("<Q", bytes(core.uc.mem_read(a + 0x10, 8)))[0]
        return bytes(core.uc.mem_read(p, n)).decode("utf-8", "replace")
    return bytes(core.uc.mem_read(a + 1, b0 >> 1)).decode("utf-8", "replace")


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

    seen = []
    real_cstr = core._read_cstr

    def log_cstr(uc, addr, limit=4096):
        s = real_cstr(uc, addr, limit)
        seen.append(s)
        return s

    core._read_cstr = log_cstr

    body = open("getserverenv_body.bin", "rb").read()
    out = core.alloc(64, b"\0" * 64, name="url")
    core.call(0x7B099D0, w0=out, x1=mk_str(core, b"CMD_GET_SERVER_ENV"),
              x2=mk_str(core, b""), timeout_s=60, max_insns=200_000_000)
    url = rd_str(core, out)

    subreq = core.alloc(0x10200, b"\0" * 0x10200, name="sr")
    core.write_u64(subreq, B + 0x98225A0)
    urlbuf = core.alloc(256, url.encode() + b"\0" * (256 - len(url)))
    bb = core.alloc(len(body), body)
    ob, ol = core.alloc(8, b"\0" * 8), core.alloc(8, b"\0" * 8)
    ex = 0xA4000000000
    try:
        core.uc.mem_map(ex, 0x100000, 7)
        core.uc.mem_write(ex, struct.pack("<I", 0xD65F03C0))
    except Exception:
        pass

    core.call(0x7D03C68, w0=subreq, w1=urlbuf, x2=bb, x3=len(body),
              w4=ob, w5=ol, x6=ex, x7=0,
              timeout_s=120, max_insns=200_000_000)
    core.call(0x7D04350, w0=subreq, timeout_s=120, max_insns=200_000_000)

    print("=== every C-string argument passed to a libc import ===")
    for s in seen:
        if s:
            print(f"    {s!r}", flush=True)

    print("\n=== unhandled imports (still stubbed to 0) ===")
    for line in getattr(core, "_log", []):
        if "unhandled import" in line:
            print("   ", line.strip(), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
