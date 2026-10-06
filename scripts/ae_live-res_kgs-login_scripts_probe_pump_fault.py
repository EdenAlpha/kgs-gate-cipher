#!/usr/bin/env python3
"""Catch the jump-to-NULL during curl_multi_perform and report who made it.

When AArch64 executes `blr x8` with x8 == 0, the CPU fetches address 0 and
LR still holds the instruction *after* the branch -- i.e. the exact call site
that invoked a NULL function pointer.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn.arm64_const import (                      # noqa: E402
    UC_ARM64_REG_LR, UC_ARM64_REG_PC, UC_ARM64_REG_X8,
)

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
    print(f"[probe] URL = {url}", flush=True)

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

    r = core.call(POST, w0=subreq, w1=urlbuf, x2=bodybuf, x3=len(body),
                  w4=ob, w5=ol, x6=exec_base, x7=0,
                  timeout_s=120, max_insns=200_000_000)
    print(f"[probe] sender err={r['error']}", flush=True)

    r = core.call(PUMP, w0=subreq, timeout_s=120, max_insns=200_000_000)
    lr = core.uc.reg_read(UC_ARM64_REG_LR)
    pc = core.uc.reg_read(UC_ARM64_REG_PC)
    x8 = core.uc.reg_read(UC_ARM64_REG_X8)
    print(f"\n[probe] pump err={r['error']}", flush=True)
    print(f"[probe] fault pc = {pc:#x}   LR = {lr:#x}   x8 = {x8:#x}",
          flush=True)
    print(f"[probe] LR file-va = {lr - B:#x}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
