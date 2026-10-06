#!/usr/bin/env python3
"""Decide once and for all what 0x7a2fc64 returns to its caller.

Watches the exact call site 0x7a2f268 inside TaskLogin (registers before the
BL and right after it) and also runs the composer directly with x8 = a real
output buffer, so we can see whether clang used x8 as an sret pointer.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

COMPOSER = 0x7A2FC64
CALLSITE = 0x7A2F268          # bl 0x7a2fc64
AFTER = 0x7A2F26C


def rd_str(core, addr) -> str:
    try:
        b0 = bytes(core.uc.mem_read(addr, 1))[0]
        if b0 & 1:
            size = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 8, 8)))[0]
            ptr = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 0x10, 8)))[0]
            if size > 0x40000 or ptr == 0:
                return f"<long size={size} ptr={ptr:#x}>"
            return bytes(core.uc.mem_read(ptr, size)).decode("utf-8", "replace")
        return bytes(core.uc.mem_read(addr + 1, b0 >> 1)).decode("utf-8",
                                                                  "replace")
    except Exception as e:
        return f"<read {addr:#x} failed: {e}>"


def main() -> int:
    print("[x8] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[x8] booted", flush=True)

    from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_X0,
                                     UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                     UC_ARM64_REG_X8)

    def regs(uc):
        return (uc.reg_read(UC_ARM64_REG_SP), uc.reg_read(UC_ARM64_REG_X0),
                uc.reg_read(UC_ARM64_REG_X1), uc.reg_read(UC_ARM64_REG_X2),
                uc.reg_read(UC_ARM64_REG_X8))

    def before(uc, c):
        sp, x0, x1, x2, x8 = regs(uc)
        print(f"[x8] BEFORE bl: sp={sp:#x} x0={x0:#x} x1={x1:#x} "
              f"x2={x2:#x} x8={x8:#x}", flush=True)
        print(f"[x8]   str@x8 = {rd_str(c, x8)!r}", flush=True)
        print(f"[x8]   str@x0 = {rd_str(c, x0)!r}", flush=True)

    def after(uc, c):
        sp, x0, x1, x2, x8 = regs(uc)
        print(f"[x8] AFTER  bl: x0={x0:#x} x8={x8:#x}", flush=True)
        print(f"[x8]   str@x8 = {rd_str(c, x8)!r}", flush=True)
        print(f"[x8]   str@x0 = {rd_str(c, x0)!r}", flush=True)

    w1 = core.watch(CALLSITE - 4, before, name="before_bl")
    w2 = core.watch(AFTER, after, name="after_bl")

    out = core.alloc(64, b"\0" * 64, name="out")
    try:
        r = core.call_x8(COMPOSER, x8=out, timeout_s=60,
                         max_insns=200_000_000)
        print(f"[x8] direct call: err={r['error']} pc={r['pc']:#x} "
              f"x0={r['x0']:#x}", flush=True)
        print(f"[x8]   str@x8(out) = {rd_str(core, out)!r}", flush=True)
    except Exception as e:
        print(f"[x8] EXC {e}", flush=True)
    finally:
        core.unwatch(w1)
        core.unwatch(w2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
