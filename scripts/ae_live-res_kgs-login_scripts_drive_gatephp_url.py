#!/usr/bin/env python3
"""Run the game's own gate.php URL composer 0x7a2fc64 under a code hook and
print the string it builds, plus what it leaves in x0/x8 on return.

The function takes no usable input; every byte comes from the endpoint config
inside libUE4.so, so this is the photocopier answer to "where do commands go".
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
HOOK_AT = 0x7A2FE48          # just before the frame is torn down


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
    print("[gate] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[gate] booted", flush=True)

    def hook(uc, c):
        try:
            from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_X0,
                                             UC_ARM64_REG_X8, UC_ARM64_REG_LR)
            sp = uc.reg_read(UC_ARM64_REG_SP)
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x8 = uc.reg_read(UC_ARM64_REG_X8)
            lr = uc.reg_read(UC_ARM64_REG_LR)
            print(f"[gate] --- reached {HOOK_AT:#x}", flush=True)
            print(f"[gate]   sp={sp:#x}  lr={lr:#x}", flush=True)
            print(f"[gate]   str@sp+8  = {rd_str(c, sp + 8)!r}", flush=True)
            print(f"[gate]   x0={x0:#x}  x8={x8:#x}", flush=True)
            print(f"[gate]   str@x8    = {rd_str(c, x8)!r}", flush=True)
            print(f"[gate]   str@x0    = {rd_str(c, x0)!r}", flush=True)
        except Exception as e:
            print(f"[gate] hook read failed: {e}", flush=True)

    h = core.watch(HOOK_AT, hook, name="composer_return")
    out = core.alloc(64, b"\0" * 64, name="out")
    try:
        r = core.call_x8(COMPOSER, x8=out, timeout_s=60,
                         max_insns=200_000_000)
    except Exception as e:
        print(f"[gate] EXC {e}", flush=True)
        r = {"error": str(e), "pc": 0}
    finally:
        core.unwatch(h)

    print(f"[gate] result err={r.get('error')} pc={r.get('pc'):#x} "
          f"x0={r.get('x0', 0):#x}", flush=True)
    print(f"[gate] out buffer = {rd_str(core, out)!r}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
