#!/usr/bin/env python3
"""Micro-probe: WHY do the low-address ctors fault?

For 3 failing targets print: readable? first bytes? fault pc? fault lr?
Distinguishes unmapped-page vs bad-LR-return vs bad-call-inside.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from unicorn.arm64_const import UC_ARM64_REG_LR, UC_ARM64_REG_PC  # noqa: E402

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

CREATE = 0x7CDA280
TARGETS = [0x8B34484, 0x28294A0, 0x767F6E4]   # 2 failing + 1 known-good


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(CREATE, timeout_s=60)
    print("[probe] booted base=%#x" % core.base, flush=True)
    for t in TARGETS:
        addr = core.base + t
        try:
            head = bytes(core.uc.mem_read(addr, 16)).hex()
        except Exception as e:
            head = "UNREADABLE %s" % e
        try:
            r = core.call(addr, timeout_s=20, max_insns=5_000_000)
            err, pc = r["error"], r["pc"]
        except Exception as e:
            err, pc = "%s" % e, -1
        try:
            lr = core.uc.reg_read(UC_ARM64_REG_LR)
        except Exception:
            lr = -1
        print("  %#x readable16=%s err=%s pc=%s lr=%#x"
              % (t, head, err, hex(pc) if isinstance(pc, int) and pc >= 0
                 else pc, lr & 0xFFFFFFFFFFFFFFFF), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
