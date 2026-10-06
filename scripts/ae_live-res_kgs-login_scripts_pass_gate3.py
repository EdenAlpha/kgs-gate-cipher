#!/usr/bin/env python3
"""State 9 creates the task; state 10 runs it but needs task->[0xf8] bit 0.
Set that byte and drive state 10 to the HTTP path."""
from __future__ import annotations

import os
import struct
import sys
import time

from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1   # noqa: E402

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

SM = 0x7DC7164
CREATE = 0x7CDA280
CURL_SETOPT = 0x6886498
SESS = 0xA4AB6A8
CMD_TBL = 0xA4CFF18


def main():
    print("[t2] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(CREATE, timeout_s=60)
    B = core.base

    obj = core.alloc(0x400, b"\0" * 0x400, name="cmdobj")
    stub = core.alloc(0x40, b"\0" * 0x40, name="stub")
    core.uc.mem_write(stub, struct.pack("<II", 0x52800002, 0xD65F03C0))
    core.write_u64(obj + 0x118, stub)
    core.write_u64(B + CMD_TBL + 8, obj)

    urls = []

    def on_setopt(uc, c):
        o = uc.reg_read(UC_ARM64_REG_X1)
        v = uc.reg_read(UC_ARM64_REG_X2)
        if o == 10002:
            try:
                raw = bytes(uc.mem_read(v, 512))
            except Exception:
                raw = b""
            z = raw.find(b"\0")
            urls.append(raw[:z if z >= 0 else 512])
            print(f"    >>> URL = {urls[-1]!r}", flush=True)

    core.watch(CURL_SETOPT, on_setopt, name="curl")

    ctx = core.alloc(0x1000, b"\0" * 0x1000, name="ctx")
    core.write_u8(ctx + 0x278, 1)
    core.write_u8(ctx + 0x280, 0)

    # state 9 -> creates the task
    core.write_u32(ctx + 0x2a0, 9)
    r = core.call(SM, x0=ctx, timeout_s=40, max_insns=15_000_000)
    task = core.safe_read_u64(ctx + 0x288)
    print(f"  state 9 -> err={r['error']} task={task:#x}", flush=True)

    if not task:
        print("  no task created")
        return 1

    # set the task's state byte and run state 10
    core.write_u8(task + 0xf8, 1)
    print(f"  set task->[0xf8] = 1", flush=True)

    core.write_u32(ctx + 0x2a0, 10)
    r = core.call(SM, x0=ctx, timeout_s=40, max_insns=15_000_000)
    print(f"  state 10 -> err={r['error']} x0={r['x0']:#x}", flush=True)

    print(f"\ncurl URLs: {len(urls)}")
    for u in urls[:6]:
        print(f"    {u!r}")

    print("\nlog (last 12):")
    for line in getattr(core, "_log", [])[-12:]:
        print("   ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
