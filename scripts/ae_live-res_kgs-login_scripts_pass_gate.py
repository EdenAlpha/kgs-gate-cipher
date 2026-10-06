#!/usr/bin/env python3
"""State 9 gates on array[1] (at 0xa4cff20) being non-NULL and
array[1]->[0x118] being non-NULL.  Fabricate that entry and drive the SM
from state 9 to see if it then builds and runs the task.
"""
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
    print("[gate] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(CREATE, timeout_s=60)
    B = core.base
    print(f"[gate] session = "
          f"{struct.unpack('<Q', bytes(core.uc.mem_read(B+SESS,8)))[0]:#x}",
          flush=True)

    # ---- fabricate array[1] --------------------------------------------
    obj = core.alloc(0x400, b"\0" * 0x400, name="cmdobj")
    stub = core.alloc(0x40, b"\0" * 0x40, name="stub")
    # a stub: mov w0,#1 ; ret
    core.uc.mem_write(stub, struct.pack("<II", 0x52800002, 0xD65F03C0))
    core.write_u64(obj + 0x118, stub)          # array[1]->[0x118]
    core.write_u64(B + CMD_TBL + 1 * 8, obj)    # array[1] = obj
    print(f"[gate] array[1] = {obj:#x}, [0x118] = {stub:#x}", flush=True)

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
    for state in (9, 10):
        core.write_u32(ctx + 0x2a0, state)
        try:
            r = core.call(SM, x0=ctx, timeout_s=40, max_insns=15_000_000)
            res = f"err={r['error']} x0={r['x0']:#x}"
        except Exception as e:
            res = f"{type(e).__name__}: {str(e)[:50]}"
        st = core.safe_read_u32(ctx + 0x2a0)
        tk = core.safe_read_u64(ctx + 0x288)
        print(f"  state {state}: {res}  -> state={st} task={tk:#x}")
        if r.get("error"):
            break

    print(f"\ncurl URLs: {len(urls)}")
    for u in urls[:6]:
        print(f"    {u!r}")

    print("\nlog (last 12):")
    for line in getattr(core, "_log", [])[-12:]:
        print("   ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
