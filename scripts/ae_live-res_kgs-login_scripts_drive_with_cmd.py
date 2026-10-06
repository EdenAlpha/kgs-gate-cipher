#!/usr/bin/env python3
"""Set the command-name std::string at 0xa4b2648 (which the SM's state 10
reads) and drive the SM from state 0, so the game builds and runs the task
through its own path.
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
CMDSTR = 0xA4B2648
CMDNAME = b"CmdGetServerEnv"


def main():
    print("[cmd] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(CREATE, timeout_s=60)
    B = core.base
    sess = struct.unpack("<Q", bytes(core.uc.mem_read(B + SESS, 8)))[0]
    print(f"[cmd] session = {sess:#x}", flush=True)

    # ---- set the command-name string -----------------------------------
    buf = core.alloc(64, CMDNAME + b"\0" * (64 - len(CMDNAME)), name="cmd")
    # std::string layout per the SM's reader: flag@0, size@8, data@0x10
    core.write_u8(B + CMDSTR, 0x01)            # is_long
    core.write_u64(B + CMDSTR + 8, len(CMDNAME))
    core.write_u64(B + CMDSTR + 0x10, buf)
    print(f"[cmd] command string set at {CMDSTR:#x} -> {buf:#x}", flush=True)

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

    # ---- drive the SM from state 0 --------------------------------------
    ctx = core.alloc(0x1000, b"\0" * 0x1000, name="ctx")
    for state in range(12):
        core.write_u32(ctx + 0x2a0, state)
        try:
            r = core.call(SM, x0=ctx, timeout_s=40, max_insns=15_000_000)
            res = f"err={r['error']} x0={r['x0']:#x}"
        except Exception as e:
            res = f"{type(e).__name__}: {str(e)[:50]}"
        st = core.safe_read_u32(ctx + 0x2a0)
        tk = core.safe_read_u64(ctx + 0x288)
        print(f"  state {state:2d}: {res}  -> state={st} task={tk:#x}")
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
