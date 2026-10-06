#!/usr/bin/env python3
"""With a real session created, drive the login SM from state 0 and trace
which session methods get called and whether the HTTP stack fires.
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
SESS_VT = 0x9821500

# session methods we want to trace
TRACE = {
    0x7CDA184: "sess_destroy0",
    0x7CDA1F8: "sess_destroy1",
    0x7CDB974: "m4", 0x7CDB9D0: "m5",
    0x7CE1A48: "m6", 0x7CE1ACC: "m7",
    0x7CDBA60: "m8", 0x7CDC3D8: "m9",
    0x7CDC414: "m10", 0x7CDC6E8: "m11",
    0x7CDCA20: "m12", 0x7CDCAD4: "m13",
    0x7CDCAB4: "m14", 0x7CE1860: "m15",
    0x7CE1974: "m16", 0x7CE1480: "m17",
    0x7CDC3D8: "m9", 0x7CDC414: "m10",
    0x7CDCAF4: "m24", 0x7CE1334: "m25",
    0x7CE1450: "m26", 0x7CDD70C: "m28",
    0x7D2BF4C: "f_7d2bf4c", 0x7D5A1EC: "f_7d5a1ec",
    0x7B1CF34: "f_7b1cf34",
}


def main():
    t0 = time.time()
    print("[drv] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    print(f"[drv] up in {time.time()-t0:.1f}s", flush=True)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass

    B = core.base
    r = core.call(CREATE, timeout_s=60)
    sess = struct.unpack("<Q", bytes(core.uc.mem_read(B + SESS, 8)))[0]
    print(f"[drv] session = {sess:#x}", flush=True)

    calls = []

    def mk(name):
        def h(uc, c):
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            calls.append((name, x0, x1))
            print(f"    [{len(calls):3d}] {name:16s} x0={x0:#x} x1={x1:#x}",
                  flush=True)
        return h

    for addr, name in TRACE.items():
        try:
            core.watch(addr, mk(name), name=name)
        except Exception:
            pass

    urls = []

    def on_setopt(uc, c):
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        if opt == 10002:
            try:
                raw = bytes(uc.mem_read(val, 256))
            except Exception:
                raw = b""
            z = raw.find(b"\0")
            urls.append(raw[:z if z >= 0 else 256])
            print(f"    >>> CURLOPT_URL = {urls[-1]!r}", flush=True)

    core.watch(CURL_SETOPT, on_setopt, name="curl_easy_setopt")

    # ---- drive the SM through its states --------------------------------
    ctx = core.alloc(0x1000, b"\0" * 0x1000, name="login_ctx")

    for state in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10):
        core.write_u32(ctx + 0x2a0, state)
        calls.clear()
        print(f"\n--- state {state} ---", flush=True)
        try:
            r = core.call(SM, x0=ctx, timeout_s=40,
                          max_insns=15_000_000)
            print(f"  -> err={r['error']} x0={r['x0']:#x}", flush=True)
        except Exception as e:
            print(f"  -> {type(e).__name__}: {str(e)[:70]}", flush=True)
        st = core.safe_read_u32(ctx + 0x2a0)
        tk = core.safe_read_u64(ctx + 0x288)
        print(f"  ctx: state={st} task={tk:#x}", flush=True)
        if r.get("error"):
            break

    print("\n" + "=" * 74)
    print(f"curl URLs seen: {len(urls)}")
    for u in urls[:8]:
        print(f"    {u!r}")

    print("\nharness log (last 12):")
    for line in getattr(core, "_log", [])[-12:]:
        print("   ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
