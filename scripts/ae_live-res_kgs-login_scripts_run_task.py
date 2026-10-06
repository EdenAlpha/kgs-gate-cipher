#!/usr/bin/env python3
"""Drive the login SM at state 10 with the REAL CmdGetServerEnv task.

vtable[7] (0x745aaec) returns task->[0xf8]; the SM continues only if bit 0
is set.  So: create the task, set its state byte, hand it to the SM.
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
FACTORY = 0x7DC91D8
CURL_SETOPT = 0x6886498
SESS = 0xA4AB6A8
FDE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "funcs_eh.txt")


def load_fde():
    out = []
    with open(FDE, encoding="utf-8") as f:
        for line in f:
            p = line.split()
            out.append((int(p[0], 16), int(p[1], 16)))
    return out


def enclosing(fde, addr):
    lo, hi = 0, len(fde) - 1
    best = None
    while lo <= hi:
        m = (lo + hi) // 2
        if fde[m][0] <= addr:
            best = m
            lo = m + 1
        else:
            hi = m - 1
    if best is None:
        return None
    a, b = fde[best]
    return (a, b) if a <= addr < b else None


def main():
    print("[run] booting ...", flush=True)
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
    print(f"[run] session = {sess:#x}", flush=True)

    fde = load_fde()
    name = core.alloc(64, b"CmdGetServerEnv\0", name="cmdname")
    r = core.call(FACTORY, name, 0, 0, 0, 0, timeout_s=60,
                  max_insns=20_000_000)
    task = r.get("x0")
    print(f"[run] task = {task:#x} err={r.get('error')}", flush=True)
    if not task:
        return 1

    # dump the task's fields
    print("\ntask fields:")
    try:
        raw = bytes(core.uc.mem_read(task, 0x120))
        for off in range(0, 0x120, 8):
            v = struct.unpack_from("<Q", raw, off)[0]
            if v == 0:
                continue
            extra = ""
            if off + 8 <= 0x30:
                bs = struct.pack("<Q", v)
                if all(32 <= c < 127 for c in bs):
                    extra = f'  "{bs.decode()}"'
            print(f"    +{off:#04x}: {v:#018x}{extra}")
    except Exception as e:
        print(f"    unreadable: {type(e).__name__}")

    # ---- set the state byte and drive ----------------------------------
    core.write_u8(task + 0xf8, 1)
    print(f"\n[run] set task->[0xf8] = 1", flush=True)

    urls = []

    def on_setopt(uc, c):
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        if opt == 10002:
            try:
                raw2 = bytes(uc.mem_read(val, 256))
            except Exception:
                raw2 = b""
            z = raw2.find(b"\0")
            urls.append(raw2[:z if z >= 0 else 256])
            print(f"    >>> CURLOPT_URL = {urls[-1]!r}", flush=True)

    core.watch(CURL_SETOPT, on_setopt, name="curl_easy_setopt")

    ctx = core.alloc(0x1000, b"\0" * 0x1000, name="ctx")
    core.write_u64(ctx + 0x288, task)
    core.write_u32(ctx + 0x2a0, 10)

    print("[run] driving SM at state 10 with the real task ...", flush=True)
    try:
        r = core.call(SM, x0=ctx, timeout_s=60, max_insns=20_000_000)
        print(f"[run] SM -> err={r['error']} x0={r['x0']:#x}", flush=True)
    except Exception as e:
        print(f"[run] SM -> {type(e).__name__}: {str(e)[:70]}", flush=True)

    print(f"\ncurl URLs seen: {len(urls)}")
    for u in urls[:8]:
        print(f"    {u!r}")

    print("\nharness log (last 15):")
    for line in getattr(core, "_log", [])[-15:]:
        print("   ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
