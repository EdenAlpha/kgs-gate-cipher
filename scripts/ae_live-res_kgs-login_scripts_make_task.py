#!/usr/bin/env python3
"""Call the task factory 0x7dc91d8 with a command name and dump the task's
vtable (0x9828a90) -- whose [7] is what the login SM's state 10 executes.
"""
from __future__ import annotations

import os
import struct
import sys
import time

from unicorn.arm64_const import UC_ARM64_REG_X0   # noqa: E402

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

CREATE = 0x7CDA280
TASK_FACTORY = 0x7DC91D8
TASK_VT = 0x9828A90
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
    print("[task] booting ...", flush=True)
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
    print(f"[task] session = {sess:#x}", flush=True)

    fde = load_fde()

    # ---- call the task factory with a command name ----------------------
    name = core.alloc(64, b"CmdGetServerEnv\0", name="cmdname")
    print(f"[task] calling factory with name at {name:#x}", flush=True)

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

    try:
        r = core.call(TASK_FACTORY, name, 0, 0, 0, 0,
                      timeout_s=60, max_insns=20_000_000)
        task = r.get("x0")
        print(f"[task] factory -> {task:#x}  err={r.get('error')}",
              flush=True)
    except Exception as e:
        print(f"[task] EXC {type(e).__name__}: {str(e)[:70]}", flush=True)
        return 1

    if not task:
        print("[task] factory returned NULL")
        return 1

    # ---- dump the task object ------------------------------------------
    print(f"\n*** TASK OBJECT {task:#x} ***")
    try:
        raw = bytes(core.uc.mem_read(task, 0x80))
        for off in range(0, 0x80, 8):
            v = struct.unpack_from("<Q", raw, off)[0]
            if v == 0:
                continue
            tag = ""
            e = enclosing(fde, v - B) if B <= v < B + 0x100000000 else None
            if e and v - B == e[0]:
                tag = f"  FN {e[0]:#x}"
            print(f"    +{off:#04x}: {v:#018x}{tag}")
    except Exception as e:
        print(f"    unreadable: {type(e).__name__}")

    # ---- dump the task vtable ------------------------------------------
    print(f"\nRUNTIME TASK VTABLE {TASK_VT:#x}")
    print("=" * 74)
    try:
        vtd = bytes(core.uc.mem_read(B + TASK_VT, 24 * 8))
    except Exception as e:
        print(f"  unreadable: {type(e).__name__}")
        return 1
    vt_fns = {}
    for i in range(24):
        v = struct.unpack_from("<Q", vtd, i * 8)[0]
        if v == 0:
            continue
        e = enclosing(fde, v - B) if B <= v < B + 0x100000000 else None
        if e and v - B == e[0]:
            tag = f"FN {v - B:#x} size {e[1]-e[0]:#x}"
            vt_fns[i] = v - B
        elif e:
            tag = f"fn {e[0]:#x}+{v - B - e[0]:#x}"
        else:
            tag = f"{v:#x}"
        mark = "   <== state10 calls this" if i == 7 else ""
        print(f"  [{i:2d}] +{i*8:#05x}  {v:#018x}  {tag}{mark}")

    print(f"\ncurl URLs seen: {len(urls)}")
    for u in urls[:6]:
        print(f"    {u!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
