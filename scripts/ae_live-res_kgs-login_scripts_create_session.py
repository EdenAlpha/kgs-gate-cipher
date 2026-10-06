#!/usr/bin/env python3
"""0x7cda280 is the session get-or-create:
    if (*(0xa4ab6a8)) return it;
    obj = new(0x68); obj->vt = 0x9821500; *(0xa4ab6a8) = obj;

Call it, confirm the session exists, dump its vtable, then drive the login
SM and watch for the game's own HTTP stack firing.
"""
from __future__ import annotations

import os
import struct
import sys
import time

from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1   # noqa: E402

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

SM = 0x7DC7164
CREATE_SESSION = 0x7CDA280
CURL_SETOPT = 0x6886498
SESS = 0xA4AB6A8
MODE = 0xA4AB6A0
SESS_VT = 0x9821500
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
    t0 = time.time()
    print("[sess2] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    print(f"[sess2] up in {time.time()-t0:.1f}s", flush=True)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    print("[sess2] registrars done", flush=True)

    B = core.base

    def rd(a, n=8):
        try:
            return bytes(core.uc.mem_read(B + a, n))
        except Exception:
            return b""

    print(f"\nbefore: mode={struct.unpack('<I', rd(MODE,4))[0]} "
          f"sess={struct.unpack('<Q', rd(SESS))[0]:#x}")

    # ---- create the session -------------------------------------------
    print("\ncalling 0x7cda280 (get-or-create session) ...", flush=True)
    try:
        r = core.call(CREATE_SESSION, timeout_s=60)
        print(f"  -> {r}", flush=True)
    except Exception as e:
        print(f"  -> {type(e).__name__}: {e}", flush=True)

    mode = struct.unpack("<I", rd(MODE, 4))[0]
    sess = struct.unpack("<Q", rd(SESS))[0]
    print(f"\nafter:  mode={mode} sess={sess:#x}")

    if sess == 0:
        print("\n*** session still NULL ***")
        return 1

    print(f"\n*** SESSION OBJECT at {sess:#x} ***")
    fde = load_fde()
    raw = bytes(core.uc.mem_read(sess, 0x68))
    for off in range(0, 0x68, 8):
        v = struct.unpack_from("<Q", raw, off)[0]
        if v == 0:
            continue
        tag = ""
        e = enclosing(fde, v - B) if B <= v < B + 0x100000000 else None
        if e and v - B == e[0]:
            tag = f"  FN {e[0]:#x}"
        print(f"    +{off:#04x}: {v:#018x}{tag}")

    # ---- the session vtable -------------------------------------------
    print(f"\nRUNTIME VTABLE {SESS_VT:#x} (session methods)")
    print("=" * 74)
    try:
        vtd = bytes(core.uc.mem_read(B + SESS_VT, 32 * 8))
    except Exception as e:
        print(f"  unreadable: {type(e).__name__}")
        return 1
    fde = load_fde()
    for i in range(32):
        v = struct.unpack_from("<Q", vtd, i * 8)[0]
        if v == 0:
            continue
        e = enclosing(fde, v - B) if B <= v < B + 0x100000000 else None
        if e and v - B == e[0]:
            tag = f"FN {v - B:#x} size {e[1]-e[0]:#x}"
        elif e:
            tag = f"fn {e[0]:#x}+{v - B - e[0]:#x}"
        else:
            tag = f"{v:#x}"
        print(f"  [{i:2d}] +{i*8:#05x}  {v:#018x}  {tag}")

    # ---- now drive the SM ---------------------------------------------
    print("\n" + "=" * 74)
    print("DRIVING THE LOGIN SM (state 10) WITH THE REAL SESSION")
    print("=" * 74)

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

    EXEC_BASE = 0xA4000000000
    try:
        core.uc.mem_map(EXEC_BASE, 0x100000, 7)
    except Exception:
        pass
    stub = EXEC_BASE
    core.uc.mem_write(stub, struct.pack("<II", 0x52800002, 0xD65F03C0) * 8)

    task_vt = core.alloc(0x100, b"\0" * 0x100, name="task_vt")
    task = core.alloc(0x200, b"\0" * 0x200, name="task")
    ctx = core.alloc(0x800, b"\0" * 0x800, name="ctx")
    core.write_u64(task_vt + 0x38, stub)
    core.write_u64(task, task_vt)
    core.write_u64(ctx + 0x288, task)
    core.write_u32(ctx + 0x2a0, 10)

    try:
        r = core.call(SM, x0=ctx, timeout_s=60, max_insns=20_000_000)
        print(f"  SM -> {r}", flush=True)
    except Exception as e:
        print(f"  SM -> {type(e).__name__}: {str(e)[:80]}", flush=True)

    print(f"\ncurl URLs seen: {len(urls)}")
    for u in urls[:6]:
        print(f"    {u!r}")

    print("\nharness log (last 15):")
    for line in getattr(core, "_log", [])[-15:]:
        print("   ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
