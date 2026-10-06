#!/usr/bin/env python3
"""Dump a wide window around the discovered dispatch tables to reveal their
extent, record stride, and field layout -- and find any global that points
at them (the owner).
"""
from __future__ import annotations

import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "scripts"))
sys.path.insert(0, HERE)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

HITS = {
    "cmdenv_dispatcher": 0x767CECC,
    "bootstrap_SM":      0x7DC7164,
    "cmd_getserverenv":  0x767EAF0,
    "http_post_routine": 0x7D038C8,
    "gateinfo_sender":   0x7D0C06C,
}
WINDOW = 0x400


def load_fde():
    p = os.path.join(HERE, "funcs_eh.txt")
    out = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            a = line.split()
            out.append((int(a[0], 16), int(a[1], 16)))
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


def find(core, vaddr_abs):
    pat = struct.pack("<Q", vaddr_abs)
    found = []
    for start, end, _p in core.uc.mem_regions():
        size = end - start
        if size <= 0 or size > 1 << 32:
            continue
        off = 0
        while off < size:
            n = min(4 << 20, size - off)
            try:
                buf = bytes(core.uc.mem_read(start + off, n))
            except Exception:
                break
            i = buf.find(pat)
            if i >= 0:
                found.append(start + off + i)
            off += n
    return found


def main():
    t0 = time.time()
    print("[dump] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    print(f"[dump] up in {time.time()-t0:.1f}s base={core.base:#x}",
          flush=True)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    print("[dump] registrars done", flush=True)

    fde = load_fde()

    for name, v in HITS.items():
        locs = find(core, core.base + v)
        print("\n" + "=" * 74)
        print(f"{name} {v:#x}  -> {len(locs)} pointer(s)")
        print("=" * 74)
        for loc in locs[:2]:
            lo = loc - WINDOW
            print(f"  window {lo:#x} .. {loc + WINDOW:#x}")
            try:
                raw = bytes(core.uc.mem_read(lo, WINDOW * 2))
            except Exception:
                print("    (unreadable)")
                continue
            for i in range(0, len(raw), 8):
                at = lo + i
                val = struct.unpack_from("<Q", raw, i)[0]
                if val == 0:
                    continue
                sel = ">>" if at == loc else "  "
                if core.base <= val < core.base + 0x100000000:
                    off = val - core.base
                    e = enclosing(fde, off)
                    if e and off == e[0]:
                        tag = f"FN {e[0]:#x} size {e[1]-e[0]:#x}"
                    elif e:
                        tag = f"fn {e[0]:#x}+{off-e[0]:#x}"
                    else:
                        tag = f"obj {off:#x}"
                else:
                    tag = f"(not code: {val:#x})"
                print(f"    {sel} {at:#x}: {val:#018x}  {tag}")

        # who points at the neighbourhood of this hit?
        if locs:
            base_guess = locs[0] & ~0xFFF
            print(f"  --- globals pointing into {base_guess:#x}.. ---")
            owners = find(core, base_guess)
            for o in owners[:6]:
                print(f"      owner ptr at {o:#x}")

    print("\n[harness log last 12]")
    for line in getattr(core, "_log", [])[-12:]:
        print("   ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
