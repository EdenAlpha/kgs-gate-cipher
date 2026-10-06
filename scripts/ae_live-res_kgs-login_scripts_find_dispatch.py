#!/usr/bin/env python3
"""Boot the headless game, run its online registrars, then SCAN EMULATED
MEMORY for pointers to the online/login functions.

The relocations in this binary are Android-packed (SHT_ANDROID_RELA / "APS2"),
so pointer tables are zero-filled in the file and invisible to static scans.
At runtime they are filled in -- so we read them back out of the emulator.

Wherever `base + TARGET` appears, that is the dispatch table. Dump the
surrounding qwords, resolve each neighbour to its real function (.eh_frame),
and we get the whole handler family at once.
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

# online/login functions we want to find pointers to
TARGETS = {
    "bootstrap_SM":         0x7DC7164,
    "cmdenv_chain_top":     0x7A39B0C,
    "cmdenv_dispatcher":    0x767CECC,
    "cmd_getserverenv":     0x767EAF0,
    "http_post_routine":    0x7D038C8,
    "http_post_parent":     0x7D017DC,
    "http_post_grandparent": 0x7CE7070,
    "gateinfo_parent":      0x7D0BDA8,
    "gateinfo_sender":      0x7D0C06C,
    "http_post_alt":        0x7D157F8,
}

FDE = os.path.join(HERE, "funcs_eh.txt")


def load_fde():
    starts = []
    with open(FDE, encoding="utf-8") as f:
        for line in f:
            p = line.split()
            starts.append((int(p[0], 16), int(p[1], 16)))
    return starts


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


def scan(core, needles):
    """Return {name: [(region_start, file_off_in_region), ...]}"""
    hits = {k: [] for k in needles}
    regs = []
    for start, end, _perm in core.uc.mem_regions():
        regs.append((start, end))
    regs.sort()
    total = 0
    CHUNK = 4 * 1024 * 1024
    for rs, re_ in regs:
        size = re_ - rs
        if size <= 0 or size > 1 << 32:
            continue
        off = 0
        while off < size:
            n = min(CHUNK, size - off)
            try:
                buf = bytes(core.uc.mem_read(rs + off, n))
            except Exception:
                break
            total += n
            for name, pat in needles.items():
                p = 0
                while True:
                    i = buf.find(pat, p)
                    if i < 0:
                        break
                    hits[name].append(rs + off + i)
                    p = i + 1
            off += n
    return hits, total, len(regs)


def main():
    t0 = time.time()
    print("[scan] booting headless game core ...", flush=True)
    core = OnlineCore(verbose=False)
    print(f"[scan] core up in {time.time()-t0:.1f}s "
          f"(base {core.base:#x})", flush=True)

    try:
        core.install_netsplice()
        print("[scan] netsplice installed", flush=True)
    except Exception as e:
        print(f"[scan] netsplice: {type(e).__name__}: {e}", flush=True)

    # ---- run the game's own online-config registrars --------------------
    ok = 0
    for fn in REGISTRARS:
        try:
            core.call(fn)
            ok += 1
        except Exception as e:
            print(f"  registrar {fn:#x}: {type(e).__name__} "
                  f"{str(e)[:70]}", flush=True)
    print(f"[scan] registrars: {ok}/{len(REGISTRARS)} ran", flush=True)

    # ---- build needle -> absolute address in emulated memory ------------
    needles = {}
    for name, v in TARGETS.items():
        needles[f"{name}|abs"] = struct.pack("<Q", core.base + v)
        needles[f"{name}|rel"] = struct.pack("<Q", v)

    print(f"[scan] scanning memory for {len(needles)} needles ...",
          flush=True)
    hits, total, nreg = scan(core, needles)
    print(f"[scan] read {total/1e6:.1f} MB across {nreg} regions",
          flush=True)

    fde = load_fde()

    print("\n" + "=" * 74)
    print("POINTERS FOUND IN EMULATED MEMORY")
    print("=" * 74)
    any_hit = False
    for key, locs in hits.items():
        if not locs:
            continue
        any_hit = True
        name = key.rsplit("|", 1)[0]
        mode = key.rsplit("|", 1)[1]
        print(f"\n  {name} ({mode}): {len(locs)} pointer(s)")
        for loc in locs[:6]:
            print(f"      at {loc:#x}")
            # dump 12 qwords either side
            try:
                raw = bytes(core.uc.mem_read(loc - 0x60, 0xC0))
            except Exception:
                continue
            for i in range(0, len(raw), 8):
                v = struct.unpack_from("<Q", raw, i)[0]
                at = loc - 0x60 + i
                mark = " <== HERE" if at == loc else ""
                # classify
                if core.base <= v < core.base + 0x100000000:
                    off = v - core.base
                    e = enclosing(fde, off)
                    tag = f"fn {e[0]:#x}+{off-e[0]:#x}" if e else f"obj {off:#x}"
                else:
                    tag = ""
                sel = ">>" if at == loc else "  "
                print(f"         {sel} {at:#x}: {v:#018x} {tag}{mark}")

    if not any_hit:
        print("\n  (no pointers found - the tables are still empty,")
        print("   or these functions are reached some other way)")

    print("\n" + "=" * 74)
    print("harness log (last 20):")
    for line in getattr(core, "_log", [])[-20:]:
        print("   ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
