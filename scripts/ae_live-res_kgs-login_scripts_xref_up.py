#!/usr/bin/env python3
"""Walk the call graph BACKWARD from the game's own HTTP functions.

Goal: find the real, drivable entry point that eventually reaches
curl_easy_setopt -- i.e. let the game run its own login flow instead of
us guessing URLs.

BL encoding: 100101 imm26  -> target = pc + SignExtend(imm26<<2)
BLR Xn:     1101011 0 0 10 11111 000000 Rn 00000
"""
from __future__ import annotations

import os
import struct
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x6000000

SEEDS = {
    0x6886498: "curl_easy_setopt",
    0x7D038C8: "http_post_routine",
    0x767EAF0: "cmd_getserverenv_builder",
    0x7DC7164: "bootstrap_SM",
}


def load_text():
    with open(SO, "rb") as f:
        f.seek(TEXT_OFF)
        return f.read(TEXT_SIZE)


def scan(text):
    """-> (bl_targets: target -> [call_site], calls: site_hi -> target)"""
    bl = defaultdict(list)
    n = len(text) // 4
    for idx in range(n):
        insn = struct.unpack_from("<I", text, idx * 4)[0]
        if (insn & 0xFC000000) == 0x94000000:              # BL
            imm = insn & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            pc = TEXT_VADDR + idx * 4
            bl[pc + (imm << 2)].append(pc)
    return bl


def enclosing(site, funcs):
    """crude enclosing-function guess: greatest func start <= site"""
    best = None
    for fs in funcs:
        if fs <= site and (best is None or fs > best):
            best = fs
    return best


def main():
    depth = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    print("loading .text ...", flush=True)
    text = load_text()
    print(f"  {len(text):,} bytes", flush=True)
    bl = scan(text)
    print(f"  {len(bl):,} distinct BL targets", flush=True)

    # candidate function boundaries: every BL target + every call site's
    # preceding prologue is unknown, so use BL targets as approx starts.
    starts = set(bl.keys())

    # ---- backward BFS ---------------------------------------------------
    seen = set()
    frontier = dict(SEEDS)
    for lvl in range(depth):
        nxt = {}
        print("\n" + "=" * 74)
        print(f"LEVEL {lvl}")
        print("=" * 74)
        for tgt, label in frontier.items():
            sites = bl.get(tgt, [])
            print(f"\n  {label} {tgt:#x}  <- {len(sites)} direct caller(s)")
            for s in sites[:12]:
                print(f"        caller site {s:#x}")
            for s in sites:
                if s in seen:
                    continue
                seen.add(s)
                # the caller function: nearest BL target at/below site
                enc = enclosing(s, starts)
                # climb: report the site itself as the interesting hop
                nxt.setdefault(s, f"caller-of-{label}@{s:#x}")
                # also record the enclosing function start so we can ascend
                if enc is not None:
                    nxt.setdefault(enc, f"fn({label}) {enc:#x}")
        if not nxt:
            print("  (no more callers)")
            break
        # for level>0 we ascend: treat each caller SITE as a target too
        frontier = {}
        for k, v in nxt.items():
            # find callers of the enclosing function start if we have it
            frontier[k] = v
        # keep only real function starts we can be called through
        frontier = {k: v for k, v in frontier.items() if k in starts}
        if not frontier:
            # fall back: ascend from the raw sites by searching BL to them
            frontier = {k: v for k, v in nxt.items()}
            # keep sites that are themselves plausible call targets
            frontier = {k: v for k, v in frontier.items() if k in starts}

    # ---- report every BL that lands on our seeds ------------------------
    print("\n" + "=" * 74)
    print("SUMMARY: direct callers of each seed")
    print("=" * 74)
    for tgt, label in SEEDS.items():
        sites = bl.get(tgt, [])
        print(f"  {label:28s} {tgt:#x}  {len(sites)} caller(s): "
              f"{', '.join(hex(s) for s in sites[:8])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
