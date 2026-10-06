#!/usr/bin/env python3
"""Dump .dynsym function symbols; resolve the names of our mystery
addresses; grep the symbol table for the login/session flow.

The binary is NOT stripped of dynsym -- 33k names are available.
"""
from __future__ import annotations

import os
import sys

from elftools.elf.elffile import ELFFile

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
OUT = os.path.join(HERE, "dynsym_funcs.txt")

KEYS = [0x7DC7164, 0x7A39EA0, 0x767EAF0, 0x7D038C8, 0x7D015B0,
        0x7CDD628, 0x767CEEC, 0x767BDD8, 0x7D04570, 0x7D0C06C,
        0x6886498, 0x814A04C, 0x7DBC788, 0x7D65884, 0x6E93AEC]

GREP = ("serverenv", "gateinfo", "gate_info", "logingate", "kgs",
        "login", "logon", "session", "intro", "bootstrap", "firsttime",
        "first_run", "firstrun", "createuser", "create_user", "guest",
        "room", "matchmake", "onlineenv", "server_env", "serverenvinfo",
        "country", "regionselect", "startgame", "connectserver")


def main():
    syms = []
    with open(SO, "rb") as f:
        elf = ELFFile(f)
        dyn = elf.get_section_by_name(".dynsym")
        if dyn is None:
            print("no .dynsym")
            return 1
        for s in dyn.iter_symbols():
            if s.name and s["st_size"] > 0:
                syms.append((s["st_value"], s["st_size"], s.name))
    syms.sort()
    print(f"{len(syms)} named functions with size")

    with open(OUT, "w", encoding="utf-8") as g:
        for v, sz, nm in syms:
            g.write(f"{v:#012x} {sz:#10x} {nm}\n")
    print(f"wrote {OUT}")

    # ------------------------------------------------ resolve mystery addrs
    print("\n" + "=" * 74)
    print("WHAT ARE OUR MYSTERY ADDRESSES?")
    print("=" * 74)

    def bracket(addr):
        lo, hi = 0, len(syms) - 1
        best = None
        while lo <= hi:
            m = (lo + hi) // 2
            if syms[m][0] <= addr:
                best = m
                lo = m + 1
            else:
                hi = m - 1
        return best

    for k in KEYS:
        for label, a in (("as-vaddr", k), ("as-offset(+0x4000)", k + 0x4000)):
            i = bracket(a)
            if i is None:
                print(f"  {k:#x} [{label}]: below all symbols")
                continue
            v, sz, nm = syms[i]
            inside = v <= a < v + sz
            mark = "  <== INSIDE" if inside else ""
            gap = a - (v + sz)
            print(f"  {k:#x} [{label}]: last sym {v:#x}+{sz:#x} "
                  f"{nm[:70]}{'  (+' + hex(gap) + ' past end)' if not inside else ''}{mark}")

    # ------------------------------------------------------- flow grepping
    print("\n" + "=" * 74)
    print("SYMBOLS MATCHING THE LOGIN / SESSION FLOW")
    print("=" * 74)
    buckets = {k: [] for k in GREP}
    for v, sz, nm in syms:
        low = nm.lower()
        for k in GREP:
            if k in low:
                buckets[k].append((v, sz, nm))
                break
    for k in GREP:
        hits = buckets[k]
        if not hits:
            continue
        print(f"\n-- '{k}' ({len(hits)}) --")
        for v, sz, nm in hits[:30]:
            print(f"    {v:#012x} +{sz:#-8x} {nm[:96]}")
        if len(hits) > 30:
            print(f"    ... {len(hits) - 30} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
