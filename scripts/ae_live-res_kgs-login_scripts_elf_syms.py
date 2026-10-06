#!/usr/bin/env python3
"""Enumerate ELF symbols: find the library's real top-level entry points
(ANativeActivity_onCreate / SDL_main / main / JNI_OnLoad / Java_*), and get
proper function boundaries so call-graph ascent stops guessing.
"""
from __future__ import annotations

import os
import sys

from elftools.elf.elffile import ELFFile

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

INTEREST = (
    "oncreate", "androidmain", "sdl_main", "androidentry", "android_main",
    "jni_onload", "jni_onunload", "nativeactivity", "app_dummy",
    "android_mainentry", "main", "entrypoint", "runmain",
)


def main():
    with open(SO, "rb") as f:
        elf = ELFFile(f)

        print("=" * 74)
        print("SECTIONS")
        print("=" * 74)
        for s in elf.iter_sections():
            if s.name in (".symtab", ".dynsym", ".strtab", ".dynstr",
                          ".eh_frame", ".text", ".init_array", ".fini_array",
                          ".gnu.hash", ".rela.dyn", ".rela.plt"):
                print(f"  {s.name:16s} size={s.data_size:#x}")

        for sec_name, str_name in ((".symtab", ".strtab"),
                                   (".dynsym", ".dynstr")):
            sec = elf.get_section_by_name(sec_name)
            if sec is None:
                print(f"\n{sec_name}: ABSENT")
                continue
            strs = elf.get_section_by_name(str_name)
            print("\n" + "=" * 74)
            print(f"{sec_name}: {sec.num_symbols()} symbols")
            print("=" * 74)

            # 1. entry-ish symbols
            print("\n-- entry-point candidates --")
            found = 0
            for sym in sec.iter_symbols():
                nm = sym.name
                if not nm:
                    continue
                low = nm.lower()
                if any(k in low for k in INTEREST) and \
                        ("main" in low or "entry" in low or
                         "oncreate" in low or "jni_onload" in low or
                         "activity" in low or "android" in low or
                         low == "main" or "dummy" in low):
                    print(f"  {sym['st_value']:#012x}  "
                          f"size={sym['st_size']:#x}  {nm}")
                    found += 1
            if not found:
                print("  (none)")

            # 2. function symbols whose size covers our targets of interest
            print("\n-- functions containing our key addresses --")
            KEYS = [0x7DC7164, 0x7A39EA0, 0x767EAF0, 0x7D038C8,
                    0x7D015B0, 0x7CDD628, 0x767CEEC, 0x767BDD8]
            hits = []
            for sym in sec.iter_symbols():
                v = sym["st_value"]
                sz = sym["st_size"]
                if sz <= 0 or not sym.name:
                    continue
                for k in KEYS:
                    if v <= k < v + sz:
                        hits.append((k, v, sz, sym.name))
            seen = set()
            for k, v, sz, nm in sorted(hits):
                if (k, v) in seen:
                    continue
                seen.add((k, v))
                print(f"  target {k:#x} in {v:#x}+{sz:#x}  {nm}")

            # 3. count of named functions overall
            nf = sum(1 for s in sec.iter_symbols()
                     if s.name and s["st_size"] > 0)
            print(f"\n  named non-empty symbols: {nf}")

        # init_array
        ia = elf.get_section_by_name(".init_array")
        if ia is not None:
            print(f"\n.init_array size {ia.data_size:#x} "
                  f"-> {ia.data_size // 8} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
