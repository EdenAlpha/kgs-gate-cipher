#!/usr/bin/env python3
"""Debug .rela.dyn: print section metadata, raw sample entries, and an
addend histogram by section. Determines whether pointer tables are findable.
"""
from __future__ import annotations

import os
import struct
import sys
from collections import Counter

from elftools.elf.elffile import ELFFile

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

TEXT_VADDR = 0x28293C0
TEXT_END = 0x28293C0 + 0x630BE48


def main():
    with open(SO, "rb") as f:
        elf = ELFFile(f)
        print("SECTIONS that look like relocations:")
        for s in elf.iter_sections():
            if "rela" in s.name or "rel" == s.name[:3]:
                print(f"  {s.name:14s} type={s['sh_type']!r:16} "
                      f"entsize={s['sh_entsize']} size={s.data_size:#x} "
                      f"-> {s.data_size // max(1, s['sh_entsize'])} entries")

        rela = elf.get_section_by_name(".rela.dyn")
        raw = rela.data()
        print(f"\n.sh_type={rela['sh_type']} sh_entsize={rela['sh_entsize']} "
              f"len(data)={len(raw):#x}")

        print("\nfirst 8 raw entries (24B each):")
        for i in range(8):
            o, info, add = struct.unpack_from("<QQq", raw, i * 24)
            print(f"  r_offset={o:#014x} r_info={info:#018x} "
                  f"type={info & 0xFFFFFFFF:#x} addend={add:#014x}")

        # section map for classification
        secs = [(s.name, s["sh_addr"], s["sh_addr"] + s.data_size)
                for s in elf.iter_sections()
                if s["sh_addr"] and s.data_size]

        def sec_of(a):
            for nm, lo, hi in secs:
                if lo <= a < hi:
                    return nm
            return f"<unmapped:{a:#x}>"

        types = Counter()
        add_sec = Counter()
        big = []
        for i in range(0, len(raw) - 24, 24):
            o, info, add = struct.unpack_from("<QQq", raw, i * 24)
            types[info & 0xFFFFFFFF] += 1
            add_sec[sec_of(add)] += 1
            if TEXT_VADDR <= add < TEXT_END:
                big.append((o, add))

        print("\nrelocation type histogram (r_info & 0xffffffff):")
        for t, c in types.most_common(12):
            print(f"  type {t:#x} ({t}): {c:,}")

        print("\naddend -> section histogram (top 15):")
        for s, c in add_sec.most_common(15):
            print(f"  {s:24s} {c:,}")

        print(f"\naddends inside .text: {len(big):,}")
        for o, a in big[:10]:
            print(f"   r_offset={o:#x} -> fn {a:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
