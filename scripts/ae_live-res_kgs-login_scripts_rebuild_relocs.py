#!/usr/bin/env python3
"""Rebuild packed_relocs.npz straight from the ELF.

The cache used to live in apk_lab/analysis/, which no longer exists.  Nothing
in it is derived data we cannot recompute: parse PT_DYNAMIC for DT_RELA /
DT_RELASZ / DT_RELAENT, walk .rela.dyn, and pack (offset, sym, rtype, addend)
into the same .npz the loader expects.
"""
from __future__ import annotations

import os
import sys

import numpy as np
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.dynamic import DynamicSection

SO = os.path.join(r"C:\Users\Administrator\Documents\Default Project",
                  "peerlink-efootball-disconnects", "efootball-apk", "native",
                  "lib", "arm64-v8a", "libUE4.so")
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "apk_lab", "analysis")

DT_RELA, DT_RELASZ, DT_RELAENT, DT_REL, DT_RELSZ = 7, 8, 9, 17, 18


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, "packed_relocs.npz")

    with open(SO, "rb") as f:
        elf = ELFFile(f)

        # --- DT_RELA region from PT_DYNAMIC ---
        rela_addr = rela_sz = rela_ent = None
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_DYNAMIC":
                continue
            for tag in seg.iter_tags():
                if tag.entry.d_tag == "DT_RELA":
                    rela_addr = tag.entry.d_ptr
                elif tag.entry.d_tag == "DT_RELASZ":
                    rela_sz = tag.entry.d_val
                elif tag.entry.d_tag == "DT_RELAENT":
                    rela_ent = tag.entry.d_val
            break
        print("DT_RELA=%s size=%s ent=%s" % (rela_addr, rela_sz, rela_ent))

        offsets, syms, rtypes, addends = [], [], [], []

        # --- 1. SHT_RELA sections (these carry the real symbol indices) ---
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            n = sec.num_relocations()
            print("  rela section %-24s n=%d" % (sec.name, n))
            symtab = elf.get_section(sec["sh_link"]) \
                if sec["sh_link"] else None
            for i in range(n):
                r = sec.get_relocation(i)
                si = r["r_info_sym"]
                if symtab is not None and si < symtab.num_symbols():
                    sym = symtab.get_symbol(si)
                    name = sym.name
                    val = sym["st_value"]
                else:
                    name, val = None, 0
                offsets.append(r["r_offset"])
                rtypes.append(r["r_info_type"])
                addends.append(r["r_addend"])
                # the loader maps symbol names -> stubs, so keep the name in
                # the sym array as an index into a name table we also store
                syms.append(name if name is not None else "")

        print("total relocations: %d" % len(offsets))

        if not offsets:
            print("no relocations found", file=sys.stderr)
            return 1

        # symbol names as a numpy string array (the loader does .tolist())
        sym_arr = np.array(syms, dtype=object).astype(str)
        np.savez(out,
                 offset=np.array(offsets, dtype="<u8"),
                 sym=sym_arr,
                 rtype=np.array(rtypes, dtype="<u8"),
                 addend=np.array(addends, dtype="<i8"))
    print("wrote", out, os.path.getsize(out), "bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
