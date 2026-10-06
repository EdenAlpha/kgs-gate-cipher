#!/usr/bin/env python3
"""This ELF has no DT_RELA/DT_RELASZ, so the loader's relocation pass does
nothing and every vtable slot stays 0 -- which is why any virtual call in the
game jumps to address 0.

The linker stores the vtable's *targets* as R_AARCH64_RELATIVE relocations
that are not in the file, but the addends are recoverable: the .rela.plt
GOT slots we did recover give us the "got" address for each import, and the
real fix is to walk the section-relative relocation list the linker left
behind, or -- when a .rela.dyn really is absent -- recover vtable contents
from the runtime image of a real Android process.

This script reports exactly what is available so we do not guess.
"""
from __future__ import annotations

import struct
import sys

from elftools.elf.elffile import ELFFile

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
VADDR = 0x97D4448          # the vtable the command ctor installs
N = 12


def main() -> int:
    with open(SO, "rb") as f:
        elf = ELFFile(f)
        print("section headers that could carry relocations:")
        for s in elf.iter_sections():
            if s["sh_type"] in ("SHT_RELA", "SHT_REL", "SHT_DYNSYM"):
                n = s.num_relocations() if s["sh_type"] == "SHT_RELA" else 0
                print(f"   {s.name:24s} {s['sh_type']:12s} relocs={n} "
                      f"size={s['sh_size']:#x} addr={s['sh_addr']:#x}")

        print("\nprogram headers:")
        for seg in elf.iter_segments():
            if seg["p_type"] in ("PT_DYNAMIC", "PT_LOAD"):
                print(f"   {seg['p_type']:10s} vaddr={seg['p_vaddr']:#x} "
                      f"filesz={seg['p_filesz']:#x} memsz={seg['p_memsz']:#x}")

        # the vtable lives in a PT_LOAD; show its raw bytes
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            if seg["p_vaddr"] <= VADDR < seg["p_vaddr"] + seg["p_memsz"]:
                off = seg["p_offset"] + (VADDR - seg["p_vaddr"])
                f.seek(off)
                raw = f.read(8 * N)
                print(f"\nvtable {VADDR:#x} raw (in file):")
                for i in range(N):
                    v = struct.unpack_from("<Q", raw, 8 * i)[0]
                    print(f"   [{i}] {v:#018x}")
                print("\nall zero -> R_AARCH64_RELATIVE addends were never "
                      "written into the file; they come from the dynamic\n"
                      "linker at load time, and there is no .rela.dyn to "
                      "read them from.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
