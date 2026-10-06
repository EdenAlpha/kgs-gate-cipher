#!/usr/bin/env python3
"""Validate two assumptions before trusting them:

A) .eh_frame parse is correct  -> FDE starts must coincide with .dynsym
   function starts (dynsym is ground truth for the symbols it does have).
B) address model is correct    -> show the raw prologue bytes at
   (vaddr - 0x4000) vs (vaddr), and disassemble both.
"""
from __future__ import annotations

import os
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
SHIFT = TEXT_VADDR - TEXT_OFF          # 0x4000

KEYS = [0x7DC7164, 0x767EAF0, 0x7D038C8, 0x7A39B0C, 0x2830374]


def main():
    with open(SO, "rb") as f:
        elf = ELFFile(f)
        dyn = elf.get_section_by_name(".dynsym")
        dyn_starts = set()
        for s in dyn.iter_symbols():
            if s.name and s["st_size"] > 0:
                dyn_starts.add(s["st_value"])
        print(f".dynsym function starts: {len(dyn_starts)}")

        eh = elf.get_section_by_name(".eh_frame")
        raw = eh.data()
        sec_addr = eh["sh_addr"]

    # --- parse FDE starts only (fast path) -------------------------------
    fde_starts = set()
    cie_ptr_enc = {}
    off = 0
    n = len(raw)
    while off + 8 <= n:
        ln = struct.unpack_from("<I", raw, off)[0]
        if ln == 0:
            break
        if ln == 0xFFFFFFFF:
            ln = struct.unpack_from("<Q", raw, off + 4)[0]
            body = off + 12
        else:
            body = off + 4
        end = body + ln
        if end > n:
            break
        cid = struct.unpack_from("<I", raw, body)[0]
        if cid == 0:
            p = body + 4
            ver = raw[p]
            p += 1
            z = raw.index(0, p)
            aug = raw[p:z].decode("latin1")
            p = z + 1
            if ver >= 4:
                p += 2
            # code_align uleb
            while raw[p] & 0x80:
                p += 1
            p += 1
            # data_align sleb
            while raw[p] & 0x80:
                p += 1
            p += 1
            if ver < 4:
                p += 1
            else:
                while raw[p] & 0x80:
                    p += 1
                p += 1
            enc = 0x00
            if aug[:1] == "z":
                adl = 0
                shift = 0
                while True:
                    c = raw[p]
                    p += 1
                    adl |= (c & 0x7F) << shift
                    shift += 7
                    if not (c & 0x80):
                        break
                aend = p + adl
                if "R" in aug:
                    enc = raw[p]
                p = aend
            cie_ptr_enc[off] = enc
        else:
            enc = cie_ptr_enc.get(body - cid, 0x1B)
            p = body + 4
            fmt, app = enc & 0xF, enc & 0x70
            if fmt == 0x0B:
                v = struct.unpack_from("<i", raw, p)[0]
                base = sec_addr + p
                p += 4
            elif fmt == 0x03:
                v = struct.unpack_from("<I", raw, p)[0]
                base = sec_addr + p
                p += 4
            elif fmt == 0x0C:
                v = struct.unpack_from("<q", raw, p)[0]
                base = sec_addr + p
                p += 8
            else:
                v = struct.unpack_from("<Q", raw, p)[0]
                base = 0
                p += 8
            if app == 0x20:
                base = TEXT_VADDR
            fde_starts.add((base + v) & 0xFFFFFFFFFFFFFFFF)
        off = end

    print(f".eh_frame FDE starts: {len(fde_starts)}")

    inter = dyn_starts & fde_starts
    print(f"\n(A) dynsym starts that are ALSO FDE starts: "
          f"{len(inter)} / {len(dyn_starts)}  "
          f"({100.0 * len(inter) / max(1, len(dyn_starts)):.1f}%)")

    # are our KEYS FDE starts?
    print("\n  are our mystery addresses FDE *starts* (not just inside)?")
    for k in KEYS:
        print(f"    {k:#x}: {'YES' if k in fde_starts else 'no'}")

    # --- disassemble both candidate offsets ------------------------------
    print("\n" + "=" * 74)
    print("(B) RAW BYTES at vaddr-SHIFT  vs  vaddr")
    print("=" * 74)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    with open(SO, "rb") as f:
        for k in KEYS:
            print(f"\n  --- {k:#x} ---")
            for label, fo in (("file off = vaddr-0x4000", k - SHIFT),
                              ("file off = vaddr      ", k)):
                try:
                    f.seek(fo)
                    b = f.read(32)
                except Exception as e:
                    print(f"    {label}: {e}")
                    continue
                if len(b) < 32:
                    print(f"    {label}: EOF")
                    continue
                # heuristics for a plausible function prologue
                w = [struct.unpack_from("<I", b, i)[0] for i in range(0, 32, 4)]
                stp = any((x & 0xFFE07FFF) == 0xA9807BFD for x in w)
                pac = w[0] == 0xD503233F
                sub = any((x & 0xFFC003FF) == 0xD10003FF for x in w)
                note = []
                if pac:
                    note.append("PACIASP")
                if stp:
                    note.append("STP x29,x30")
                if sub:
                    note.append("SUB sp")
                print(f"    {label}: {b.hex(' ')}")
                print(f"        -> {' '.join(note) if note else 'NO prologue sig'}")
                for ins in list(md.disasm(b, fo))[:5]:
                    print(f"           {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
