#!/usr/bin/env python3
"""Recover the real relocation data with LIEF.

The loader needs (offset, sym, rtype, addend) for every relocation.  The ELF
carries its R_AARCH64_RELATIVE entries in **Android packed relocations**
(DT_ANDROID_RELA / DT_ANDROID_RELASZ), which is why a plain .rela.dyn walk
found nothing and every vtable slot read as zero.

LIEF decodes APS2 out of the box.  Nothing here is hand-rolled.
"""
from __future__ import annotations

import os
import sys

import lief
import numpy as np

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "apk_lab", "analysis")
VADDR = 0x97D4448        # the vtable the command ctor installs


def main() -> int:
    print("[reloc] loading ELF with lief ...", flush=True)
    b = lief.parse(SO)
    relocs = list(b.relocations)
    print(f"[reloc] lief reports {len(relocs):,} relocations", flush=True)

    from collections import Counter
    kinds = Counter(str(r.type) for r in relocs)
    for k, n in kinds.most_common(10):
        print(f"    {k:40s} {n:,}")
    # show the integer codes so the loader's `rtype == 1027` check matches
    codes = Counter(int(r.type) for r in relocs)
    print("  integer codes:", {hex(k): v for k, v in codes.items()})

    offs, syms, rtypes, adds = [], [], [], []
    # the loader keys on the real ELF codes (rtype == 1027 is RELATIVE)
    ELF_CODE = {"TYPE.AARCH64_RELATIVE": 1027,
                "TYPE.AARCH64_ABS64": 257,
                "TYPE.AARCH64_GLOB_DAT": 1025,
                "TYPE.AARCH64_JUMP_SLOT": 1026}
    for r in relocs:
        s = r.symbol
        name = ""
        if s is not None:
            try:
                name = s.name or ""
            except Exception:
                name = ""
        offs.append(int(r.address))
        rtypes.append(ELF_CODE.get(str(r.type), int(r.type)))
        adds.append(int(r.addend))
        syms.append(name[:64])          # mangled names can be 100s of chars

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, "packed_relocs.npz")
    np.savez(out,
             offset=np.array(offs, dtype="<u8"),
             sym=np.array(syms, dtype=object).astype(str),
             rtype=np.array(rtypes, dtype="<u8"),
             addend=np.array(adds, dtype="<i8"))
    print(f"[reloc] wrote {out}  {os.path.getsize(out):,} bytes", flush=True)

    # ---- prove it: rebuild the vtable the command ctor uses ------------
    image = {}
    for off, rt, ad in zip(offs, rtypes, adds):
        if rt == 1027:          # R_AARCH64_RELATIVE
            image[off] = ad
    print(f"\n[reloc] R_AARCH64_RELATIVE entries: {len(image):,}", flush=True)
    print(f"[reloc] vtable {VADDR:#x} recovered slots:", flush=True)
    for i in range(8):
        v = image.get(VADDR + 8 * i)
        print(f"   [{i}] {v and hex(v) or '(none)'}", flush=True)

    have = sum(1 for i in range(32) if VADDR + 8 * i in image)
    print(f"\n[reloc] vtable slots recoverable: {have}/32", flush=True)
    return 0 if have else 1


if __name__ == "__main__":
    sys.exit(main())
