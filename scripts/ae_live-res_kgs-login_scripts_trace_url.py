"""1. Trace how the URL (x21) is produced inside HTTP POST 0x7d038c8.
   2. Scan the image for stored function pointers to the key routines.
   3. Resolve string literals referenced from 0x7d038c8."""
import os
import re
import struct
import sys

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_VADDR, TEXT_OFF, TEXT_SIZE = 0x28293C0, 0x28253C0, 0x630BE48

HTTP_POST = 0x7D038C8
END = 0x7D03D60                     # past the three setopt(URL) sites

TARGETS = {
    0x7D038C8: "HTTP_POST",
    0x7D01830: "HTTP_POST_caller_A",
    0x7D159F0: "HTTP_POST_caller_B",
    0x767EAF0: "serverenv_builder_A",
    0x767F6E4: "serverenv_builder_B",
    0x767CEEC: "serverenv_branch_A",
    0x767CEFC: "serverenv_branch_B",
    0x7D0C06C: "GateInfo_sender",
    0x7DC7164: "bootstrap_SM",
    0x50D62BC: "curl_wrapper_caller",
}


def cstr(raw, addr, n=96):
    off = addr
    if 0 <= off < len(raw):
        b = raw[off:off + n]
        i = b.find(b"\0")
        if 0 < i < n:
            s = b[:i]
            if all(32 <= c < 127 for c in s) and len(s) >= 3:
                return s.decode("ascii")
    return None


def main():
    with open(SO, "rb") as f:
        raw = f.read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    print(f"=== disassembly of HTTP POST 0x{HTTP_POST:x} .. 0x{END:x} ===")
    off = HTTP_POST - TEXT_VADDR + TEXT_OFF
    n = (END - HTTP_POST) // 4
    interesting = []
    adrp_reg = {}
    for ins in md.disasm(raw[off:off + n * 4], HTTP_POST):
        line = f"  0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}"
        keep = False
        if ins.mnemonic == "adrp":
            rd = ins.op_str.split(",")[0].strip()
            adrp_reg[rd] = int(ins.op_str.split("#")[-1], 16)
            keep = True
        elif ins.mnemonic == "add" and ", #" in ins.op_str:
            parts = [p.strip() for p in ins.op_str.split(",")]
            rd = parts[0]
            if rd in adrp_reg and "#" in ins.op_str:
                try:
                    imm = int(parts[-1].lstrip("#"), 16)
                    va = adrp_reg[rd] + imm
                    s = cstr(raw, va)
                    if s:
                        line += f"        ; -> str@{va:#x} {s!r}"
                        keep = True
                except Exception:
                    pass
        if ins.mnemonic in ("mov", "ldr", "add", "adrp", "adr") and \
                ins.op_str.startswith("x21"):
            keep = True
        if "x21" in ins.op_str and ins.mnemonic in ("mov", "ldr", "add"):
            keep = True
        if ins.mnemonic == "bl" and "#0x6886498" in ins.op_str:
            keep = True
        if keep:
            interesting.append(line)
    for l in interesting:
        print(l)

    # ---- function pointer scan -------------------------------------
    print(f"\n=== stored function pointers ===")
    for va, name in TARGETS.items():
        pat = struct.pack("<Q", va)
        hits = []
        start = 0
        while True:
            i = raw.find(pat, start)
            if i < 0:
                break
            hits.append(i)
            start = i + 1
            if len(hits) > 12:
                break
        print(f"  {name:26} {va:#012x}  refs={len(hits)} "
              f"{[hex(h) for h in hits[:8]]}")
        for h in hits[:4]:
            nb = cstr(raw, h - 64, 64) or cstr(raw, h + 8, 64)
            if nb:
                print(f"        near {h:#x}: {nb!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
