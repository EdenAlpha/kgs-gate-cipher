#!/usr/bin/env python3
"""dis_range.py <so> <va_hex> <len_hex> -- disassemble, annotating string
loads (STR), pointer-table slots (PTR) and x0 receiver arithmetic.

Rebuilt 2026-10-10 (original destroyed by temp cleanup).
NOTE: third argument is LENGTH in hex, not an end address.
"""

import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs  # noqa

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
from xref2 import Elf, adrpf, addimm        # noqa: E402
from dump_keys import cstr, is_print        # noqa: E402


def main():
    path, va, ln = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
    e = Elf(path)
    _, _, _, tv, to, ts = e.sec(".text")
    data = e.read(to, ts)
    i = va - tv
    end = min(len(data), i + ln)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    while i < end:
        w = struct.unpack_from("<I", data, i)[0]
        note = ""
        rd, delta = adrpf(w)
        if rd is not None:
            page = ((tv + i) & ~0xFFF) + delta
            tgt = None
            # look ahead for add xd, x{rd}, #imm -> exact target
            for k in range(4, 24, 4):
                if i + k >= len(data):
                    break
                w2 = struct.unpack_from("<I", data, i + k)[0]
                add = addimm(w2)
                if add is None:
                    continue
                rd2, rn2, imm = add
                if rd2 is not None and rn2 == rd:
                    tgt = page + imm
                    break
            if tgt is None:
                tgt = page
            s = cstr(e, tgt) if tgt is not None else None
            if s is not None and is_print(s):
                show = s if len(s) <= 70 else s[:67] + "..."
                note = "; STR %#x '%s'" % (tgt, show)
            else:
                note = "; PTR %#x" % tgt
        else:
            add = addimm(w)
            if add is not None and add[0] == 0:
                note = "; <== RECEIVER off=%#x" % add[2]
            elif w == 0xAA0003E0:                       # mov x0, sp
                note = "; <== RECEIVER off=0x0"

        pc = tv + i
        text = None
        for ins in md.disasm(bytes(data[i:i + 4]), pc):
            text = "%-8s %s" % (ins.mnemonic, ins.op_str)
        if text is None:
            text = ".int    0x%08x" % w
        line = "0x%08x  %s" % (pc, text)
        if note:
            line = "%s  %s" % (line.ljust(44), note)
        print(line)
        i += 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
