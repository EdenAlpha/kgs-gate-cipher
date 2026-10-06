#!/usr/bin/env python3
"""Find the code that references the `Def_Online_gRPC_*` key literals.

Shape of the argument is what has to change, not the guesswork: the two offsets
recorded as the int and string getters are both std::string constructors (the
SSO compare at 0x17, the `2*len|is_long` size byte, the `operator new` for the
long form, the {size, ptr} store), so neither can be overriding an int config
value. To find the real int accessor without guessing, resolve the *call site*
instead.

`Def_Online_gRPC_insecure` is a string in .rodata at 0xc023be. Code referring to
it does `adrp xN, #<page>` then `add xN, xN, #<0x3be>`. Both are A64
instructions with fixed bit patterns, so a byte-level scan finds them in a
second or two instead of disassembling 160 MB. The call immediately after the
add is the accessor to hook.

A64 `add (immediate)`, 64-bit form:
    sf op S 10001 sh imm12 Rn Rd
    31 30 29 28..24 23 22..11 10..5 4..0
with sf=1, op=0, S=0, sh=0 for a plain 12-bit add.
"""
import struct
import sys

BIN = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"

ADD_MASK = ((1 << 31) | (1 << 30) | (1 << 29) | (0x1F << 24) | (1 << 23)
            | (0xFFF << 11) | (0x3F << 5) | 0x1F)
ADD_FIX = (1 << 31) | (0b10001 << 24)

TARGETS = {
    0xc023be: "Def_Online_gRPC_insecure (int)",
    0xba2aff: "Def_Online_gRPC_server_address (string)",
    0x9c69c1: "Def_Online_gRPC_server_path (string)",
    0xb68de6: "Def_Online_gRPC_server_port (int)",
}


def decode_adrp(w):
    """Return (Rd, page) for an ADRP, else None."""
    if (w >> 24) & 0x9F != 0x90:
        return None
    immlo = (w >> 29) & 0x3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return w & 0x1F, imm << 12


def main():
    data = open(BIN, "rb").read()
    print("file %d bytes (%.1f MB)" % (len(data), len(data) / 1048576.0))

    # For each target, the low 12 bits are the ADD's imm12 and the high 20 bits
    # are the page. Prefilter on the two high bytes of the ADD word, which are
    # fully determined by imm12:  b3=0x91, b2=(imm12>>5)&0x7f  (little endian).
    hits = []
    for tgt, name in sorted(TARGETS.items()):
        imm12 = tgt & 0xFFF
        pat = bytes([0x91, (imm12 >> 5) & 0x7F])
        pos = 0
        seen = 0
        while True:
            i = data.find(pat, pos)
            if i < 0 or i + 4 > len(data):
                break
            pos = i + 1
            w = struct.unpack_from("<I", data, i)[0]
            if (w & ADD_MASK) != (ADD_FIX | (imm12 << 11)):
                continue
            if i < 4:
                continue
            w2 = struct.unpack_from("<I", data, i - 4)[0]
            d = decode_adrp(w2)
            if not d:
                continue
            rdn, page = d
            rn = (w >> 5) & 0x1F
            rd = w & 0x1F
            if rdn != rn:
                continue
            # The ADRP yields a VA while the target table holds file offsets.
            # The low 12 bits -- and so imm12 -- are identical either way, so
            # accept the reference and report the address it computes to rather
            # than assuming which of the two is in hand.
            computed = page + imm12
            seen += 1
            hits.append((i, rn, rd, tgt, name, w2, computed))
        print("  %-46s imm12=%#05x pattern=%s -> %d ref(s)"
              % (name, imm12, pat.hex(), seen))

    print("\ntotal key references: %d" % len(hits))
    if not hits:
        print("  none -- the keys are not referenced by an adrp/add pair.")
        print("  they may live in a table reached by index instead.")
        return 0

    import subprocess
    tool = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work"
            r"\disasm_range.py")
    for off, rn, rd, tgt, name, w2, computed in hits:
        r = subprocess.run([sys.executable, tool, hex(off - 4), hex(off + 0x60),
                            "26"], capture_output=True, text=True, timeout=180)
        delta = computed - tgt
        print("\n=== %s  literal(file)=%#x  adrp+add computes VA %#x  (delta %s) ==="
              % (name, tgt, computed,
                 ("+%#x" % delta) if delta else "0"))
        for line in r.stdout.split("\n"):
            if "0x" in line:
                mark = "  >>" if line.strip().startswith("0x%x" % off) else "    "
                print(mark + " " + line.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
