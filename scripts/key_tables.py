"""Dump the key-derivation function and the two .rodata blobs it consumes.

find_ctx.txt located the generator at 0x7d64fb0.  Two XOR loops:

  loop A (0x7d65024 .. 0x7d65078)   cmp x8, #0x38   -> 56 bytes into bufA
      x14 = 0x9823af0
      src  = *(x14 + 8  + i)
      T1   = *(x14 + 0x50 + idx1)
      T2   = *(x14 + 0x59 + idx2)
      out[i] = src ^ T1 ^ T2 ^ 0x75

  loop B (0x7d650c8 .. 0x7d6511c)   cmp x8, #0x20   -> 32 bytes into bufB
      x14 = 0x9823ba0
      src  = *(x14 + 8  + i)
      T1   = *(x14 + 0x38 + idx1)
      T2   = *(x14 + 0x41 + idx2)

idx1 = i - 9*((i*57) >> 9)      == i mod 9   for the i in play
idx2 = i - 12*((i*171) >> 11)   == i mod 12

Loop A's multiplier constants are set before 0x7d65018 (outside the window we
have read), so this dumps the whole function first -- assuming anything about
them would be exactly the kind of guess that has already cost time.
"""
import struct

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\key_tables.txt"

FN_START = 0x7D64FB0
FN_END = 0x7D65144

BLOB_A = 0x9823AF0
BLOB_B = 0x9823BA0

d = open(SO, "rb").read()
FL = len(d)


def _delta(va):
    if va >= 0x9906CC0:
        return 0xC000
    if va >= 0x8B75140:
        return 0x8000
    if va >= 0x28293C0:
        return 0x4000
    return 0x0


def off(va):
    return va - _delta(va)


from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = []


def say(s=""):
    out.append(str(s))


def hexdump(va, n):
    o = off(va)
    b = d[o:o + n]
    for i in range(0, len(b), 16):
        row = b[i:i + 16]
        hx = " ".join("%02x" % c for c in row)
        asc = "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in row)
        say("  0x%08x  %-47s  |%s|" % (va + i, hx, asc))
    return b


say("=" * 78)
say("KEY DERIVATION FUNCTION 0x%x .. 0x%x" % (FN_START, FN_END))
say("=" * 78)
body = d[off(FN_START):off(FN_END)]
insns = list(md.disasm(body, FN_START))
say("instructions: %d" % len(insns))
say("")
pend = {}
for i, ins in enumerate(insns):
    mark = ""
    if ins.mnemonic == "adrp":
        try:
            pend[ins.address] = int(ins.op_str.split(",")[1].strip().lstrip("#"), 16)
        except Exception:
            pass
    elif ins.mnemonic == "add" and (ins.address - 4) in pend:
        page = pend.pop(ins.address - 4)
        try:
            imm = int(ins.op_str.split(",")[2].strip().lstrip("#"), 16)
            mark = "     -> 0x%x" % (page + imm)
        except Exception:
            pass
    say("  0x%08x  %-8s %-40s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))

say("")
say("=" * 78)
say("BLOB A  0x%x   (feeds loop A -> bufA, 56 bytes)" % BLOB_A)
say("=" * 78)
a = hexdump(BLOB_A, 0x70)

say("")
say("=" * 78)
say("BLOB B  0x%x   (feeds loop B -> bufB, 32 bytes)" % BLOB_B)
say("=" * 78)
b = hexdump(BLOB_B, 0x60)

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
