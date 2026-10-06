"""Resolve the cipher object's vtable and disassemble what it points at.

This is the last unknown in the chain.  The pieces established so far:

  encrypt_mode0 0x7b2cbb0
      init_cipher_state(stack_state, key, keylen)
      pad_then_transform(stack_state, data, len, out)
      out := state+0x4c (8-byte random IV)  ||  ciphertext

  transform 0x7b2ce94  (per 8-byte block)
      byte_swap -> cipher_obj.vtable[6] -> byte_swap
      and before the loop:  cipher_obj.vtable[4](key, keylen)   <- key schedule

  build_cipher_object 0x7b2d164 / 0x7b2e150
      new(0x1058 = 4184) = { vtable=0x981a6e0 (8 B)
                             working buffer 0x1048 = 4168 B   <- Blowfish P+S
                             u64 iv at +0x1050 }

4168 B is exactly P[18] + 4*S[256], and the .rodata constants at 0xc8d92c are
the pi-digit Blowfish tables landing on precisely 4168 B before a NUL.  So the
object layout and the table layout agree.  What this script does is read slot
[4] (key schedule), [6] (encrypt) and [7] (decrypt) out of 0x981a6e0 -- the
vtable that until now read as zeros, because .rela.dyn is an APS2 packed stream
-- and print them, so the algorithm is confirmed by its code rather than by the
coincidence of two sizes matching.

The APS2 decoder is kept in this file rather than imported, because it is short
and because a decoder you cannot see is a decoder you cannot trust.
"""
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\cipher_vtable.txt"

d = open(SO, "rb").read()

# ----------------------------------------------------------------- APS2 -----
def sleb128(buf, pos):
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    if shift < 64 and (b & 0x40):
        result -= 1 << shift
    return result, pos


RELA_OFF, RELA_SZ = 0x2ED270, 0x3DE65A
buf = d[RELA_OFF:RELA_OFF + RELA_SZ]
assert buf[:4] == b"APS2"
count0, pos = sleb128(buf, 4)
off0, pos = sleb128(buf, pos)

FLAG_INFO, FLAG_OFFDELTA, FLAG_ADDEND, FLAG_HAS_ADDEND = 1, 2, 4, 8
# group-field order established by unpack_aps2.py: OFFSET_DELTA, INFO, ADDEND
ORDER = (FLAG_OFFDELTA, FLAG_INFO, FLAG_ADDEND)

p, n, r_offset, r_addend = pos, 0, off0, 0
rel = {}
while p < len(buf):
    gsize, p = sleb128(buf, p)
    gflags, p = sleb128(buf, p)
    gval = {}
    for bit in ORDER:
        if gflags & bit:
            gval[bit], p = sleb128(buf, p)
    for _ in range(gsize):
        if gflags & FLAG_OFFDELTA:
            r_offset += gval[FLAG_OFFDELTA]
        else:
            delta, p = sleb128(buf, p)
            r_offset += delta
        if gflags & FLAG_INFO:
            r_info = gval[FLAG_INFO]
        else:
            r_info, p = sleb128(buf, p)
        if gflags & FLAG_HAS_ADDEND:
            if gflags & FLAG_ADDEND:
                r_addend += gval[FLAG_ADDEND]
            else:
                ad, p = sleb128(buf, p)
                r_addend += ad
        rel[r_offset & 0xFFFFFFFFFFFFFFFF] = r_addend & 0xFFFFFFFFFFFFFFFF
        n += 1
assert n == count0 and p == len(buf), (n, count0, p, len(buf))

# ------------------------------------------------------------- sections -----
e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def sec(i):
    return struct.unpack_from("<IIQQQQIIQQ", d, e_shoff + i * e_shentsize)


shstr = sec(e_shstrndx)
SEC = []
for i in range(e_shnum):
    s = sec(i)
    nm = d[shstr[4] + s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    SEC.append({"name": nm, "type": s[1], "flags": s[2], "addr": s[3],
                "off": s[4], "size": s[5]})

TEXT = [s for s in SEC if s["name"] == ".text"][0]
TVA, TSZ, TOFF = TEXT["addr"], TEXT["size"], TEXT["off"]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = []


def say(s=""):
    out.append(str(s))


def disasm(va, before, after):
    lo = max(TVA, va - before)
    hi = min(TVA + TSZ, va + after)
    start = lo - (lo - va) % 4
    o = TOFF + (start - TVA)
    pend = {}
    lines = []
    for ins in md.disasm(d[o:o + (hi - start)], start):
        mark = ""
        if ins.mnemonic == "adrp":
            try:
                pend[ins.address] = int(
                    ins.op_str.split(",")[1].strip().lstrip("#"), 16)
            except Exception:
                pass
        elif ins.mnemonic == "add" and (ins.address - 4) in pend:
            q = pend.pop(ins.address - 4)
            try:
                im = int(ins.op_str.split(",")[2].strip().lstrip("#"), 16)
                mark = "   -> 0x%x" % (q + im)
            except Exception:
                pass
        if ins.mnemonic in ("bl", "b"):
            try:
                t = int(ins.op_str.lstrip("#"), 16)
                mark = "   -> 0x%x" % t
            except Exception:
                pass
        lines.append((ins, mark))
    return lines


VT = 0x981A6E0
say("=" * 78)
say("CIPHER OBJECT VTABLE @ 0x%x  (built by 0x7b2e150)" % VT)
say("=" * 78)
slots = []
for i in range(16):
    k = VT + 8 * i
    v = rel.get(k)
    slots.append(v)
    say("  [%2d] +0x%03x  %s" % (i, 8 * i,
                                 ("0x%x" % v) if v else "(no relocation)"))
say("")
say("called from transform 0x7b2ce94 as:")
say("  slot [4] +0x20  key schedule(state+0x10 = key, state+0x48 = keylen)")
say("  slot [6] +0x30  encrypt (8-byte block, byte-swapped on either side)")
say("  slot [7] +0x38  decrypt")
say("")

NAMED = {
    0x7B2D354: "byte_swap_block", 0x7B2D398: "byte_swap_block",
}

for i in (0, 1, 2, 3, 4, 5, 6, 7, 8):
    v = slots[i]
    if not v:
        continue
    say("-" * 78)
    say("SLOT [%d] +0x%03x -> 0x%x" % (i, 8 * i, v))
    say("-" * 78)
    # start exactly at the entry point: a window opened before the address
    # lands in the *previous* function's epilogue and prints its `ret`,
    # which would misattribute the whole routine.  The window is deliberately
    # long and does not stop at the first `ret`, because these routines have
    # early-exit paths and a truncated listing hides the key schedule.
    for ins, mark in disasm(v, 0, 0x1200):
        say("      0x%08x  %-8s %-42s%s"
            % (ins.address, ins.mnemonic, ins.op_str, mark))
    say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
