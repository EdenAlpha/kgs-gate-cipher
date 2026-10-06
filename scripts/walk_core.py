"""Disassemble the Blowfish core 0x7b2d404 (encrypt) and 0x7b2d794 (decrypt).

Why this one and not another scan
---------------------------------
Every layer above it is now settled from code: Blowfish-CBC, PKCS#7 at block 8,
56-byte Key A, IV = body[0:8].  And yet every candidate decrypts to 0/42 valid
padding, so one of two assumptions is wrong: the key, or the key schedule.

The key schedule 0x7b2db24 calls the core as

    xor  P[i] ^= key_word              (18 words, obj+8 .. obj+0x4c)
    str  xzr, [sp]                     # zero the two halves
    bl   0x7b2d404                     # core(obj, sp+4, sp)
    stp  ... -> P[0], P[1]
    ... repeated, input read back from sp each time

Textbook Blowfish instead does P[i],P[i+1] = enc(P[i], P[i+1]), i.e. the input
is the freshly key-XORed P words, not a zeroed stack slot.  If the core reads
its input from *x1/*x2, this schedule throws the key away and the cipher is
independent of it -- which would exactly explain a 0/42 result for every key
tried.  If instead the core pulls its input from the object, the schedule is
standard and the fault lies elsewhere.

So the question this script answers is: does 0x7b2d404 read its two input words
from the registers it is handed, or from the object?  The answer decides whether
the recovered key is being used at all.
"""
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\walk_core.txt"

d = open(SO, "rb").read()

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
    SEC.append({"name": nm, "addr": s[3], "off": s[4], "size": s[5]})

TEXT = [s for s in SEC if s["name"] == ".text"][0]
TVA, TSZ, TOFF = TEXT["addr"], TEXT["size"], TEXT["off"]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = []


def say(s=""):
    out.append(str(s))


def walk(va, before, after, stop_at_ret=True):
    lo = max(TVA, va - before)
    hi = min(TVA + TSZ, va + after)
    start = lo - (lo - va) % 4
    o = TOFF + (start - TVA)
    pend = {}
    started = False
    for ins in md.disasm(d[o:o + (hi - start)], start):
        mark = ""
        if ins.mnemonic == "adrp":
            try:
                pend[ins.address] = int(
                    ins.op_str.split(",")[1].strip().lstrip("#"), 16)
            except Exception:
                pass
        elif ins.mnemonic == "add" and (ins.address - 4) in pend:
            p = pend.pop(ins.address - 4)
            try:
                im = int(ins.op_str.split(",")[2].strip().lstrip("#"), 16)
                mark = "   -> 0x%x" % (p + im)
            except Exception:
                pass
        if ins.mnemonic in ("bl", "b", "blr"):
            mark += "   <"
        if ins.address == va:
            mark += "   <<<< ENTRY"
            started = True
        if not started:
            continue
        say("      0x%08x  %-8s %-42s%s"
            % (ins.address, ins.mnemonic, ins.op_str, mark))
        if stop_at_ret and ins.mnemonic == "ret":
            say("      <<<<")
            break


for va, label in ((0x7B2D404, "Blowfish core (encrypt) -- called by key schedule "
                               "and by vtable[0] 0x7b2e17c"),
                  (0x7B2D794, "Blowfish core (decrypt) -- called by vtable[1] "
                              "0x7b2e244")):
    say("=" * 78)
    say("%s   @ 0x%x" % (label, va))
    say("=" * 78)
    walk(va, 0, 0x500)
    say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
