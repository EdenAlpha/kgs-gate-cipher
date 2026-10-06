"""Find every caller of the sub-request POST sender and read what it passes
in x4/x5/x6 -- the arguments Ghidra names a4/a5/a6.

    0x7d04148  POST (self, url, body, body_len, a4, a5, a6, ...)
    0x7d03e10  header/body builder (rejects a4/a5/a6 == NULL)

A raw BL scan is used instead of a capstone sweep over the 103 MB .text: BL is
the fixed opcode 100101 with a 26-bit signed word offset, so one pass of
struct.unpack_from over .text finds them all in seconds.
"""
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\xref_post.txt"

TARGETS = {0x7D04148: "POST sender", 0x7D03E10: "header builder"}

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


def cstr(va):
    for s in SEC:
        if s["name"] != ".text" and s["addr"] <= va < s["addr"] + s["size"]:
            o = s["off"] + (va - s["addr"])
            if 0 <= o < len(d):
                end = d.find(b"\x00", o)
                raw = d[o:end if 0 < end - o < 400 else o + 64]
                try:
                    t = raw.decode("ascii")
                except Exception:
                    return None
                if t.isprintable() and len(t) >= 3:
                    return t
            return None
    return None


# ------------------------------------------------------- raw BL scan --------
hits = []
base = TOFF
for off in range(0, TSZ - 3, 4):
    w = struct.unpack_from("<I", d, base + off)[0]
    if w & 0xFC000000 != 0x94000000:        # BL
        continue
    imm = w & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    tgt = TVA + off + imm * 4
    if tgt in TARGETS:
        hits.append((TVA + off, tgt))

say("BL scan over .text (%d bytes): %d call sites" % (TSZ, len(hits)))
for t in TARGETS:
    say("  target 0x%x  %s" % (t, TARGETS[t]))
say("")

# ------------------------------------------------- context around each -----
for va, tgt in sorted(hits):
    say("=" * 78)
    say("caller 0x%x  ->  0x%x %s" % (va, tgt, TARGETS[tgt]))
    say("=" * 78)
    lo = va - 0x70
    start = lo - (lo % 4)
    o = TOFF + (start - TVA)
    pend, ctx = {}, []
    for ins in md.disasm(d[o:o + 0x90], start):
        note = ""
        if ins.mnemonic == "adrp":
            try:
                pend[ins.address] = int(
                    ins.op_str.split(",")[1].strip().lstrip("#"), 16)
            except Exception:
                pass
        elif ins.mnemonic == "add" and (ins.address - 4) in pend:
            baseva = pend.pop(ins.address - 4)
            try:
                imm = int(ins.op_str.split(",")[-1].strip().lstrip("#"), 16)
                tgt = baseva + imm
                pend[ins.address] = tgt
                st = cstr(tgt)
                if st:
                    note = '  "%s"' % st
            except Exception:
                pass
        line = "  0x%08x  %-8s %-40s%s" % (ins.address, ins.mnemonic,
                                           ins.op_str, note)
        if ins.address == va:
            line = "  0x%08x  %-8s %-40s%s   <<< CALL" % (
                ins.address, ins.mnemonic, ins.op_str, note)
        ctx.append(line)
    say("\n".join(ctx[-30:]))
    say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
