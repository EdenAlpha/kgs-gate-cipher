"""What are a4 / a5 / a6?  Disassemble the POST sender and its header builder.

    sub-request vtable 0x98225a0
      [7] 0x7d03e10  header/body builder   (rejects NULL a4/a5/a6)
      [8] 0x7d04148  POST (self, url, body, body_len, a4, a5, a6,
                           out_body, out_len, cb, cb_arg)

x2..x7 are a4..a6 on entry to the builder, so every `str w4/x5/x6` and every
string literal it forms tells us what the three arguments are: cookies, a
header value, or something else.  String literals are resolved through the
adrp+add pair so the dump reads as words, not addresses.
"""
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\walk_post.txt"

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
    """Read a NUL-terminated string at a .rodata VA, or None."""
    for s in SEC:
        if s["addr"] <= va < s["addr"] + s["size"] and s["name"] != ".text":
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


def walk(va, before, after):
    lo = max(TVA, va - before)
    hi = min(TVA + TSZ, va + after)
    start = lo - (lo - va) % 4
    o = TOFF + (start - TVA)
    pend = {}
    for ins in md.disasm(d[o:o + (hi - start)], start):
        note = ""
        if ins.mnemonic == "adrp":
            try:
                pend[ins.address] = int(
                    ins.op_str.split(",")[1].strip().lstrip("#"), 16)
            except Exception:
                pass
        elif ins.mnemonic == "add" and (ins.address - 4) in pend:
            base = pend.pop(ins.address - 4)
            try:
                imm = int(ins.op_str.split(",")[-1].strip().lstrip("#"), 16)
                tgt = base + imm
                st = cstr(tgt)
                note = "  -> 0x%x" % tgt
                if st:
                    note += '  "%s"' % st
                pend[ins.address] = tgt
            except Exception:
                pass
        mark = "  <<< a4/a5/a6" if (
            ins.mnemonic in ("str", "stur", "stp", "sturh", "strh", "strb")
            and any(r in ins.op_str for r in ("w4", "x4", "w5", "x5", "x6", "x6"))
        ) else ""
        say("  0x%08x  %-8s %-44s%s%s"
            % (ins.address, ins.mnemonic, ins.op_str, note, mark))


for name, va, before, after in (
        ("vtable[7] header/body builder  0x7d03e10", 0x7D03E10, 0, 0x400),
        ("POST sender  0x7d04148", 0x7D04148, 0, 0x340),
):
    say("=" * 78)
    say(name)
    say("=" * 78)
    walk(va, before, after)
    say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
