"""The unread tail of FUN_07c38a44.

We established this function is 576 instructions (0x7b38a44 .. 0x7b39344) but
only ever examined the first ~258, stopping at 0x7b38e5c.  Two facts say the
tail matters:

  * the string 'pes-custom-encrypt' (the header naming the cipher) is
    referenced at 0x7b39120 -- inside THIS function
  * it also owns the 'sign=' literal, so it builds the request wholesale

Prints, for the unread half only:
  - every bl /blr with its resolved .rela.plt name (and a crypto flag)
  - every adrp+add pair (string/table addresses being formed)
  - a full instruction dump around 0x7b39120, to see the header reference
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\fun_tail.txt"

d = open(SO, "rb").read()
DELTA = 0x4000
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = []


def say(s=""):
    out.append(str(s))


# --------------------------------------------------------- PLT symbol names --
e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def sec(i):
    o = e_shoff + i * e_shentsize
    return struct.unpack_from("<IIQQQQIIQQ", d, o)


shstr = sec(e_shstrndx)
secs = []
for i in range(e_shnum):
    s = sec(i)
    nm = d[shstr[4] + s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    secs.append({"name": nm, "addr": s[3], "off": s[4], "size": s[5],
                 "entsize": s[9]})
by = {s["name"]: s for s in secs}
plt, rela = by[".plt"], by[".rela.plt"]
dynsym, dynstr = by[".dynsym"], by[".dynstr"]


def sym_name(idx):
    off = dynsym["off"] + idx * dynsym["entsize"]
    st_name = struct.unpack_from("<I", d, off)[0]
    b = dynstr["off"] + st_name
    return d[b:d.index(b"\x00", b)].decode("ascii", "replace")


reloc = {}
for i in range(rela["size"] // 24):
    r_offset, r_info, _ = struct.unpack_from("<QQq", d, rela["off"] + i * 24)
    reloc[i] = sym_name(r_info >> 32)


def plt_name(va):
    if va < plt["addr"] or va > plt["addr"] + plt["size"]:
        return None
    return reloc.get((va - plt["addr"] - 0x20) // 16)


FUNC = 0x7B38A44
START = 0x7B38E60          # first byte we have NOT yet read
END = FUNC + 576 * 4        # 0x7b39344
insns = list(md.disasm(d[START - DELTA:END - DELTA], START))

say("=" * 78)
say("UNREAD TAIL OF FUN_07c38a44   0x%x .. 0x%x  (%d instructions)"
    % (START, END, len(insns)))
say("=" * 78)
say("")
say("--- calls ---")
prev = {}
for i in insns:
    if i.mnemonic in ("bl", "blr"):
        nm = None
        if i.mnemonic == "bl":
            try:
                tgt = int(i.op_str.lstrip("#"), 16)
                nm = plt_name(tgt)
            except Exception:
                pass
        idx = insns.index(i)
        ctx = "; ".join("%s %s" % (c.mnemonic, c.op_str)
                        for c in insns[max(0, idx - 3):idx])
        tag = ("   PLT: %s" % nm) if nm else ""
        say("  0x%08x %s %s%s" % (i.address, i.mnemonic, i.op_str, tag))
        say("        setup: %s" % ctx)
    if i.mnemonic == "adrp":
        prev[i.address] = i
    if i.mnemonic == "add" and i.address - 4 in prev:
        page = prev[i.address - 4].op_str.split(",")[1].strip()
        say("  [str] 0x%08x  adrp %s ; %s   -> see below"
            % (i.address, page, i.op_str))

say("")
say("--- full dump around the pes-custom-encrypt xref 0x7b39120 ---")
for i in insns:
    if abs(i.address - 0x7B39120) <= 0x70:
        mark = "   <== header xref" if i.address == 0x7B39120 else ""
        say("  0x%08x  %-8s %s%s" % (i.address, i.mnemonic, i.op_str, mark))

say("")
say("--- every ret (function ends / inlined tails) ---")
for i in insns:
    if i.mnemonic == "ret":
        say("  0x%08x" % i.address)

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
