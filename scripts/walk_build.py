"""Disassemble the build/sign/send neighbourhood function by function.

header_reads.py showed the request sender does, in order:

    0x7b2e3b4  bl 0x7b2ef44   x0=[x20+8], x1=&local buffer   build body
    0x7b2e448  bl 0x7b2ef88   x1=&header name, x2=&value     set header
    0x7b2e46c  bl 0x7b38a44                                  sign
    0x7b2e4ac  blr x8         (vtable+0x20)                   send

So the encryption, if it happens on the client, has to occur inside one of
0x7b2ef44 or 0x7b2ef88 -- between "build body" and "sign".  Neither has ever
been disassembled: an earlier attempt took 128 instructions from 0x7b2ef44,
which simply ran past the end of that function and swallowed 0x7b2ef88 with it,
making it look call-free.

This walks the region from real function boundary to real boundary (each ends
in a plain `ret`) and prints every call with its resolved .rela.plt name, plus
every string the code materialises, so the roles can be read off directly.
"""
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\walk_cipher.txt"

d = open(SO, "rb").read()
FL = len(d)
DELTA = 0x4000
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = []


def say(s=""):
    out.append(str(s))


def _delta(va):
    if va >= 0x9906CC0:
        return 0xC000
    if va >= 0x8B75140:
        return 0x8000
    if va >= 0x28293C0:
        return 0x4000
    return 0x0


def word(va):
    o = va - _delta(va)
    if 0 <= o + 4 <= FL:
        return struct.unpack_from("<I", d, o)[0]
    return None


def read_str(va, n=56):
    o = va - _delta(va)
    if 0 <= o < FL:
        b = d[o:o + n]
        e = b.find(b"\x00")
        if e >= 0:
            b = b[:e]
        if b and all(0x20 <= c < 0x7F for c in b):
            return repr(b.decode("ascii"))
        if b:
            return "<%d bytes> %s" % (len(b), b[:16].hex())
        return "<zeroed>"
    return "<not file-backed>"


# --------------------------------------------------------- PLT symbol names --
e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def sec(i):
    return struct.unpack_from("<IIQQQQIIQQ", d, e_shoff + i * e_shentsize)


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


RET = 0xD65F03C0


def func_end(start):
    """First plain `ret` at or after start, scanned word by word."""
    va = start & ~3
    while True:
        w = word(va)
        if w is None:
            return va
        if w == RET:
            return va
        va += 4


def run(start, stop_at):
    insns = list(md.disasm(d[start - DELTA:stop_at - DELTA], start))
    if not insns:
        say("  (nothing decoded at 0x%x)" % start)
        return
    say("  instructions: %d   (0x%x .. 0x%x)"
        % (len(insns), insns[0].address, insns[-1].address))
    say("  --- calls ---")
    pending = {}
    calls = 0
    for i, ins in enumerate(insns):
        if ins.mnemonic == "adrp":
            try:
                page = int(ins.op_str.split(",")[1].strip().lstrip("#"), 16)
                pending[ins.address] = page
            except Exception:
                pass
        elif ins.mnemonic == "add" and (ins.address - 4) in pending:
            page = pending.pop(ins.address - 4)
            try:
                imm = int(ins.op_str.split(",")[2].strip().lstrip("#"), 16)
                say("      [str] 0x%08x -> 0x%08x  %s"
                    % (ins.address, page + imm, read_str(page + imm)))
            except Exception:
                pass
        if ins.mnemonic in ("bl", "blr"):
            calls += 1
            nm = None
            if ins.mnemonic == "bl":
                try:
                    nm = plt_name(int(ins.op_str.lstrip("#"), 16))
                except Exception:
                    pass
            tag = ("   PLT: %s" % nm) if nm else ""
            say("      0x%08x %s %s%s" % (ins.address, ins.mnemonic,
                                          ins.op_str, tag))
            say("            setup: %s"
                % "; ".join("%s %s" % (c.mnemonic, c.op_str)
                            for c in insns[max(0, i - 3):i]))
    if not calls:
        say("      (no bl / blr at all)")
    say("  --- full listing ---")
    for ins in insns:
        say("      0x%08x  %-7s %s" % (ins.address, ins.mnemonic, ins.op_str))
    say("")


say("=" * 78)
say("WALK OF THE BUILD -> SIGN -> SEND REGION")
say("=" * 78)

for start in (0x7B2D094, 0x7B2CA78, 0x7B2D144, 0x7B2CE00):
    end = start + 0x200
    say("")
    say("-" * 78)
    say("FUNCTION 0x%08x .. 0x%08x   (window)" % (start, end))
    say("-" * 78)
    run(start, end)

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
