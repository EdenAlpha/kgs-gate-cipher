"""Find the callers that hand the encryption key to the context constructor.

walk_init.txt decoded the context creator at 0x7b2c9a4:

    Context* get_or_create(const char* data, int len) {
        if (*0xa4a98d8) return *0xa4a98d8;     // already built
        auto* c = new Context;                 // 0x38 bytes, vtable 0x981a590
        c->field8.assign(data, len);           // <-- the key, passed IN
        *0xa4a98d8 = c;
        return c;
    }

So the key is an argument, not a constant.  Whoever calls 0x7b2c9a4 owns it.
This walks the whole binary for `bl`/`b` to that address (and to the
equivalent constructor for the second context, global 0xa4a98d0), then prints
each caller's prologue, its strings, and every call it makes -- so the source
of `data`/`len` becomes readable directly.
"""
import struct

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\find_callers.txt"

# 0x7d65e00 = the XOR decoder that turns obj+8 into the key string
TARGETS = [0x7D65E00]

d = open(SO, "rb").read()
FL = len(d)

e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def sec(i):
    return struct.unpack_from("<IIQQQQIIQQ", d, e_shoff + i * e_shentsize)


shstr = sec(e_shstrndx)
SECS = []
for i in range(e_shnum):
    s = sec(i)
    nm = d[shstr[4] + s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    SECS.append({"name": nm, "flags": s[2], "addr": s[3], "off": s[4],
                 "size": s[5], "entsize": s[9]})
by = {s["name"]: s for s in SECS}
text = by[".text"]

raw = d[text["off"]:text["off"] + text["size"]]
if len(raw) % 4:
    raw += b"\x00" * (4 - len(raw) % 4)
w = np.frombuffer(raw, dtype="<u4")
base = text["addr"]

# ------------------------------------------------------- bl / b to targets ---
# B   : 000101 imm26            mask 0xFC000000 == 0x14000000
# BL  : 100101 imm26            mask 0xFC000000 == 0x94000000
is_br = (w & 0xFC000000) == 0x14000000
is_bl = (w & 0xFC000000) == 0x94000000
i_br = np.nonzero(is_br | is_bl)[0]
imm = w[i_br].astype(np.int64) & 0x03FFFFFF
imm = np.where(imm >= (1 << 25), imm - (1 << 26), imm)
pc = base + i_br.astype(np.int64) * 4
dest = pc + (imm << 2)

print("branches found: %d" % len(i_br))
callers = []
for i, t in enumerate(TARGETS):
    m = np.nonzero(dest == t)[0]
    print("  -> 0x%x : %d sites" % (t, len(m)))
    for q in m:
        j = int(i_br[q])
        callers.append((int(base + j * 4), t, bool(is_bl[j])))

print("total call sites: %d" % len(callers))

# ------------------------------------------------------------- helpers -------
plt, rela = by[".plt"], by[".rela.plt"]
dynsym, dynstr = by[".dynsym"], by[".dynstr"]


def sym_name(i):
    off = dynsym["off"] + i * dynsym["entsize"]
    st_name = struct.unpack_from("<I", d, off)[0]
    b = dynstr["off"] + st_name
    return d[b:d.index(b"\x00", b)].decode("ascii", "replace")


reloc = {}
for i in range(rela["size"] // 24):
    _o, r_info, _ = struct.unpack_from("<QQq", d, rela["off"] + i * 24)
    reloc[i] = sym_name(r_info >> 32)


def plt_name(va):
    if va < plt["addr"] or va > plt["addr"] + plt["size"]:
        return None
    return reloc.get((va - plt["addr"] - 0x20) // 16)


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


def read_str(va, n=72):
    o = va - _delta(va)
    if 0 <= o < FL:
        b = d[o:o + n]
        e = b.find(b"\x00")
        if e >= 0:
            b = b[:e]
        if b and all(0x20 <= c < 0x7F for c in b):
            return repr(b.decode("ascii"))
        if b:
            return "<%d bytes> %s" % (len(b), b[:24].hex())
        return "<zeroed>"
    return "<not file-backed>"


RET = 0xD65F03C0
PROLOGUE = {0xD1000000: "sub sp", 0xA9000000: "stp",
            0xF8000000: "str(pre)", 0xD1800000: ""}


def func_start(site, back=0x20000):
    """Back up to the last plain ret, then skip the guard clause."""
    for va in range(site & ~3, (site & ~3) - back, -4):
        if word(va) == RET:
            return va + 4
    return None


md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = []


def say(s=""):
    out.append(str(s))


say("=" * 78)
say("CALLERS OF THE CONTEXT CONSTRUCTOR (the key holder)")
say("=" * 78)
for va, tgt, is_bl in sorted(callers):
    say("  0x%08x  %s -> 0x%x" % (va, "bl " if is_bl else "b  ", tgt))

for va, tgt, is_bl in sorted(callers):
    st = func_start(va)
    say("")
    say("=" * 78)
    say("CALL SITE 0x%08x -> 0x%x" % (va, tgt))
    say("=" * 78)
    if st is None:
        say("  no enclosing function found")
        continue
    say("  function start 0x%x  (%d bytes before)" % (st, va - st))
    end = min(va + 0x100, st + 0x900)
    insns = list(md.disasm(d[st - 0x4000:end - 0x4000], st))
    say("  --- calls / strings ---")
    pend = {}
    for i, ins in enumerate(insns):
        if ins.mnemonic == "adrp":
            try:
                pend[ins.address] = int(
                    ins.op_str.split(",")[1].strip().lstrip("#"), 16)
            except Exception:
                pass
        elif ins.mnemonic == "add" and (ins.address - 4) in pend:
            page = pend.pop(ins.address - 4)
            try:
                imm_ = int(ins.op_str.split(",")[2].strip().lstrip("#"), 16)
                say("      [str] 0x%08x -> 0x%08x  %s"
                    % (ins.address, page + imm_, read_str(page + imm_)))
            except Exception:
                pass
        if ins.mnemonic in ("bl", "blr"):
            nm = None
            if ins.mnemonic == "bl":
                try:
                    nm = plt_name(int(ins.op_str.lstrip("#"), 16))
                except Exception:
                    pass
            say("      0x%08x %s %s%s"
                % (ins.address, ins.mnemonic, ins.op_str,
                   ("   PLT: %s" % nm) if nm else ""))
            say("            setup: %s"
                % "; ".join("%s %s" % (c.mnemonic, c.op_str)
                            for c in insns[max(0, i - 4):i]))
    say("  --- window around the call (arguments being set up) ---")
    for ins in insns:
        if abs(ins.address - va) <= 0x40:
            say("      0x%08x  %-7s %s%s"
                % (ins.address, ins.mnemonic, ins.op_str,
                   "   <== CALL" if ins.address == va else ""))

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
