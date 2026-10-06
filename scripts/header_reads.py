"""Find the code that READS the pes-custom-encrypt header onto a request.

Established: all six real cross-references to the literal 'pes-custom-encrypt'
are global constructors that copy it into .bss slots and register a destructor.
Two further "xrefs" (0x7ec024c, 0x7ecad64) turned out to be false positives --
they sit in protobuf reflection code and decode as plain movs.

So nothing in .text reads the literal.  The request builder must instead read
the .bss copy.  Those slots are known:

    0xa4a98e0  0xa4a9990  0xa4a9a08  0xa4a9a98  0xa4a9b30

A reference to any of them has to be adrp + add, so decode those pairs straight
out of the instruction words (no disassembler -- covers all 103 MB of .text)
and report each hit with its enclosing calls and neighbouring strings.  The
site that attaches the header to an outgoing request is where the encryption
is performed, so this is the shortest route to the key.
"""
import struct

import numpy as np

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\header_reads.txt"

d = open(SO, "rb").read()

# ------------------------------------------------------------- sections ----
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
    SECS.append({"name": nm, "addr": s[3], "off": s[4], "size": s[5]})
text = next(s for s in SECS if s["name"] == ".text")
print(".text va 0x%x off 0x%x size %d" % (text["addr"], text["off"], text["size"]))

raw = d[text["off"]:text["off"] + text["size"]]
if len(raw) % 4:
    raw += b"\x00" * (4 - len(raw) % 4)
w = np.frombuffer(raw, dtype="<u4")
n = len(w)

# --------------------------------------------------------- adrp + add -------
# ADRP  Xd, label      : 1 immlo(2) 10000 immhi(19) Rd      -> mask 0x9f000000
# ADD   Xd, Xn, #imm12 : 1 00 100010 sh(1) imm12(12) Rn Rd  -> mask 0xffc00000
is_adrp = (w & 0x9F000000) == 0x90000000
is_add = (w & 0xFFC00000) == 0x91000000

idx = np.nonzero(is_adrp[:-1])[0]
rd_a = (w[idx] & 0x1F)
immlo = (w[idx] >> 29) & 0x3
immhi = (w[idx] >> 5) & 0x7FFFF
# sign-extend the 21-bit immediate: do it in int64, otherwise a negative page
# offset wraps around in uint32 and points somewhere else entirely
raw21 = (((immhi << 2) | immlo).astype(np.int64))
signed = np.where(raw21 >= (1 << 20), raw21 - (1 << 21), raw21)
# idx counts WORDS, so the address is text.addr + 4*idx (first version forgot
# the *4, which silently made every page wrong and returned zero hits)
pc = (text["addr"] + idx.astype(np.int64) * 4) & ~0xFFF
pages = pc + (signed.astype(np.int64) << 12)

# only pairs where the very next instruction is ADD using the same register
nxt = idx + 1
ok = (nxt < n) & is_add[nxt]
rd_n = w[nxt] & 0x1F
rn_n = (w[nxt] >> 5) & 0x1F
ok &= (rd_n == rd_a) & (rn_n == rd_a)
imm12 = (w[nxt] >> 10) & 0xFFF
shift = (w[nxt] >> 22) & 0x1          # 1 -> LSL #12
target = pages + np.where(shift == 1, imm12.astype(np.int64) << 12,
                          imm12.astype(np.int64))

pairs = np.nonzero(ok)[0]
print("adrp+add pairs decoded: %d" % len(pairs))

SLOTS = [0xA4A98E0, 0xA4A9990, 0xA4A9A08, 0xA4A9A98, 0xA4A9B30]
LO, HI = 0xA4A9800, 0xA4A9C80

sel = pairs[(target[pairs] >= LO) & (target[pairs] < HI)]
print("references into the header .bss window 0x%x..0x%x : %d"
      % (LO, HI, len(sel)))

hits = [(int(text["addr"] + int(idx[p]) * 4), int(target[p])) for p in sel]

# --------------------------------------------------------------- report -----
out = []


def say(s=""):
    out.append(str(s))


say("=" * 78)
say("READS OF THE pes-custom-encrypt / AES256 .bss GLOBALS")
say("=" * 78)
say("adrp+add pairs scanned : %d" % len(pairs))
say("known header slots     : %s" % ", ".join("0x%x" % s for s in SLOTS))
say("")
if not hits:
    say("  NONE FOUND -- no adrp+add in .text addresses 0x%x..0x%x" % (LO, HI))
    say("  (the request builder must reach the header through a pointer held")
    say("   in a register or a struct, not by materialising the address)")

# also list every adrp+add that lands anywhere in this .bss page, for context
print("  hits: %d" % len(hits))

# -------------------------------------------- context around each hit -------
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
RET = 0xD65F03C0
DELTA = 0x4000


def _delta(va):
    """ELF VA -> file offset uses the per-PT_LOAD delta (segment 2 covers
    0x28293c0..0x8b352e8, so any fixed-width range test misses it)."""
    if va >= 0x9906CC0:
        return 0xC000
    if va >= 0x8B75140:
        return 0x8000
    if va >= 0x28293C0:
        return 0x4000
    return 0x0


def word(va):
    o = va - _delta(va)
    if 0 <= o + 4 <= len(d):
        return struct.unpack_from("<I", d, o)[0]
    return None


def func_start(site, back=0x10000):
    for va in range(site & ~3, (site & ~3) - back, -4):
        if word(va) == RET:
            return va + 4
    return None


def read_str(va, n=48):
    o = va - _delta(va)
    if 0 <= o < len(d):
        b = d[o:o + n]
        e = b.find(b"\x00")
        if e >= 0:
            b = b[:e]
        if b and all(0x20 <= c < 0x7F for c in b):
            return repr(b.decode("ascii"))
        if b:
            return "<%d bytes>" % len(b)
        return "<zeroed at 0x%x>" % va
    return "<not file-backed>"


for va, tgt in hits:
    say("")
    say("-" * 78)
    say("READ SITE 0x%08x  ->  slot 0x%08x%s"
        % (va, tgt, "   <-- known header slot"
           if tgt in SLOTS else ""))
    st = func_start(va)
    if st is None:
        say("  no enclosing function found")
        continue
    say("  function start 0x%x   (%d bytes before)" % (st, va - st))
    insns = list(md.disasm(d[st - DELTA:va - DELTA + 0x100], st))
    say("  instructions: %d" % len(insns))
    say("  --- calls ---")
    pending = {}
    for i, ins in enumerate(insns):
        if ins.mnemonic == "adrp":
            try:
                page = int(ins.op_str.split(",")[1].strip().lstrip("#"), 16)
                pending[ins.address] = (page, ins.op_str.split(",")[0].strip())
            except Exception:
                pass
        elif ins.mnemonic == "add" and (ins.address - 4) in pending:
            page, reg = pending.pop(ins.address - 4)
            try:
                imm = int(ins.op_str.split(",")[2].strip().lstrip("#"), 16)
                say("    [str] 0x%08x -> 0x%08x  %s"
                    % (ins.address, page + imm, read_str(page + imm)))
            except Exception:
                pass
        if ins.mnemonic in ("bl", "blr"):
            say("      0x%08x %s %s   | setup: %s"
                % (ins.address, ins.mnemonic, ins.op_str,
                   "; ".join("%s %s" % (c.mnemonic, c.op_str)
                             for c in insns[max(0, i - 3):i])))
    say("  --- window around the read ---")
    for ins in insns:
        if abs(ins.address - va) <= 0x50:
            say("      0x%08x  %-7s %s%s"
                % (ins.address, ins.mnemonic, ins.op_str,
                   "   <== header slot read" if ins.address == va else ""))

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
