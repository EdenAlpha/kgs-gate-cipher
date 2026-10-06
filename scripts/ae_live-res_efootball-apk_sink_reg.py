"""sink_reg.py -- does the logging framework ever get a sink attached?

The watchdog's message goes to `log_singleton->emit(file, line, ...)` at
0x7dc06fc, which begins:

    ldr x8, [x19, #0x30]        ; sink count
    cbz x8, -> skip everything
    ... loops over 0x58-byte entries reached through [x19,#0x10] / [x19,#0x28]

The singleton is heap-allocated at 0x7dc02e4 with exactly those fields zeroed.
So the framework can only speak if some code stores into +0x10 / +0x28 / +0x30
of the object returned by the getter at 0x7dc0390.

We walk forward from every BL-to-the-getter site, track the returned pointer
through moves, and report any store to those offsets.

  sink_reg.py
"""
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

# RX PT_LOAD: va 0x28293c0 is at file off 0x28253c0
RX_VA, RX_OFF, RX_SZ = 0x28293C0, 0x28253C0, 0x6347D80
DELTA = RX_VA - RX_OFF
GETTER = 0x07DC0390
FIELDS = {0x10, 0x28, 0x30}
AHEAD = 64

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def disasm(va, n):
    off = va - DELTA
    out = []
    for insn in md.disasm(d[off:off + n * 4], va):
        out.append(insn)
    return out


bls = []
for va in range(RX_VA, RX_VA + RX_SZ, 4):
    w = struct.unpack_from("<I", d, va - DELTA)[0]
    if (w & 0xFC000000) != 0x94000000:
        continue
    imm = w & 0x3FFFFFF
    if imm >= 0x2000000:
        imm -= 0x4000000
    if va + imm * 4 == GETTER:
        bls.append(va)

print("BL sites to getter 0x%x : %d" % (GETTER, len(bls)))
print()

hits = []
for site in bls:
    ptr = {"x0"}
    for insn in disasm(site + 4, AHEAD):
        m, ops = insn.mnemonic, insn.op_str

        if m in ("mov", "movz") and "," in ops:          # mov xN, xM
            dst, src = [s.strip() for s in ops.split(",", 1)]
            if src in ptr:
                ptr.add(dst)
            else:
                ptr.discard(dst)
            continue

        if m == "add" and ops.endswith(", 0"):           # add xN, xM, #0
            dst = ops.split(",")[0].strip()
            src = ops.split(",")[1].strip()
            if src in ptr:
                ptr.add(dst)
            else:
                ptr.discard(dst)
            continue

        if m.startswith("st"):                           # str / stp / stur
            if "[" not in ops:
                continue
            regs, mem = ops.split("[", 1)
            mem = mem.rstrip("]")
            base = mem.split(",")[0].strip()
            if base not in ptr:
                continue
            parts = [p.strip() for p in mem.split(",")]
            try:
                disp = int(parts[1], 0) if len(parts) > 1 else 0
            except ValueError:
                continue
            if m.startswith("stp"):                      # stp writes two slots
                first = regs.split(",")[0].strip()
                slots = (disp, disp + 8)
            else:
                slots = (disp,)
            for s in slots:
                if s in FIELDS:
                    hits.append((site, insn.address, m, s))

        if m in ("b", "br", "ret"):
            break

if hits:
    print("stores into the singleton's sink fields:")
    for site, va, m, imm in hits:
        print("  BL@0x%08x -> %s at 0x%08x  offset +0x%x" % (site, m, va, imm))
else:
    print("NO store into +0x10 / +0x28 / +0x30 reachable from any getter call")
    print("  (walked %d sites x %d instructions)" % (len(bls), AHEAD))
    print("  => sink count stays 0 => 0x7dc06fc discards every message")
