"""sink_audit.py -- prove whether the log sink at 0x9c14870 has any writer.

The variadic emitter at 0x39e5ff8 (678 call sites, including
"Score  HOME[%d] AWAY[%d]\\n") does:

    ldr x8, [0x9c14870]
    cbz x8, epilogue          ; NULL -> emit nothing
    blr x8

0x9c14870 sits in the bss tail of PT_LOAD #4, so it starts NULL.  glob_xrefs
only recognises immediate-offset addressing; this walks every ADRP onto that
page and propagates register constants through ADD/SUB/register moves so that
any store form -- unsigned offset, pre/post index, register offset -- is
resolved and compared against the slot.

Prints every access that lands on 0x9c14870, and every store that lands
anywhere on the page, so nothing is silently missed.
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

e_phoff = struct.unpack_from("<Q", d, 32)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)
ph = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, fl = struct.unpack_from("<II", d, o)
    po, pv = struct.unpack_from("<QQ", d, o + 8)
    pf, pm = struct.unpack_from("<QQ", d, o + 32)
    ph.append((t, fl, po, pv, pf, pm))

RX = [(po, pv, pf) for t, fl, po, pv, pf, pm in ph if t == 1 and (fl & 1)][0]
R_OFF, R_VA, R_SZ = RX


def va2off(va):
    for t, fl, po, pv, pf, pm in ph:
        if t == 1 and pv <= va < pv + pf:
            return po + (va - pv)
    return None


def sx(x, bits):
    s = 1 << (bits - 1)
    m = (1 << bits) - 1
    v = x & m
    return (v ^ s) - s


PAGE = int(sys.argv[1], 16) & ~0xFFF if len(sys.argv) > 1 else 0x9C14000
SLOT = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x9C14870
BEFORE, AFTER = 0, 64

adrps = []
for off in range(0, R_SZ, 4):
    w = struct.unpack_from("<I", d, R_OFF + off)[0]
    if ((w >> 24) & 0x9F) != 0x90:
        continue
    pc = R_VA + off
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    tgt = (pc & ~0xFFF) + (sx((immhi << 2) | immlo, 21) << 12)
    if tgt == PAGE:
        adrps.append(pc)

print("=" * 78)
print("ADRP sites on page 0x%x : %d" % (PAGE, len(adrps)))
print("=" * 78)

slot_hits = []
page_stores = []

for pc in adrps:
    reg = {}          # reg index -> constant offset from PAGE
    for i in range(BEFORE + AFTER):
        a = pc + (i - BEFORE) * 4
        o = va2off(a)
        if o is None:
            continue
        w = struct.unpack_from("<I", d, o)[0]

        if ((w >> 24) & 0x9F) == 0x90:          # ADRP
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            tgt = (a & ~0xFFF) + (sx((immhi << 2) | immlo, 21) << 12)
            rd = w & 0x1F
            if tgt == PAGE:
                reg[rd] = 0
            elif rd in reg:
                del reg[rd]
            continue
        if ((w >> 24) & 0x9F) == 0x10:          # ADR
            rd = w & 0x1F
            reg.pop(rd, None)
            continue

        if (w & 0xFF800000) == 0x91000000:      # ADD imm 64
            rd, rn = w & 0x1F, (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            if (w >> 22) & 1:
                imm12 <<= 12
            if rn in reg:
                reg[rd] = reg[rn] + imm12
            elif rd in reg:
                del reg[rd]
            continue
        if (w & 0xFF800000) == 0xD1000000:      # SUB imm 64
            rd, rn = w & 0x1F, (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            if (w >> 22) & 1:
                imm12 <<= 12
            if rn in reg:
                reg[rd] = reg[rn] - imm12
            elif rd in reg:
                del reg[rd]
            continue
        if (w & 0xFF800000) == 0xAA0003E0:      # ORR Xd, XZR, Xm  (MOV reg)
            rd, rn = w & 0x1F, (w >> 5) & 0x1F
            if rn in reg:
                reg[rd] = reg[rn]
            elif rd in reg:
                del reg[rd]
            continue

        # --- loads and stores ---
        base_off = None
        kind = None
        if (w & 0xFFC00000) == 0xF9400000:
            rn, rt = (w >> 5) & 0x1F, w & 0x1F
            if rn in reg:
                base_off = reg[rn] + ((w >> 10) & 0xFFF) * 8
            kind = "LDR"
        elif (w & 0xFFC00000) == 0xF9000000:
            rn, rt = (w >> 5) & 0x1F, w & 0x1F
            if rn in reg:
                base_off = reg[rn] + ((w >> 10) & 0xFFF) * 8
            kind = "STR"
        elif (w & 0xFFE00C00) in (0xF8000400, 0xF8000C00):   # pre/post index
            rn, rt = (w >> 5) & 0x1F, w & 0x1F
            simm = sx((w >> 12) & 0x7F, 7)
            if rn in reg:
                base_off = reg[rn] + simm
            kind = "STR(pre/post)" if (w & 0xFFE00C00) == 0xF8000C00 else \
                   "STR(idx)"
            if (w & 0x3F000000) & 0x01000000:   # opc bit distinguishes L/ST
                kind = "LDR(idx)"
        elif (w & 0xFFE00C00) in (0xF8400400, 0xF8400C00):
            rn, rt = (w >> 5) & 0x1F, w & 0x1F
            simm = sx((w >> 12) & 0x7F, 7)
            if rn in reg:
                base_off = reg[rn] + simm
            kind = "LDR(idx)"
        elif (w & 0xFFC00000) == 0xB9000000:    # STR W unsigned
            rn, rt = (w >> 5) & 0x1F, w & 0x1F
            if rn in reg:
                base_off = reg[rn] + ((w >> 10) & 0xFFF) * 4
            kind = "STR(W)"
        elif (w & 0xFFC00000) == 0xB9400000:    # LDR W unsigned
            rn, rt = (w >> 5) & 0x1F, w & 0x1F
            if rn in reg:
                base_off = reg[rn] + ((w >> 10) & 0xFFF) * 4
            kind = "LDR(W)"
        elif (w & 0xFFC00000) == 0x39000000:    # STRB unsigned
            rn, rt = (w >> 5) & 0x1F, w & 0x1F
            if rn in reg:
                base_off = reg[rn] + ((w >> 10) & 0xFFF)
            kind = "STRB"
        elif (w & 0xFFC00000) == 0x39400000:    # LDRB unsigned
            rn, rt = (w >> 5) & 0x1F, w & 0x1F
            if rn in reg:
                base_off = reg[rn] + ((w >> 10) & 0xFFF)
            kind = "LDRB"

        if base_off is not None:
            addr = PAGE + base_off
            if addr == SLOT:
                slot_hits.append((a, kind, addr))
            if kind and kind.startswith("STR"):
                page_stores.append((a, kind, addr))

print()
print("=" * 78)
print("accesses landing exactly on the sink slot 0x%x" % SLOT)
print("=" * 78)
if not slot_hits:
    print("  NONE FOUND")
for a, kind, addr in slot_hits:
    tag = "  <== WRITER" if kind.startswith("STR") else "  (reader)"
    print("  0x%08x  %-14s 0x%x%s" % (a, kind, addr, tag))

writers = [h for h in slot_hits if h[1].startswith("STR")]
print()
print("  distinct writers of the slot: %d" % len({h[0] for h in writers}))

print()
print("=" * 78)
print("all stores anywhere on page 0x%x (context for missed addressing)" % PAGE)
print("=" * 78)
print("  %d store(s)" % len(page_stores))
for a, kind, addr in page_stores:
    mark = "   <== THE SINK" if addr == SLOT else ""
    print("    0x%08x  %-14s -> 0x%x%s" % (a, kind, addr, mark))
