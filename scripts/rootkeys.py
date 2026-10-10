#!/usr/bin/env python3
"""rootkeys.py <so> <start_hex> <end_hex> -- exact per-object set-key lists.

Rebuilt 2026-10-10 (original destroyed by temp cleanup; logic re-derived
from the verified runs described in the session notes).

Linear sweep of a serializer.  Tracks the symbolic value of registers so
every `set-key` call (bl 0x2fcc828, key string in x1) is attributed to the
parent object address form in x0:

    sub x0, x29, #0xb8   ->  "x29-0xb8"
    add x0, sp,  #0xd0   ->  "sp+0xd0"
    add xd, x_this, #0xf0 ->  "ROOT"          (the request root at this+0xf0)
    ldr x0, [sp, #8]     ->  slot tracked via earlier str
    mov x0, x20 (unk.)   ->  "UNTRACKED(mov x0, x20)"

Array appends (bl 0x2fccc54) are printed as `[].append(<key>)` under the
same parent.  A group of set-keys sharing a parent = one msgpack map.
"""
import struct
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
from xref2 import Elf, adrpf, addimm        # noqa: E402
from dump_keys import cstr                  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs  # noqa

BL_SETKEY = 0x2F92514          # this build (11.0.1); was 0x2fcc828 on lost build
BL_APPEND = None                # derive from array-heavy serializer when needed

# mov xd, xN  (64-bit): 10010101000 0000000000 000000 Rn Rd -> 0xAA0003E0 base
def mov_xd_xn(w):
    """orr xd, xzr, xN  ==  mov xd, xN  (Rd any, Rn must be xzr/31)."""
    if w & 0xFFE0FFE0 == 0xAA0003E0:
        return w & 0x1F, (w >> 16) & 0x1F
    return None, None


def ldr_imm(w):
    """ldr xt, [xn, #imm] (64-bit, unsigned offset): 1111100101 imm12 Rn Rt."""
    if w & 0xFFC00000 == 0xF9400000:
        rt = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm = ((w >> 10) & 0xFFF) << 3
        return rt, rn, imm
    return None, None, None


def str_imm(w):
    """str xt, [xn, #imm] (64-bit, unsigned offset): 1111100100 imm12 Rn Rt."""
    if w & 0xFFC00000 == 0xF9000000:
        rt = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm = ((w >> 10) & 0xFFF) << 3
        return rt, rn, imm
    return None, None, None


def main():
    path, va, ln = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
    e = Elf(path)
    _, _, _, tv, to, ts = e.sec(".text")
    data = e.read(to, ts)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    sym = {"x0": "this", "sp": "sp", "x29": "x29"}
    slots = {}          # "sp+8" -> label
    kaddr = {}          # reg -> key string address (adrp page or final)
    groups = {}         # parent label -> [(pc, row)]
    order = []
    last_key = None
    CALLEE = ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7")

    def kill_caller():
        for r in CALLEE:
            sym.pop(r, None)
            kaddr.pop(r, None)

    def label_of(reg):
        return sym.get(reg)

    def add_group(parent, pc, row):
        if parent not in groups:
            groups[parent] = []
            order.append(parent)
        groups[parent].append((pc, row))

    i = va - tv
    end = min(len(data), i + ln)
    while i < end:
        w = struct.unpack_from("<I", data, i)[0]
        pc = tv + i

        # ---- branches to helpers ----------------------------------------
        bl_target = None
        if (w & 0xFC000000) == 0x94000000:            # bl imm26
            off = w & 0x3FFFFFF
            if off & 0x2000000:
                off -= 0x4000000
            bl_target = pc + off * 4

        if bl_target == BL_SETKEY:
            key = None
            if "x1" in kaddr:
                key = cstr(e, kaddr["x1"])
            parent = label_of("x0") or "UNTRACKED(?)"
            last_key = key or "?"
            add_group(parent, pc, "%s" % key)
            kill_caller()                       # args/ret + key regs dead
            i += 4
            continue
        if BL_APPEND is not None and bl_target == BL_APPEND:
            parent = label_of("x0") or "UNTRACKED(?)"
            add_group(parent, pc, "[].append(%s)" % last_key)
            kill_caller()
            i += 4
            continue
        if bl_target is not None:
            # generic call: args/ret dead, callee-saved survive
            kill_caller()
            i += 4
            continue

        # ---- adrp ---------------------------------------------------------
        rd, delta = adrpf(w)
        if rd is not None:
            page = (pc & ~0xFFF) + delta
            reg = "x%d" % rd
            sym[reg] = "adrp:%#x" % page
            kaddr[reg] = page                    # candidate key-string page
            i += 4
            continue

        # ---- add/sub immediate -------------------------------------------
        add = addimm(w)
        if add is not None:
            rd2, rn2, imm = add
            if rd2 == 31:
                sym["sp"] = "sp"                 # add sp, ... writes SP
                kaddr.pop("sp", None)
                i += 4
                continue
            if rd2 == 29:
                sym["x29"] = "x29"               # frame pointer stays canonical
                kaddr.pop("x29", None)
                i += 4
                continue
            reg = "x%d" % rd2
            rreg = "sp" if rn2 == 31 else "x%d" % rn2
            # key-address arithmetic on an adrp page
            if kaddr.get(rreg) is not None:
                kaddr[reg] = kaddr[rreg] + imm
                sym[reg] = "key:%#x" % kaddr[reg]
                i += 4
                continue
            kaddr.pop(reg, None)
            base = label_of(rreg)
            if base == "this" and imm == 0xF0:
                sym[reg] = "ROOT"
            elif base is not None and base not in ("adrp",):
                sym[reg] = "%s+%#x" % (base, imm)
            else:
                sym[reg] = None
            i += 4
            continue
        # sub xd, xn, #imm  (64-bit: 1101000100 sh imm12 Rn Rd)
        if w & 0xFF800000 == 0xD1000000:
            rd3 = w & 0x1F
            rn3 = (w >> 5) & 0x1F
            imm3 = (w >> 10) & 0xFFF
            if w & (1 << 22):
                imm3 <<= 12
            if rd3 == 31:
                sym["sp"] = "sp"
                kaddr.pop("sp", None)
                i += 4
                continue
            if rd3 == 29:
                sym["x29"] = "x29"
                kaddr.pop("x29", None)
                i += 4
                continue
            reg = "x%d" % rd3
            rreg = "sp" if rn3 == 31 else "x%d" % rn3
            kaddr.pop(reg, None)
            base = label_of(rreg)
            if base is not None:
                sym[reg] = "%s-%#x" % (base, imm3)
            else:
                sym[reg] = None
            i += 4
            continue

        # ---- mov ----------------------------------------------------------
        md_rd, md_rn = mov_xd_xn(w)
        if md_rd is not None:
            if md_rd == 31:
                sym["sp"] = "sp"
                kaddr.pop("sp", None)
                i += 4
                continue
            reg, rreg = "x%d" % md_rd, "x%d" % md_rn
            if kaddr.get(rreg) is not None:
                kaddr[reg] = kaddr[rreg]          # hoisted key reg copy
            else:
                kaddr.pop(reg, None)
            base = label_of(rreg)
            if base is not None:
                sym[reg] = base
            elif reg == "x0":
                sym[reg] = "UNTRACKED(mov x0, %s)" % rreg
            else:
                sym.pop(reg, None)
            i += 4
            continue
        # mov xd, sp  (alias: add xd, sp, #0)
        if (w & 0xFFFFFFE0) == 0x910003E0:           # add xd, sp, #0 (mov xd,sp)
            sym["x%d" % (w & 0x1F)] = "sp"
            i += 4
            continue

        # ---- ldr/str slot tracking ----------------------------------------
        rt, rn, imm = ldr_imm(w)
        if rt is not None:
            slot = "x%d+%#x" % (rn, imm)
            reg = "x%d" % rt
            kaddr.pop(reg, None)
            if slot in slots:
                sym[reg] = slots[slot]
            elif "sp+%#x" % imm in slots and rn == 31:
                sym[reg] = slots["sp+%#x" % imm]
            else:
                sym.pop(reg, None)
            i += 4
            continue
        rt2, rn2b, imm2 = str_imm(w)
        if rt2 is not None:
            val = label_of("x%d" % rt2)
            regn = "x%d" % rn2b
            if val is not None:
                if rn2b == 31:
                    slots["sp+%#x" % imm2] = val
                slots["%s+%#x" % (regn, imm2)] = val
            i += 4
            continue

        # anything else that writes x0 explicitly: movz/movk etc -> drop x0
        if (w & 0xFF800000) in (0x52800000, 0xD2800000):   # movz xd, #imm
            sym.pop("x%d" % (w & 0x1F), None)
            kaddr.pop("x%d" % (w & 0x1F), None)
        i += 4

    # ---- emit -------------------------------------------------------------
    for parent in order:
        print("=== %s ===" % parent)
        for pc, row in groups[parent]:
            print("   0x%x  %s" % (pc, row))
        keys = sorted(set(r.split("(")[-1].rstrip(")")
                           for _, r in groups[parent]))
        print("   distinct: %s" % ", ".join(keys))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
