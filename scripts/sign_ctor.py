"""Resolve FUN_07c38a44's imports and disassemble the 3 functions that make the sign value.

Two jobs in one pass, because both answer the same question:
  1. Which libc/lib calls does the sign builder make?  (PLT -> .dynsym name)
  2. What do the three non-imported callees do?
       0x7b39a28(ctx, body, bodylen, keystr, keylen, out)  <- fills x29-0x38
       0x74b8d24(w) -> length used for the output buffer
       0x74b8d5c(out, 40, dst, dstcap, 1)                  <- 0x28 = 40 bytes
     The call passes 0x28 (=40) explicitly, which is the exact length of the
     decoded sign cookie, so these three are the whole construction.
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
d = open(SO, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# ---------------------------------------------------------------- ELF ----
e_phoff, = struct.unpack_from("<Q", d, 0x20)
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
segs, dyn = [], None
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, = struct.unpack_from("<I", d, o)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
        "<QQQQQQ", d, o + 8)
    if p_type == 1:
        segs.append((p_offset, p_vaddr, p_filesz))
    elif p_type == 2:                       # PT_DYNAMIC
        dyn = (p_offset, p_filesz, p_vaddr)


def va2off(v):
    for po, pv, ps in segs:
        if pv <= v < pv + ps:
            return po + (v - pv)
    return None


def off2va(o):
    for po, pv, ps in segs:
        if po <= o < po + ps:
            return pv + (o - po)
    return None


# dynamic tags -> symbol table for JUMP_SLOT relocations
tags = {}
o, sz, va = dyn
off = va2off(va)
i = 0
while i < sz:
    tag, val = struct.unpack_from("<QQ", d, off + i)
    if tag == 0:
        break
    tags.setdefault(tag, val)
    i += 16

DT_STRTAB, DT_SYMTAB, DT_SYMENT = 5, 6, 11
DT_JMPREL, DT_PLTRELSZ, DT_SYMENT_ = 23, 2, 11
strtab = va2off(tags[DT_STRTAB])
symtab = va2off(tags[DT_SYMTAB])
syment = tags.get(DT_SYMENT, 24)
jmprel, pltrelsz = tags.get(DT_JMPREL), tags.get(DT_PLTRELSZ)


def dynname(idx):
    so = symtab + idx * syment
    st_name, = struct.unpack_from("<I", d, so)
    end = d.index(b"\x00", strtab + st_name)
    return d[strtab + st_name:end].decode("latin1")


got2name = {}
if jmprel and pltrelsz:
    ro = va2off(jmprel)
    for i in range(0, pltrelsz, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQQ", d, ro + i)
        symidx = r_info >> 32
        got2name[r_offset] = dynname(symidx)

# ------------------------------------------------------------- targets ---
CALLS = [0x2f1ec94, 0x8b38a10, 0x8b352c0, 0x8b38a20, 0x8b38a30, 0x7420858,
         0x8b38590, 0x8b385a0, 0x2f2e26c, 0x8b3ac10, 0x31b542c, 0x7b39a28,
         0x2efa56c, 0x74b8d24, 0x8b35680, 0x8b35260, 0x8b35360, 0x74b8d5c,
         0x2f15088, 0x8b35330, 0x8b34ef0, 0x8b388f0, 0x8b385c0, 0x8b385d0,
         0x8b385e0, 0x8b35290, 0x8b38920, 0x8b35240, 0x7b393bc]


def plt_name(target):
    """A PLT stub loads the GOT slot for its import; recover that slot."""
    fo = va2off(target)
    if fo is None:
        return None
    page = None
    for ins in md.disasm(d[fo:fo + 16], target):
        if ins.mnemonic == "adrp":
            page = int(ins.op_str.split("#")[-1], 16)
        elif ins.mnemonic == "ldr" and page is not None and "#" in ins.op_str:
            imm = int(ins.op_str.split("#")[-1].split("]")[0], 16)
            return got2name.get(page + imm)
    return None


print("=== FUN_07c38a44 imports ===")
print("%-11s %s" % ("elfva", "resolved"))
print("-" * 60)
plts, native = [], []
for t in CALLS:
    n = plt_name(t)
    if n:
        plts.append((t, n))
        print("%-11x IMPORT  %s" % (t, n))
    else:
        native.append(t)
print()
print("native (in-binary) callees: %s" % ", ".join("0x%x" % x for x in native))


def show(title, start, length, extra=()):
    print("\n=== %s  elfva 0x%x  (%d bytes) ===" % (title, start, length))
    fo = va2off(start)
    page = None
    for ins in md.disasm(d[fo:fo + length], start):
        note = ""
        if ins.mnemonic == "adrp":
            page = int(ins.op_str.split("#")[-1], 16)
            note = "  -> page 0x%x" % page
        elif ins.mnemonic in ("add", "ldr") and page is not None and "#" in ins.op_str:
            try:
                imm = int(ins.op_str.split("#")[-1].split("]")[0], 16)
                tgt = page + imm
                so = va2off(tgt)
                if so is not None and 32 <= d[so] < 127:
                    n = d[so:d.index(b"\x00", so)][:48]
                    if all(32 <= c < 127 for c in n):
                        note = "  -> str %r" % n.decode("latin1")
                if not note:
                    note = "  -> 0x%x" % tgt
            except Exception:
                pass
        elif ins.mnemonic == "bl":
            tgt = int(ins.op_str.split("#")[-1], 16)
            n = plt_name(tgt)
            note = "  -> CALL 0x%x %s" % (tgt, n or "")
        print("%-10x %-8s %-38s%s" % (ins.address, ins.mnemonic, ins.op_str, note))


show("0x7b39a28  (body+key -> 40-byte out)", 0x7b39a28, 0x500)
show("0x74b8d24  (returns a length)", 0x74b8d24, 0x120)
show("0x74b8d5c  (out, 40, dst, cap, 1)", 0x74b8d5c, 0x300)
