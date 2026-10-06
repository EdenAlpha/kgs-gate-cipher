"""Disassemble FUN_07c38a44 (the sign cookie writer) with correct ELF mapping.

Ghidra's dump addresses equal file offset + 0x100000 for .rodata, but .text
may sit in a different PT_LOAD segment, so this parses the ELF program
headers and derives the mapping instead of assuming it.

Marks: ADRP/ADD targets that land on the seed literal, "sign=" or the
pes-custom-encrypt header, plus every BL call target.
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
DUMP_FUNC = 0x7c38a44            # Ghidra address of FUN_07c38a44
SEED_DUMP = 0xc8f1b1
SIGN_DUMP = 0xcb6471
HDR_DUMP = 0xbd120e

d = open(SO, "rb").read()

# ---- ELF64 program headers --------------------------------------------
assert d[:4] == b"\x7fELF", "not ELF"
e_phoff, = struct.unpack_from("<Q", d, 0x20)
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", d, off)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
        "<QQQQQQ", d, off + 8)
    if p_type == 1:                       # PT_LOAD
        segs.append((p_offset, p_vaddr, p_filesz))
        print("PT_LOAD off=0x%x va=0x%x filesz=0x%x  (va-off=0x%x)"
              % (p_offset, p_vaddr, p_filesz, p_vaddr - p_offset))


def off_to_va(o):
    for po, pv, ps in segs:
        if po <= o < po + ps:
            return pv + (o - po)
    return None


def va_to_off(v):
    for po, pv, ps in segs:
        if pv <= v < pv + ps:
            return po + (v - pv)
    return None


# Ghidra's address for the seed string must match the ELF's, or the mapping
# assumption is wrong -- check before trusting anything below.
seed_off = d.find(b"Xrq-RtAF_91MAE82")
sign_off = d.find(b"sign=")
hdr_off = d.find(b"pes-custom-encrypt")
print("seed  file=0x%x elfva=0x%x dumpva=0x%x" % (seed_off, off_to_va(seed_off), SEED_DUMP))
print("sign= file=0x%x elfva=0x%x dumpva=0x%x" % (sign_off, off_to_va(sign_off), SIGN_DUMP))
print("hdr   file=0x%x elfva=0x%x dumpva=0x%x" % (hdr_off, off_to_va(hdr_off), HDR_DUMP))

# Ghidra loaded the image at a base 0x100000 above the ELF's own VAs, proved
# on three strings above. Convert every dump address through that delta.
G2E = off_to_va(seed_off) - SEED_DUMP          # 0xb8f1b1 - 0xc8f1b1
print("ghidra -> elf delta: 0x%x" % G2E)
elf_func_va = DUMP_FUNC + G2E
func_off = va_to_off(elf_func_va)
func_va = off_to_va(func_off)
print("function: dumpva 0x%x -> elfva 0x%x -> file 0x%x"
      % (DUMP_FUNC, elf_func_va, func_off))

LENGTH = 0x900
code = d[func_off:func_off + LENGTH]
SEED_VA = off_to_va(seed_off)
SIGN_VA = off_to_va(sign_off)
HDR_VA = off_to_va(hdr_off)

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
page = None
rows = []
for ins in md.disasm(code, func_va):
    note = ""
    if ins.mnemonic == "adrp":
        imm = int(ins.op_str.split("#")[-1].strip(), 16)
        page = imm
        note = "  -> page 0x%x" % page
    elif ins.mnemonic in ("add", "ldr") and page is not None and "#" in ins.op_str:
        try:
            imm = int(ins.op_str.split("#")[-1].split("]")[0].strip(), 16)
            tgt = page + imm
            if tgt == SEED_VA:
                note = "  -> SEED \"Xrq-RtAF_91MAE82\""
            elif tgt == SIGN_VA:
                note = "  -> \"sign=\""
            elif tgt == HDR_VA:
                note = "  -> \"pes-custom-encrypt\""
            else:
                note = "  -> va 0x%x" % tgt
        except Exception:
            pass
    elif ins.mnemonic == "bl":
        try:
            imm = int(ins.op_str.split("#")[-1], 16)
            note = "  -> CALL va 0x%x" % imm
        except Exception:
            pass
    rows.append((ins.address, ins.mnemonic, ins.op_str, note))

print("instructions: %d\n" % len(rows))
print("%-12s %-8s %-40s" % ("VA", "OP", "ARGS"))
print("-" * 100)
for pc, mn, op, note in rows:
    print("%-12x %-8s %-40s%s" % (pc, mn, op, note))
