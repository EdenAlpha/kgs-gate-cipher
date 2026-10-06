import struct, os, sys
import numpy as np
HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")
data = open(LIB, "rb").read()

e_phoff = struct.unpack_from("<Q", data, 32)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
ph = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", data, o)
    p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<QQQQQQ", data, o + 8)
    if p_type == 1:
        ph.append((p_offset, p_vaddr, p_filesz, p_flags))


def va2off(va):
    for po, pv, pf, fl in ph:
        if pv <= va < pv + pf:
            return po + (va - pv)
    return None


def off2va(off):
    for po, pv, pf, fl in ph:
        if po <= off < po + pf:
            return pv + (off - po)
    return None


va = int(sys.argv[1], 16)
back = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x8000
start = va - back
o = va2off(start)
n = (va - start) // 4
words = struct.unpack_from("<%dI" % n, data, o)
cands = []
for i in range(len(words) - 1, -1, -1):
    w = words[i]
    pc = start + i * 4
    # STP x29,x30,[sp,#-imm]!
    if (w & 0xFFC07FFF) == 0xA9807BFD and ((w >> 15) & 0x7F) >= 0x40:
        cands.append(("STP-pre", pc))
    # sub sp,sp,#imm  (Rd=Rn=31, 64-bit SUB imm)
    elif (w & 0xFFC003FF) == 0xD10003FF:
        cands.append(("SUB-sp", pc))
    # STP x24..x29 style first-save: stp x29,x30,[sp,#-0x..]! only
print("prologue candidates walking back from 0x%x:" % va)
for k, pc in cands[:8]:
    print("   %-8s 0x%x" % (k, pc))
