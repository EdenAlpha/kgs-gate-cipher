"""Verify what message the sign-HMAC is actually fed.

Every key search so far assumed the HMAC message is the msgpack body we send.
That came from two helper calls in the caller:

    mov x1, <result of 0x74e6d10>   ; assumed: data pointer
    mov x2, <result of 0x74e6d24>   ; assumed: length

but a finding elsewhere in this project labels those two helpers the other way
round ("size of task+8" / "data of task+8").  If the labels are right, the
message is not the body -- and then none of the key tests were valid, because
they were all keyed on the wrong input.

Photocopier: disassemble the caller's argument setup and both helpers, and
read what is really passed.  Nothing is inferred from memory.

Address mapping is per PT_LOAD, never one flat delta:
    ELF VA  ->  file offset via the segment's p_vaddr / p_offset pair.
The sign builder ELF 0x7b38a44 -> file 0x7b34a44 is the known-good check.
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\msg_check.txt"

data = open(SO, "rb").read()

# ------------------------------------------------------------ PT_LOAD map ---
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]

loads = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, = struct.unpack_from("<I", data, off)
    if p_type != 1:                      # PT_LOAD
        continue
    p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<QQQQQQ", data, off + 8)
    loads.append((p_vaddr, p_offset, p_filesz))
loads.sort()


def va_to_off(va):
    for v, o, sz in loads:
        if v <= va < v + sz:
            return o + (va - v)
    return None


def off_to_va(off):
    for v, o, sz in loads:
        if o <= off < o + sz:
            return v + (off - o)
    return None


md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

out = []
out.append("PT_LOAD segments (vaddr, fileoff, filesz):")
for v, o, sz in loads:
    out.append("  va 0x%09x  off 0x%09x  size 0x%09x   (delta 0x%x)"
               % (v, o, sz, v - o))
out.append("")

# known-good check of the mapping
chk_va = 0x7B38A44
out.append("mapping check: ELF 0x%x -> file 0x%x  (expected 0x7b34a44)"
           % (chk_va, va_to_off(chk_va) or 0))
out.append("")


def dump(label, va, size=0x120):
    o = va_to_off(va)
    out.append("=" * 78)
    out.append("%s   ELF VA 0x%x  file 0x%x  (%s)"
               % (label, va, o if o is not None else 0,
                  "ok" if o is not None else "OUT OF RANGE"))
    out.append("=" * 78)
    if o is None:
        out.append("  !! no segment covers this VA")
        out.append("")
        return
    for insn in md.disasm(data[o:o + size], va):
        out.append("  0x%08x  %-8s %s" % (insn.address, insn.mnemonic, insn.op_str))
    out.append("")


# 1. the caller's argument setup just before bl FUN_07c38a44 (ELF 0x7b38a44)
dump("CALLER around ELF 0x7b2e46c (arg setup into the sign builder)",
     0x7B2E400, 0xC0)

# 2. the two helpers whose return values become x1 / x2
dump("HELPER ELF 0x74e6d10  (first arg, assumed data)", 0x74E6D10, 0x90)
dump("HELPER ELF 0x74e6d24  (second arg, assumed length)", 0x74E6D24, 0x90)

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
