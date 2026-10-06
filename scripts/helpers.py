"""Disassemble the five small helpers FUN_07c38a44 calls.

Known so far: sign = base64(40 bytes), the 40 bytes are 20+20 (distinct),
0x7b39a28 is an HMAC whose message is the msgpack body, and the caller
streams  (w26 ^ w24)  into an ostringstream.
  0x2f1ec94  returns w24, called FIRST with (out_str, body, bodylen)
  0x7420858  returns w26, called with (sp+0x48, mt19937_state, sp+0x48)
  0x2f2e26c  called twice: (obj, seed16, 16) then (obj, byte@0xbb53ec, 1)
  0x31b542c  called twice on a std::string-like object
  0x2f15088  the append used for "sign=" / the trailing char
Plus: read the two string literals it concatenates.
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
d = open(SO, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

e_phoff, = struct.unpack_from("<Q", d, 0x20)
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
segs = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, = struct.unpack_from("<I", d, o)
    p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
    if p_type == 1:
        segs.append((p_offset, p_vaddr, p_filesz))


def va2off(v):
    for po, pv, ps in segs:
        if pv <= v < pv + ps:
            return po + (v - pv)
    return None


def cstr(v, n=48):
    fo = va2off(v)
    if fo is None:
        return None
    end = d.find(b"\x00", fo, fo + n + 1)
    if end < 0:
        end = fo + n
    b = d[fo:end]
    return b.decode("latin1") if b and all(32 <= c < 127 for c in b) else None


print("literals the sign builder concatenates:")
for v in (0xbb53ec, 0xa1d8a3, 0xa52031):
    print("  0x%x -> %r" % (v, cstr(v)))
    fo = va2off(v)
    print("        raw: %r" % d[fo:fo + 16])

HELPERS = [(0x2f1ec94, 92, "returns w24 (out_str, body, len)"),
           (0x7420858, 200, "returns w26 (buf, mt_state, buf)"),
           (0x2f2e26c, 304, "(obj, data, len) x2"),
           (0x31b542c, 540, "on a string-like object x2"),
           (0x2f15088, 392, "append(out, data, len)")]

for va, ln, why in HELPERS:
    fo = va2off(va)
    print("\n" + "=" * 74)
    print("0x%x  %d bytes -- %s" % (va, ln, why))
    print("=" * 74)
    page = None
    for ins in md.disasm(d[fo:fo + ln], va):
        note = ""
        if ins.mnemonic == "adrp":
            page = int(ins.op_str.split("#")[-1], 16)
            note = "  -> page 0x%x" % page
        elif ins.mnemonic in ("add", "ldr") and page is not None and "#" in ins.op_str:
            try:
                imm = int(ins.op_str.split("#")[-1].split("]")[0], 16)
                s = cstr(page + imm)
                note = ("  -> str %r" % s) if s else ("  -> 0x%x" % (page + imm))
            except Exception:
                pass
        elif ins.mnemonic == "bl":
            try:
                note = "  -> CALL 0x%x" % int(ins.op_str.split("#")[-1], 16)
            except Exception:
                pass
        print("  %-10x %-8s %-40s%s" % (ins.address, ins.mnemonic, ins.op_str, note))
