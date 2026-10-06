"""qword_at.py <va> [count] -- read qwords as they exist *after* relocation.

`.data.rel.ro` vtables are zeros in the file: every pointer is a
R_AARCH64_RELATIVE (1027) relocation whose target lives in r_addend, so raw
bytes return all zeroes -- which is exactly what `vtable_dump.py` printed.

Relocations are taken from the **dynamic segment** (DT_RELA / DT_RELASZ /
DT_RELAENT), not from `.rela.dyn`'s section header: that header carries a bogus
sh_type (0x60000002) and sh_entsize (1), so scanning sections finds only
`.rela.plt`'s 15,345 JUMP_SLOT entries and zero RELATIVE ones.

  qword_at.py 0x97a2888 16
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

# ---- VA -> file offset via program headers ----------------------------------
e_phoff = struct.unpack_from("<Q", d, 32)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)
LOADS = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t = struct.unpack_from("<I", d, o)[0]
    po, pv = struct.unpack_from("<QQ", d, o + 8)
    pm = struct.unpack_from("<Q", d, o + 40)[0]
    if t == 1:
        LOADS.append((po, pv, pm))


def va2off(va):
    for po, pv, pm in LOADS:
        if pv <= va < pv + pm:
            return po + (va - pv)
    return None


# ---- .dynamic: locate DT_RELA ------------------------------------------------
e_shoff = struct.unpack_from("<Q", d, 40)[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 58)
sho = e_shoff + e_shstrndx * e_shentsize
str_off = struct.unpack_from("<Q", d, sho + 24)[0]
str_size = struct.unpack_from("<Q", d, sho + 32)[0]
shstr = d[str_off:str_off + str_size]

dyn_off = dyn_size = None
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    nmoff = struct.unpack_from("<I", d, o)[0]
    t = struct.unpack_from("<I", d, o + 4)[0]
    nm = shstr[nmoff:shstr.find(b"\x00", nmoff)].decode("ascii", "replace")
    if t == 6 and nm == ".dynamic":
        dyn_off = struct.unpack_from("<Q", d, o + 24)[0]
        dyn_size = struct.unpack_from("<Q", d, o + 32)[0]
        break

if dyn_off is None:
    sys.exit("no .dynamic section")

DT = {}
for k in range(dyn_size // 16):
    tag, val = struct.unpack_from("<Qq", d, dyn_off + k * 16)
    if tag == 0:
        break
    DT.setdefault(tag, val)

DT_RELA, DT_RELASZ, DT_RELAENT = DT.get(7), DT.get(8), DT.get(9)
if None in (DT_RELA, DT_RELASZ, DT_RELAENT):
    sys.exit("DT_RELA=%r DT_RELASZ=%r DT_RELAENT=%r" % (DT_RELA, DT_RELASZ, DT_RELAENT))

rela_off = va2off(DT_RELA)

RELA = {}          # r_offset (VA) -> r_addend
KINDS = {}
for k in range(DT_RELASZ // DT_RELAENT):
    r_off, r_info, r_add = struct.unpack_from("<QQq", d, rela_off + k * DT_RELAENT)
    kind = r_info & 0xFFFFFFFF
    KINDS[kind] = KINDS.get(kind, 0) + 1
    if kind == 1027:                       # R_AARCH64_RELATIVE
        RELA[r_off] = r_add
    elif kind == 257:                      # R_AARCH64_ABS64
        RELA.setdefault(r_off, r_add)

print("DT_RELA @0x%x  %d entries; kinds=%s" % (DT_RELA, DT_RELASZ // DT_RELAENT, KINDS))
print("usable addends (1027/257): %d" % len(RELA))
print()

va = int(sys.argv[1], 16)
n = int(sys.argv[2]) if len(sys.argv) > 2 else 8

for i in range(n):
    a = va + i * 8
    off = va2off(a)
    raw = struct.unpack_from("<Q", d, off)[0] if off is not None else None
    val = RELA.get(a, raw)
    kind = "RELOC" if a in RELA else "raw  "
    mark = "  (code)" if val and 0x28293C0 <= val < 0x8B71140 else ""
    print("  [%2d] 0x%08x  -> 0x%016x  %s%s" % (i, a, val or 0, kind, mark))
