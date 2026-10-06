"""plt_resolve.py -- which imported symbol does a PLT stub belong to?

A PLT entry is:
    adrp x16, <got page>
    ldr  x17, [x16, #off]        ; load GOT slot
    add  x16, x16, #off
    br   x17

The GOT slot is the r_offset of an R_X86.. R_AARCH64_JUMP_SLOT relocation
(type 1026) in .rela.plt, whose symbol index names the import.

  plt_resolve.py <plt_va> [<plt_va> ...]
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

e_shoff = struct.unpack_from("<Q", d, 40)[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 58)
sho = e_shoff + e_shstrndx * e_shentsize
str_off = struct.unpack_from("<Q", d, sho + 24)[0]
str_size = struct.unpack_from("<Q", d, sho + 32)[0]
shstr = d[str_off:str_off + str_size]

secs = {}
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    nmoff = struct.unpack_from("<I", d, o)[0]
    t = struct.unpack_from("<I", d, o + 4)[0]
    off = struct.unpack_from("<Q", d, o + 24)[0]
    size = struct.unpack_from("<Q", d, o + 32)[0]
    entsz = struct.unpack_from("<Q", d, o + 56)[0]
    nm = shstr[nmoff:shstr.find(b"\x00", nmoff)].decode("ascii", "replace")
    secs[nm] = (t, off, size, entsz)

_, dso, dss, _ = secs[".dynstr"]
dynstr = d[dso:dso + dss]

# GOT slot -> symbol index
got2sym = {}
for nm, (t, off, size, entsz) in secs.items():
    if t != 4 or not entsz:
        continue
    for k in range(size // entsz):
        o = off + k * entsz
        r_off, r_info, r_add = struct.unpack_from("<QQq", d, o)
        if (r_info & 0xFFFFFFFF) == 1026:      # R_AARCH64_JUMP_SLOT
            got2sym[r_off] = r_info >> 32

# symbol index -> name
symname = {}
_, dymo, dymz, dyesz = secs[".dynsym"]
for i in range(dymz // dyesz):
    o = dymo + i * dyesz
    st_name = struct.unpack_from("<I", d, o)[0]
    symname[i] = dynstr[st_name:dynstr.find(b"\x00", st_name)].decode(
        "ascii", "replace")


def sx(x, bits):
    s = 1 << (bits - 1)
    m = (1 << bits) - 1
    v = x & m
    return (v ^ s) - s


# VA -> file offset (PT_LOAD #1 sits at a 0x4000 delta, so identity is unsafe)
_LOADS = []
_e_phoff = struct.unpack_from("<Q", d, 32)[0]
_e_phentsize, _e_phnum = struct.unpack_from("<HH", d, 54)
for _i in range(_e_phnum):
    _o = _e_phoff + _i * _e_phentsize
    _t, _fl = struct.unpack_from("<II", d, _o)
    _po, _pv = struct.unpack_from("<QQ", d, _o + 8)
    _pf, _pm = struct.unpack_from("<QQ", d, _o + 32)
    if _t == 1:
        _LOADS.append((_po, _pv, _pm))


def va2off(va):
    for po, pv, pm in _LOADS:
        if pv <= va < pv + pm:
            return po + (va - pv)
    return None


def resolve(plt_va):
    got = None
    for k in range(8):
        a = plt_va + k * 4
        off = va2off(a)
        if off is None:
            break
        w = struct.unpack_from("<I", d, off)[0]
        if (w >> 24) & 0x9F == 0x90:                      # ADRP
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            page = (a & ~0xFFF) + (sx((immhi << 2) | immlo, 21) << 12)
            rd = w & 0x1F
        elif (w & 0xFFC00000) == 0xF9400000:              # LDR X
            if ((w >> 5) & 0x1F) == rd:
                got = page + ((w >> 10) & 0xFFF) * 8
                break
    return got


for arg in sys.argv[1:]:
    va = int(arg, 16)
    got = resolve(va)
    sym = got2sym.get(got) if got else None
    name = symname.get(sym, "?") if sym else "?"
    print("PLT 0x%08x -> GOT 0x%x -> %s" % (va, got or 0, name))
