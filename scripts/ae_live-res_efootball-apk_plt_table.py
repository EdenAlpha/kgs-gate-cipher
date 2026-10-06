"""plt_table.py -- authoritative PLT stub -> imported symbol table.

A PLT stub is:
    adrp x16, <got page>
    ldr  x17, [x16, #off]
    add  x16, x16, #off
    br   x17
The GOT slot is the r_offset of an R_AARCH64_JUMP_SLOT relocation (1026),
whose symbol index names the import.

Earlier work mislabelled three entries because file bytes were read at the VA
instead of the mapped offset (PT_LOAD #1 sits at a 0x4000 delta), so
"187 __android_log_print callers" was in fact counting `rand`.

  plt_table.py            list every stub
  plt_table.py grep <rx>  filter by name (case-insensitive substring)
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

# ---- program headers --------------------------------------------------------
e_phoff = struct.unpack_from("<Q", d, 32)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)
LOADS, RX = [], None
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, fl = struct.unpack_from("<II", d, o)
    po, pv = struct.unpack_from("<QQ", d, o + 8)
    pf, pm = struct.unpack_from("<QQ", d, o + 32)
    if t == 1:
        LOADS.append((po, pv, pm))
        if fl & 1:
            RX = (po, pv, pf)


def va2off(va):
    for po, pv, pm in LOADS:
        if pv <= va < pv + pm:
            return po + (va - pv)
    return None


# ---- sections ---------------------------------------------------------------
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

got2sym = {}
for nm, (t, off, size, entsz) in secs.items():
    if t != 4 or not entsz:
        continue
    for k in range(size // entsz):
        o = off + k * entsz
        r_off, r_info, r_add = struct.unpack_from("<QQq", d, o)
        if (r_info & 0xFFFFFFFF) == 1026:          # R_AARCH64_JUMP_SLOT
            got2sym[r_off] = r_info >> 32

_, dymo, dymz, dyesz = secs[".dynsym"]
symname = {}
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


def read(va, n=1):
    o = va2off(va)
    return [struct.unpack_from("<I", d, o + 4 * k)[0] for k in range(n)]


# ---- find every adrp/ldr pair that resolves to an imported GOT slot ---------
rx_off, rx_va, rx_sz = RX
table = {}          # plt_va -> name
for va in range(rx_va, rx_va + rx_sz, 4):
    w = read(va)[0]
    if (w >> 24) & 0x9F != 0x90:                    # ADRP
        continue
    rd = w & 0x1F
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    page = (va & ~0xFFF) + (sx((immhi << 2) | immlo, 21) << 12)
    w2 = read(va + 4)[0]
    if (w2 & 0xFFC00000) != 0xF9400000:             # LDR Xt, [Xn, #imm]
        continue
    if ((w2 >> 5) & 0x1F) != rd:
        continue
    got = page + ((w2 >> 10) & 0xFFF) * 8
    idx = got2sym.get(got)
    if idx is None:
        continue
    table[va] = symname.get(idx, "?")

print("PLT stubs resolving to imports: %d" % len(table))
print()

if len(sys.argv) > 2 and sys.argv[1] == "grep":
    rx = sys.argv[2].lower()
    for va in sorted(table):
        if rx in table[va].lower():
            print("  0x%08x  %s" % (va, table[va]))
else:
    for va in sorted(table):
        print("  0x%08x  %s" % (va, table[va]))
