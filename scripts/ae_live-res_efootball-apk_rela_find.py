"""rela_find.py -- data references anyref cannot see.

anyref reports PC-relative refs and raw abs64/abs32 values in the file.  In a
shared object every data pointer lives in .rela.dyn as an R_AARCH64_RELATIVE
entry whose file image is 0, with the real address only in r_addend -- so a
vtable slot or .init_array entry looks like it has no reference at all.

  rela_find.py <addr> [<addr> ...]

prints every relocation whose addend (or stored value) equals the address,
plus the containing section.
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
strtab = d[str_off:str_off + str_size]

secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    nmoff = struct.unpack_from("<I", d, o)[0]
    t = struct.unpack_from("<I", d, o + 4)[0]
    off = struct.unpack_from("<Q", d, o + 24)[0]
    size = struct.unpack_from("<Q", d, o + 32)[0]
    link = struct.unpack_from("<I", d, o + 40)[0]
    entsz = struct.unpack_from("<Q", d, o + 56)[0]
    nm = strtab[nmoff:strtab.find(b"\x00", nmoff)].decode("ascii", "replace")
    secs.append(dict(name=nm, type=t, off=off, size=size, link=link, entsz=entsz))

relocs = []
for s in secs:
    if s["type"] != 4 or not s["entsz"]:
        continue
    for k in range(s["size"] // s["entsz"]):
        o = s["off"] + k * s["entsz"]
        r_off, r_info, r_add = struct.unpack_from("<QQq", d, o)
        relocs.append((s["name"], r_off, r_info & 0xFFFFFFFF, r_info >> 32, r_add))
print("total relocations: %d" % len(relocs))

SYMTYPE = {1027: "RELATIVE", 257: "ABS64", 1026: "JUMP_SLOT",
           1025: "GLOB_DAT", 0: "NONE"}

for arg in sys.argv[1:]:
    want = int(arg, 16)
    print()
    print("=" * 78)
    print("references to 0x%x" % want)
    print("=" * 78)
    n = 0
    for nm, r_off, r_type, r_sym, r_add in relocs:
        if r_add == want:
            print("  %-12s slot=0x%-10x type=%-10s addend=0x%x"
                  % (nm, r_off, SYMTYPE.get(r_type, r_type), r_add))
            n += 1
    # raw file image of a 64-bit value equal to the address
    raw = 0
    i = d.find(struct.pack("<Q", want))
    while i >= 0:
        raw += 1
        i = d.find(struct.pack("<Q", want), i + 1)
    print("  raw qword occurrences in file: %d" % raw)
    if n == 0 and raw == 0:
        print("  -> NO data reference of any kind")
