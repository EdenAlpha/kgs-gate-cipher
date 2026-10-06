"""dynsym.py -- address of an exported/imported symbol in libUE4.so.

  dynsym.py <name> [<name> ...]

Prints st_value (the load-bias-relative address) for any symbol in .dynsym.
Used to locate Java_jp_konami_Logger_PrintNative so it can be disassembled.
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

secs = {}
order = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    nmoff = struct.unpack_from("<I", d, o)[0]
    t = struct.unpack_from("<I", d, o + 4)[0]
    off = struct.unpack_from("<Q", d, o + 24)[0]
    size = struct.unpack_from("<Q", d, o + 32)[0]
    entsz = struct.unpack_from("<Q", d, o + 56)[0]
    nm = strtab[nmoff:strtab.find(b"\x00", nmoff)].decode("ascii", "replace")
    secs[nm] = (t, off, size, entsz)
    order.append(nm)

# symbol names live in .dynstr, NOT in the section-header string table
if ".dynstr" not in secs:
    print("no .dynstr section")
    sys.exit(1)
_, dso, dss, _ = secs[".dynstr"]
strtab = d[dso:dso + dss]

want = [w.encode() for w in sys.argv[1:]]
if not want:
    want = [b"Java_jp_konami_Logger_PrintNative"]

for nm in order:
    t, off, size, entsz = secs.get(nm, (0, 0, 0, 0))
    if t != 11 or not entsz:       # SHT_DYNSYM
        continue
    for i in range(size // entsz):
        o = off + i * entsz
        st_name, st_info, st_other, st_shndx = struct.unpack_from("<IBBH", d, o)
        st_value, st_size = struct.unpack_from("<QQ", d, o + 8)
        end = strtab.find(b"\x00", st_name)
        name = strtab[st_name:end]
        if name in want:
            bind = st_info >> 4
            typ = st_info & 0xF
            print("%-46s value=0x%09x size=%-8d bind=%d type=%d shndx=%d"
                  % (name.decode(), st_value, st_size, bind, typ, st_shndx))

# also: any symbol whose name contains a query (case-insensitive) as fallback
if len(sys.argv) > 1:
    print()
    print("-- substring matches --")
    for nm in order:
        t, off, size, entsz = secs.get(nm, (0, 0, 0, 0))
        if t != 11 or not entsz:
            continue
        for i in range(size // entsz):
            o = off + i * entsz
            st_name, _, _, _ = struct.unpack_from("<IBBH", d, o)
            st_value, st_size = struct.unpack_from("<QQ", d, o + 8)
            end = strtab.find(b"\x00", st_name)
            name = strtab[st_name:end].decode("ascii", "replace")
            low = name.lower()
            if any(a.lower() in low for a in sys.argv[1:]):
                print("  %-56s 0x%09x size=%d" % (name, st_value, st_size))
