"""Full dynamic-tag dump, raw section headers for the relocation sections, and
the neighbourhood of the two magic-constant hits.

Written because id_cipher.py reported DT_RELA absent from PT_DYNAMIC (only
DT_RELAENT present) while .rela.dyn through the section headers reported
sh_entsize=1 -- two different answers about where the relocations live.  This
prints the raw evidence rather than another interpretation of it.
"""
import struct

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
d = open(SO, "rb").read()

NAMES = {
    0: "DT_NULL", 1: "DT_NEEDED", 2: "DT_PLTRELSZ", 3: "DT_PLTGOT",
    4: "DT_HASH", 5: "DT_STRTAB", 6: "DT_SYMTAB", 7: "DT_RELA",
    8: "DT_RELASZ", 9: "DT_RELAENT", 10: "DT_STRSZ", 11: "DT_SYMENT",
    12: "DT_INIT", 13: "DT_FINI", 14: "DT_SONAME", 17: "DT_REL",
    18: "DT_RELSZ", 19: "DT_RELENT", 20: "DT_PLTREL", 21: "DT_DEBUG",
    23: "DT_JMPREL", 25: "DT_INIT_ARRAY", 26: "DT_FINI_ARRAY",
    27: "DT_INIT_ARRAYSZ", 28: "DT_FINI_ARRAYSZ", 30: "DT_FLAGS",
    35: "DT_RELR", 36: "DT_RELRSZ", 37: "DT_RELRENT",
    0x6FFFFEF5: "DT_GNU_HASH", 0x6FFFFFF0: "DT_VERSYM",
    0x6FFFFFFE: "DT_RELACOUNT", 0x6FFFFFFF: "DT_RELCOUNT",
    0x6FFFFFFB: "DT_FLAGS_1",
}

e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
e_phentsize = struct.unpack_from("<H", d, 0x36)[0]
e_phnum = struct.unpack_from("<H", d, 0x38)[0]

print("=== PT_DYNAMIC ===")
for i in range(e_phnum):
    p = struct.unpack_from("<IIQQQQQQ", d, e_phoff + i * e_phentsize)
    if p[0] == 2:
        off, fsz = p[2], p[5]
        print("  offset 0x%x size 0x%x" % (off, fsz))
        end, k = off + fsz, 0
        while off + 16 <= end:
            t, v = struct.unpack_from("<QQ", d, off)
            off += 16
            print("    %-20s 0x%x" % (NAMES.get(t, hex(t)), v))
            k += 1
            if t == 0 or k > 80:
                break
        break

print("=== section headers of interest ===")
e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def sec(i):
    return struct.unpack_from("<IIQQQQIIQQ", d, e_shoff + i * e_shentsize)


shstr = sec(e_shstrndx)
for i in range(e_shnum):
    s = sec(i)
    nm = d[shstr[4] + s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    if nm in (".rela.dyn", ".rela.plt", ".rel.dyn", ".data.rel.ro",
              ".init_array", ".fini_array", ".dynamic", ".got",
              ".text", ".rodata"):
        print("  idx%-3d %-14s type=%-3d flags=0x%-4x addr=0x%08x "
              "off=0x%08x size=0x%08x link=%d info=%d align=%d entsize=%d"
              % (i, nm, s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9]))

print("=== blowfish P-array neighbourhood around file 0xc8d92c ===")
for o in range(0xc8d900, 0xc8d900 + 0x60, 16):
    print("  0x%08x  %s" % (o, d[o:o + 16].hex()))
print("  u32 stream from 0xc8d92c:")
print("   ", [hex(struct.unpack_from("<I", d, o)[0])
              for o in range(0xc8d92c, 0xc8d92c + 64, 4)])

print("=== blowfish P[1] 0x85a308d3 / P[2] 0x13198a2e anywhere? ===")
for tag, pat in (("P0", 0x243F6A88), ("P1", 0x85A308D3), ("P2", 0x13198A2E),
                 ("P3", 0x03707344), ("P4", 0xA4093822),
                 ("S0[0]", 0xD1310BA6), ("S1[0]", 0x98DFB5AC),
                 ("S2[0]", 0x2FFD72DB), ("S3[0]", 0xD01ADFB7)):
    b = struct.pack("<I", pat)
    hits, start = [], 0
    while len(hits) < 6:
        j = d.find(b, start)
        if j < 0:
            break
        hits.append(j)
        start = j + 1
    print("  %-7s %s -> %s" % (tag, b.hex(), ["0x%x" % h for h in hits]))

print("=== context: what section contains file 0xc8d92c ===")
for i in range(e_shnum):
    s = sec(i)
    nm = d[shstr[4] + s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    if s[4] <= 0xC8D92C < s[4] + s[5]:
        print("  %s (idx %d) addr=0x%x off=0x%x size=0x%x"
              % (nm, i, s[3], s[4], s[5]))
