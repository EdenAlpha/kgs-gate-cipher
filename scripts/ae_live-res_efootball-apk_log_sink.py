"""log_sink.py -- what does the variadic log function at 0x39e5ff8 actually call?

It does:
    ldr x8, [0x9c14870]
    cbz x8, return          ; null -> silent
    blr x8                  ; emit

So the answer is whatever R_AARCH64_RELATIVE relocation makes of file offset
0x9c14870.  Reads it, applies the reloc, then points at the target.
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

# .rodata identity map verified: off 12231442 -> VA 0xbaa312
SLOT = 0x9C14870
print("=" * 78)
print("the slot at VA 0x%x (= file offset %d)" % (SLOT, SLOT))
print("=" * 78)
print("  raw 8 bytes : %s" % d[SLOT:SLOT + 8].hex())
raw = struct.unpack_from("<Q", d, SLOT)[0]
print("  u64         : 0x%x" % raw)

# ---- ELF section headers ---------------------------------------------------
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
    sh_type = struct.unpack_from("<I", d, o + 4)[0]
    sh_offset = struct.unpack_from("<Q", d, o + 24)[0]
    sh_size = struct.unpack_from("<Q", d, o + 32)[0]
    sh_link = struct.unpack_from("<I", d, o + 40)[0]
    sh_entsize = struct.unpack_from("<Q", d, o + 56)[0]
    nm = strtab[nmoff:strtab.find(b"\x00", nmoff)].decode("ascii", "replace")
    secs.append((nm, sh_type, sh_offset, sh_size, sh_link, sh_entsize))

by_name = {s[0]: s for s in secs}

print()
print("=" * 78)
print("relocations touching 0x%x" % SLOT)
print("=" * 78)
found = False
for nm, t, off, size, link, entsz in secs:
    if t not in (4, 9):          # SHT_RELA / SHT_REL
        continue
    if entsz == 0:
        continue
    for k in range(size // entsz):
        o = off + k * entsz
        r_off, r_info, r_add = struct.unpack_from("<QQq", d, o)
        if r_off == SLOT:
            typ = r_info & 0xFFFFFFFF
            sym = r_info >> 32
            print("  section %-10s reloc_offset=0x%x type=%d addend=0x%x"
                  % (nm, r_off, typ, r_add))
            found = True
if not found:
    print("  NO relocation -> the slot is a plain constant in .rodata")

# ---- what does the plain constant point at? --------------------------------
print()
print("=" * 78)
print("if unrelocated, the pointer target is")
print("=" * 78)
print("  0x%x" % raw)
if raw:
    print("  bytes there: %s" % d[raw:raw + 32].hex())

# ---- identify the target's PLT/GOT link to liblog ---------------------------
print()
print("=" * 78)
print("is __android_log_print reached?  locate its PLT/GOT slot")
print("=" * 78)
# find the import in .dynsym and its relocation -> GOT address
dynsym = by_name.get(".dynsym")
dynstr = by_name.get(".dynstr")
if dynsym and dynstr:
    _, _, so, ss, _, esz = dynsym
    strblob = d[dynstr[2]:dynstr[2] + dynstr[3]]
    want = b"__android_log_print"
    idxs = []
    nent = ss // (esz or 24)
    for i in range(nent):
        o = so + i * esz
        st_name = struct.unpack_from("<I", d, o)[0]
        end = strblob.find(b"\x00", st_name)
        if strblob[st_name:end] == want:
            idxs.append(i)
    print("  .dynsym index(es) for %s : %s" % (want.decode(), idxs))
    # find the JUMP_SLOT / GLOB_DAT reloc referencing that symbol
    for nm, t, off, size, link, entsz in secs:
        if t not in (4, 9) or entsz == 0:
            continue
        for k in range(size // entsz):
            o = off + k * entsz
            r_off, r_info, r_add = struct.unpack_from("<QQq", d, o)
            if (r_info >> 32) in idxs:
                print("  %-10s type=%-3d GOT/slot=0x%x addend=0x%x"
                      % (nm, r_info & 0xFFFFFFFF, r_off, r_add))
