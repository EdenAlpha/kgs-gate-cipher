"""How are code/data pointers stored in libUE4.so?

Answers: are function pointers present as absolute 64-bit values (R_AARCH64_RELATIVE
with addend written at link time), or is the binary using compact DT_RELR / no
pointers at all?  Decides whether vtable-based class identification is even possible.
"""
import struct, sys, os

SO = os.path.join("native", "lib", "arm64-v8a", "libUE4.so")
d = open(SO, "rb").read()

(e_phoff,) = struct.unpack_from("<Q", d, 32)
(_, _, e_phentsize, e_phnum) = struct.unpack_from("<HHHH", d, 52)[:4] \
    if False else (0, 0, *struct.unpack_from("<HH", d, 54))
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)

PT_LOAD, PT_DYNAMIC = 1, 2
loads, dyn = [], None
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", d, o)
    p_off, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = struct.unpack_from(
        "<QQQQQQ", d, o + 8)
    if p_type == PT_LOAD:
        loads.append((p_off, p_vaddr, p_filesz, p_flags))
    elif p_type == PT_DYNAMIC:
        dyn = (p_off, p_filesz)

DYN_TAGS = {
    2: "PLTRELSZ", 5: "STRTAB", 6: "SYMTAB", 7: "RELA", 8: "RELASZ", 9: "RELAENT",
    17: "REL", 18: "RELSZ", 19: "RELENT", 23: "JMPREL", 20: "PLTREL",
    0x6FFFFFF9: "RELACOUNT", 0x6FFFFFFE: "VERNEED", 0x6FFFFFFF: "VERNEEDNUM",
}
DT_RELR, DT_RELRSZ, DT_RELRENT = 35, 36, 37   # Android R+/LLD compact relocs

print("== LOAD segments ==")
for off, va, fs, fl in loads:
    perms = ("r" if fl & 4 else "-") + ("w" if fl & 2 else "-") + ("x" if fl & 1 else "-")
    print("   off=0x%08x va=0x%08x filesz=0x%x %s" % (off, va, fs, perms))

print("\n== DYNAMIC ==")
found = {}
if dyn:
    po, fs = dyn
    i = 0
    while i + 16 <= fs:
        tag, val = struct.unpack_from("<QQ", d, po + i)
        if tag == 0:
            break
        if tag in DYN_TAGS:
            found[DYN_TAGS[tag]] = val
            print("   DT_%-10s 0x%x" % (DYN_TAGS[tag], val))
        if tag == DT_RELR:
            found["RELR"] = val
            print("   DT_RELR        0x%x" % val)
        if tag == DT_RELRSZ:
            found["RELRSZ"] = val
            print("   DT_RELRSZ      0x%x" % val)
        i += 8

# ---- count plausible absolute code pointers stored in non-exec segments ----
print("\n== absolute 8-byte code-like pointers in non-R-X segments ==")
CODE_LO, CODE_HI = 0x400000, 0x1200000
hits = []
for off, va, fs, fl in loads:
    if fl & 1:          # skip executable segments (instructions look like data)
        continue
    seg = d[off:off + fs]
    for j in range(0, len(seg) - 7, 8):
        v = struct.unpack_from("<Q", seg, j)[0]
        if CODE_LO <= v < CODE_HI:
            hits.append((va + j, v))
print("   count=%d" % len(hits))
for loc, v in hits[:15]:
    print("     slot=0x%08x -> 0x%08x" % (loc, v))

# ---- if DT_RELR exists, decode it ----
if "RELR" in found and "RELRSZ" in found:
    relr_off, relr_sz = found["RELR"], found["RELRSZ"]

    def va_to_off(va):
        for off, v, fs, _ in loads:
            if v <= va < v + fs:
                return off + (va - v)
        return None

    print("\n== DT_RELR decode: first 10 relocated slots ==")
    n = 0
    where = 0
    k = 0
    while k + 8 <= relr_sz and n < 10:
        entry = struct.unpack_from("<Q", d, relr_off + k)[0]
        k += 8
        if (entry & 1) == 0:
            where = entry
            o = va_to_off(where)
            if o is not None:
                print("   slot=0x%08x addend=0x%x" % (where, struct.unpack_from("<Q", d, o)[0]))
                n += 1
        else:
            for b in range(1, 64):
                if (entry >> b) & 1:
                    where += 8
                    o = va_to_off(where)
                    if o is not None and n < 10:
                        print("   slot=0x%08x addend=0x%x" % (where, struct.unpack_from("<Q", d, o)[0]))
                        n += 1
