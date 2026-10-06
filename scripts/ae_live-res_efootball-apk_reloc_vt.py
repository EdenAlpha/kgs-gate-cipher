import struct, os, collections

LIB = os.path.join("native", "lib", "arm64-v8a", "libUE4.so")
d = open(LIB, "rb").read()

RELA_OFF, RELA_SZ = 0x2ED270, 0x4056666
rel = {}
for i in range(RELA_SZ // 24):
    off = RELA_OFF + i * 24
    r_off, r_info, r_add = struct.unpack_from("<QQq", d, off)
    if (r_info & 0xFFFFFFFF) == 1027:          # R_AARCH64_RELATIVE
        rel[r_off] = r_add
print("relocations: %d" % len(rel))

vt = 0x97D5CA8
print("\n=== vtable @ 0x%x after reloc ===" % vt)
for i in range(8):
    p = rel.get(vt + i * 8)
    print("   [%d] @0x%x -> %s" % (i, vt + i * 8, ("0x%x" % p) if p is not None else "(none)"))

# dereference one more level if these point at other vtables
print("\n=== deref level 2 ===")
for i in range(8):
    p = rel.get(vt + i * 8)
    if p:
        for j in range(6):
            q = rel.get(p + j * 8)
            if q:
                print("   [%d][%d] -> 0x%x" % (i, j, q))
