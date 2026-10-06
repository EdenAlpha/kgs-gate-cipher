import struct, os, sys

LIB = os.path.join("native", "lib", "arm64-v8a", "libUE4.so")
d = open(LIB, "rb").read()

# segment deltas: .text va-off = 0x4000 ; .data.rel.ro va-off = 0x8000
SEG = [(0x28293c0, 0x28253c0, 0x8B31208 - 0x28253c0, ".text"),
       (0x8b75140, 0x8b6d140, 0xd48748, ".data.rel.ro"),
       (0x725800, 0x725800, 0x8da744, ".rodata"),
       (0x9906cc0, 0x98facc0, 0x63d84, ".data")]

def va2off(va):
    for a, o, s, n in SEG:
        if a <= va < a + s:
            return o + (va - a), n
    return None, None

def read_cstr(va, n=80):
    o, _ = va2off(va)
    if o is None:
        return "?"
    return d[o:o + n].split(b"\0", 1)[0].decode("latin-1", "replace")

# command descriptor vtable built at 0x7698360: x23 = 0x97d5ca8
vt = 0x97D5CA8
print("=== vtable @ 0x%x (command descriptor) ===" % vt)
off, sec = va2off(vt)
print("   file off 0x%x in %s" % (off, sec))
for i in range(10):
    p = struct.unpack_from("<Q", d, off + i * 8)[0]
    print("   [%d] -> 0x%x" % (i, p))

# also the '/'+gate.php builder region: dump nearby string refs
print()
print("=== strings referenced near the gate.php URL builder 0x7a2fd00 ===")
for va in range(0x7A2FC00, 0x7A2FE10, 4):
    pass
