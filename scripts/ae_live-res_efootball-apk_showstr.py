import struct, sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
d = open(os.path.join(HERE, 'native/lib/arm64-v8a/libUE4.so'), 'rb').read()
e_phoff = struct.unpack_from('<Q', d, 32)[0]
e_phentsize, e_phnum = struct.unpack_from('<HH', d, 54)
ph = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, fl = struct.unpack_from('<II', d, o)
    po, pv, _, pf, _, _ = struct.unpack_from('<QQQQQQ', d, o + 8)
    if t == 1:
        ph.append((po, pv, pf, fl))


def off(va):
    for po, pv, pf, fl in ph:
        if pv <= va < pv + pf:
            return po + (va - pv)
    return None


for a in sys.argv[1:]:
    va = int(a, 16)
    o = off(va)
    if o is None:
        print(hex(va), 'NOT IN SEGMENT')
        continue
    e = d.find(b'\x00', o, o + 96)
    print(hex(va), repr(d[o:e]))
