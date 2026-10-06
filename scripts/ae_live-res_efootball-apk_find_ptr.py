import struct, sys, os, re
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


def vaof(o):
    for po, pv, pf, fl in ph:
        if po <= o < po + pf:
            return pv + (o - po)
    return None


def find_all(pat):
    r, s = [], 0
    while True:
        i = d.find(pat, s)
        if i < 0:
            break
        r.append(i)
        s = i + 1
        if len(r) > 40:
            break
    return r


for a in sys.argv[1:]:
    va = int(a, 16)
    p8 = struct.pack('<Q', va)
    p4 = struct.pack('<I', va)
    h8 = find_all(p8)
    h4 = [x for x in find_all(p4) if x % 4 == 0]
    print('--- 0x%x' % va)
    print('   ptr64 :', ['0x%x' % (vaof(x) or 0) for x in h8])
    print('   ptr32 :', ['0x%x' % (vaof(x) or 0) for x in h4])
    # MOVZ/MOVK materialisation: search for movz xN,#(va&0xffff) then movk mid
    lo = va & 0xFFFF
    mid = (va >> 16) & 0xFFFF
    movz = 0xD2800000 | (lo << 5)
    hits = [x for x in find_all(struct.pack('<I', movz))]
    print('   movz  :', ['0x%x' % (vaof(x) or 0) for x in hits[:10]])
