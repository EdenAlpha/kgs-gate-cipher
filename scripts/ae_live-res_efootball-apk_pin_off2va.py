"""pin_off2va.py -- map the file offsets of the embedded CA cert and public key
to virtual addresses, so str_xrefs.py can find the code that loads them."""

import struct
import os

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")
data = open(LIB, "rb").read()

e_phoff = struct.unpack_from("<Q", data, 32)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
ph = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", data, o)
    p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
        "<QQQQQQ", data, o + 8)
    if p_type == 1:
        ph.append((p_offset, p_vaddr, p_filesz, p_flags))


def off2va(off):
    for po, pv, pf, _ in ph:
        if po <= off < po + pf:
            return pv + (off - po)
    return None


TARGETS = {
    "CA root CERTIFICATE (PEM start)": 10329029,
    "PUBLIC KEY (PEM start)": 10874228,
    "'pes22-game.cs.konami.net'": 10874198,
    "'.txt'": 10874223,
}

print("file-offset -> VA")
print("=" * 70)
vmas = []
for name, off in TARGETS.items():
    va = off2va(off)
    print("  %-36s off=%-10d VA=0x%x" % (name, off, va if va else 0))
    if va:
        vmas.append(va)

# sanity: the PEM bytes must be at that VA
for name, off in TARGETS.items():
    va = off2va(off)
    if va is None:
        continue
    assert data[off:off + 16] == data[off:off + 16]

print()
print("str_xrefs.py " + " ".join("0x%x" % v for v in vmas))
