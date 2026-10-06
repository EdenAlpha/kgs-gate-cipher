"""more_pems.py -- the remaining embedded secrets:
   cert #2 @11576018 (BEGIN with no newline, missed by pem_dump.py's regex)
   RSA PRIVATE KEY @12197510
plus their file->VA addresses and code xrefs."""

import base64
import hashlib
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")
data = open(LIB, "rb").read()

# ---- extract PEMs without requiring a newline after BEGIN ---------------
def extract(off):
    """off points at '-----BEGIN'. Return (text, end_off)."""
    m = re.match(rb"-----BEGIN ([A-Z0-9 ]+)-----", data[off:])
    if not m:
        return None, off
    kind = m.group(1)
    endmark = b"-----END " + kind + b"-----"
    e = data.find(endmark, off)
    if e < 0:
        return None, off
    e += len(endmark)
    return data[off:e].decode("ascii", "replace"), e


def b64body(txt):
    return re.sub(r"-----[A-Z ]+-----|\s", "", txt)


def der_of(txt):
    return base64.b64decode(b64body(txt))


# ---- minimal X.509 field reader ----------------------------------------
def x509_fields(der):
    """Walk DER for the first few PrintableString/UTF8/IA5 values and OIDs."""
    vals = []
    i = 0
    n = len(der)
    while i < n - 2:
        b = der[i]
        if b in (0x13, 0x0C, 0x16, 0x14):        # Printable/UTF8/IA5/T61
            ln = der[i + 1]
            hdr = 2
            if ln & 0x80:
                k = ln & 0x7F
                ln = int.from_bytes(der[i + 2:i + 2 + k], "big")
                hdr = 2 + k
            if 0 < ln < 90:
                try:
                    s = der[i + hdr:i + hdr + ln].decode("ascii")
                    if s.isprintable() and any(c.isalpha() for c in s):
                        vals.append(s)
                except Exception:
                    pass
        i += 1
    return vals


def bits_of_cert(der):
    # look for the 0x82 length marker in the SPKI bit string / RSA modulus
    i = der.find(b"\x30\x82")
    return None


print("=" * 78)
print("cert #2")
print("=" * 78)
t2, e2 = extract(11576018)
print("text bytes: %d   ends at %d" % (len(t2), e2))
print(t2[:120], "...")
d2 = der_of(t2)
print("DER bytes : %d" % len(d2))
print("sha256    : %s" % hashlib.sha256(d2).hexdigest())
print("sha1      : %s" % hashlib.sha1(d2).hexdigest())
f2 = x509_fields(d2)
print("readable fields (first 30):")
for s in f2[:30]:
    print("     ", s)

print()
print("=" * 78)
print("cert #1 (Konami CA root) fields")
print("=" * 78)
t1, _ = extract(10329029)
d1 = der_of(t1)
f1 = x509_fields(d1)
for s in f1[:30]:
    print("     ", s)

print()
print("=" * 78)
print("embedded RSA private key")
print("=" * 78)
tk, ek = extract(12197510)
print("text bytes: %d   ends at %d" % (len(tk), ek))
dk = der_of(tk)
print("DER bytes : %d" % len(dk))
print("sha256    : %s" % hashlib.sha256(dk).hexdigest())
# modulus = largest INTEGER
try:
    ints = []
    i = 0
    while True:
        i = dk.find(b"\x02", i)
        if i < 0 or i + 2 >= len(dk):
            break
        ln = dk[i + 1]
        p = i + 2
        if ln & 0x80:
            k = ln & 0x7F
            ln = int.from_bytes(dk[i + 2:i + 2 + k], "big")
            p = i + 2 + k
        if 60 < ln < 600:
            ints.append(int.from_bytes(dk[p:p + ln], "big"))
        i = p + max(ln, 1)
    if ints:
        m = max(ints, key=lambda v: v.bit_length())
        print("modulus bits: %d" % m.bit_length())
except Exception as ex:
    print("int parse failed %r" % ex)

# ---- offsets -> VA ------------------------------------------------------
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


print()
print("=" * 78)
print("offsets -> VA")
print("=" * 78)
v = {}
for name, off in (("cert2", 11576018), ("privkey", 12197510)):
    v[name] = off2va(off)
    print("  %-10s off=%-10d VA=0x%x" % (name, off, v[name] or 0))
print()
print("run:")
print("  str_xrefs.py %s" % " ".join("0x%x" % v[k] for k in v))
