"""pem_dump.py -- bounded extraction of every embedded PEM block from
libUE4.so, with surrounding context.  (v1 used re.S and over-matched across
479 KB of binary; matches are now length-capped.)"""

import os
import re
import base64

BASE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(BASE, "efootball-apk", "native", "lib", "arm64-v8a",
                  "libUE4.so")

with open(SO, "rb") as fh:
    blob = fh.read()

BLOCK = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n"
    rb"([A-Za-z0-9+/=\r\n]{16,4096}?)"
    rb"-----END \1-----")

blocks = []
for m in BLOCK.finditer(blob):
    blocks.append((m.start(), m.group(1).decode(), m.group(0)))

print("=" * 78)
print("every bounded PEM block in libUE4.so")
print("=" * 78)
for off, kind, body in blocks:
    print("  @%-10d  %-28s  %d bytes" % (off, kind, len(body)))

print()
print("=" * 78)
print("full text")
print("=" * 78)
for off, kind, body in blocks:
    print("-" * 78)
    print("file offset %d   type=%s" % (off, kind))
    print(body.decode("ascii", "replace"))

# --- RSA public key size -------------------------------------------------
print()
print("=" * 78)
print("public key details")
print("=" * 78)
for off, kind, body in blocks:
    if kind != "PUBLIC KEY":
        continue
    b64 = re.sub(rb"-----[A-Z ]+-----|\s", b"", body)
    der = base64.b64decode(b64)
    print("  offset      : %d" % off)
    print("  DER bytes   : %d" % len(der))
    # SPKI: bit-string length at a known place; simplest robust route is
    # parse the modulus length from the PKCS#1 RSAPublicKey inside.
    print("  PEM length  : %d" % len(body))
    # crude: count leading-zero bits of modulus via DER scan
    import hashlib
    print("  sha256(DER) : %s" % hashlib.sha256(der).hexdigest())
    print("  sha1  (DER) : %s" % hashlib.sha1(der).hexdigest())
    # modulus size
    try:
        i = der.find(b"\x02")          # INTEGER (version)
        # walk: INTEGER len, INTEGER len (modulus)
        p = i
        def read_tlv(b, p):
            p += 1
            l = b[p]; p += 1
            if l & 0x80:
                n = l & 0x7f
                l = int.from_bytes(b[p:p+n], "big"); p += n
            return p, l
        p, _ = read_tlv(der, p)
        p, l = read_tlv(der, p)
        mod = der[p:p+l]
        mod = mod.lstrip(b"\x00")
        print("  modulus bits: %d" % (len(mod) * 8))
    except Exception as e:
        print("  modulus parse failed: %r" % e)

# --- context -------------------------------------------------------------
print()
print("=" * 78)
print("context immediately BEFORE the public key")
print("=" * 78)
i = blob.find(b"-----BEGIN PUBLIC KEY-----")
if i > 0:
    print(repr(blob[max(0, i - 800):i]))

print()
print("=" * 78)
print("context immediately AFTER the public key")
print("=" * 78)
j = blob.find(b"-----END PUBLIC KEY-----", i)
if j > 0:
    print(repr(blob[j:j + 800]))

print()
print("=" * 78)
print("context around the CA certificate (first CERTIFICATE block)")
print("=" * 78)
k = blob.find(b"-----BEGIN CERTIFICATE-----")
print("before:")
print(repr(blob[max(0, k - 500):k]))
e = blob.find(b"-----END CERTIFICATE-----", k)
print("after:")
print(repr(blob[e:e + 500]))

# --- what does the CA root name out? -------------------------------------
print()
print("=" * 78)
print("CA root subject / issuer strings present in the binary")
print("=" * 78)
for s in [b"CA root", b"KDE", b"Chuo-ku", b"2 Prod", b"KONAMI", b"Konami",
          b"konami"]:
    print("  %-16s %d" % (s.decode(), blob.count(s)))
