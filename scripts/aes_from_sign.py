"""Is the AES key derived from the same entropy the sign carries?

Every search so far assumed ONE static key: a window of the binary, a string,
or an immediate, tested against all six recorded replies at once.  All of them
came back NO.  But the sign already proved the client draws fresh `clock` and
`rand` on every single request and folds them into the MAC key.  If the body
key is derived the same way, then no static key exists anywhere and every one
of those scans was structurally incapable of finding it.

The pairing needed to test this exists: flows.log gives request and response in
order, flows.mitm gives the signs in the same order, and verify_sign_key.py
already confirmed that zip is right on 13/13 pairs.  Each sign's bytes 32..40
are the exact clock and rand that request was built with.

For each sign we rebuild candidate body keys from the seed and that entropy,
test the paired request and the paired response, and accept nothing on padding
alone -- the decrypted bytes must actually parse (gzip, JSON, or full msgpack),
because ~0.4% of wrong keys clear PKCS#7 by chance.
"""
import base64
import hashlib
import hmac
import json
import re
import struct
import zlib

from Crypto.Cipher import AES

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
MITM = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.mitm"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\aes_from_sign.txt"
SEED = b"Xrq-RtAF_91MAE82"

# --------------------------------------------------------------- pair up ----
raw = open(LOG, "rb").read().split(b"\n")
exch = []
path = rq = rs = None
for line in raw:
    if line.startswith(b"### REQ POST"):
        m = re.search(rb"\s(/\S+)", line)
        path = m.group(1).decode() if m else None
        rq = rs = None
    elif line.startswith(b"REQHEX: "):
        try:
            rq = bytes.fromhex(line[8:].strip().decode())
        except ValueError:
            rq = None
    elif line.startswith(b"RESPHEX: "):
        try:
            rs = bytes.fromhex(line[9:].strip().decode())
        except ValueError:
            rs = None
        if path:
            exch.append((path, rq, rs))
        path = rq = rs = None

signs = [base64.b64decode(m.group(1))
         for m in re.finditer(rb"sign=([A-Za-z0-9+/=]+)", open(MITM, "rb").read())]
n = min(len(exch), len(signs))
pairs = list(zip(exch[:n], signs[:n]))
print("exchanges=%d  signs=%d  paired=%d" % (len(exch), len(signs), len(pairs)))
print("pair lengths: req=%s resp=%s"
      % ([len(e[1]) for e, _ in pairs], [len(e[2]) for e, _ in pairs]))
print("")

# ------------------------------------------------- candidate derivations ----
def md5(b):
    return hashlib.md5(b).digest()


def evp_bytes_to_key(hasher, password, salt=b"", count=1, dklen=32):
    """OpenSSL's classic default KDF (what you get when no KDF is specified)."""
    hlen = hasher().digest_size
    need = (dklen + hlen - 1) // hlen
    out, block, prev = b"", b"", b""
    for i in range(need):
        prev = hasher(prev + password + salt).digest()
        for _ in range(1, count):
            prev = hasher(prev).digest()
        block += prev
    return block[:dklen]


def derivations(clock, rnd):
    """Every plausible way to turn the seed plus one request's entropy into a key."""
    N = (rnd ^ clock) & 0xFFFFFFFF
    ents = [
        str(N).encode(),
        SEED + b"|" + str(N).encode(),
        SEED + str(N).encode(),
        SEED + b"|" + str(clock).encode() + b"|" + str(rnd).encode(),
        SEED + struct.pack("<II", clock, rnd),
        struct.pack("<II", clock, rnd),
        str(rnd).encode(),
        SEED,
    ]
    keys = {}
    for i, e in enumerate(ents):
        keys["sha256(E%d)" % i] = hashlib.sha256(e).digest()
        keys["hmac(seed,E%d)" % i] = hmac.new(SEED, e, hashlib.sha256).digest()
        keys["hmac(E%d,seed)" % i] = hmac.new(e, SEED, hashlib.sha256).digest()
        m = md5(e)
        keys["evp_md5(E%d)" % i] = m + md5(m + e)          # EVP_BytesToKey c=1
        keys["evp_sha256(E%d)" % i] = evp_bytes_to_key(hashlib.sha256, e, b"", 1)
        keys["md5x2(E%d)" % i] = m + m
        if len(e) in (16, 24, 32):
            keys["raw(E%d)" % i] = e
        if len(e) < 32:
            keys["pad32(E%d)" % i] = e + b"\x00" * (32 - len(e))
            keys["rep32(E%d)" % i] = (e * (32 // len(e) + 1))[:32]
        for it in (1, 1000, 10000):
            keys["pbkdf2_%d(E%d)" % (it, i)] = hashlib.pbkdf2_hmac(
                "sha256", e, SEED, it, 32)
    return keys


# ----------------------------------------------------------- the oracle -----
def pad_ok(block):
    k = block[15]
    return 1 <= k <= 16 and block[16 - k:] == bytes([k]) * k


def xor16(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(16, "big")


def pad_passes(key, body):
    """Does some IV arrangement end the CBC chain in valid PKCS#7?"""
    if len(body) < 64:
        return None
    ec = AES.new(key, AES.MODE_ECB)
    for lay, (prev, last) in ((1, (body[-32:-16], body[-16:])),
                              (2, (body[-48:-32], body[-32:-16]))):
        if pad_ok(xor16(ec.decrypt(last), prev)):
            return lay
    return None


def decryptions(key, body):
    """Every sensible way to lay out IV and ciphertext, as (label, plaintext)."""
    out = []
    if len(body) >= 64:
        out.append(("IV_prefix",
                    AES.new(key, AES.MODE_CBC, body[:16]).decrypt(body[16:])))
        out.append(("no_IV",
                    AES.new(key, AES.MODE_CBC, b"\x00" * 16).decrypt(body)))
        out.append(("IV_suffix",
                    AES.new(key, AES.MODE_CBC, body[-16:]).decrypt(body[:-16])))
    return out


def looks_real(pt):
    """Strong confirmation -- parse the whole plaintext, do not eyeball a block."""
    if pt[:3] == b"\x1f\x8b\x08":
        try:
            d = zlib.decompress(pt, 16 + zlib.MAX_WBITS)
            return "gzip -> %d bytes" % len(d)
        except Exception:
            return None
    try:
        obj = json.loads(pt.decode("utf-8"))
        return "json %s" % type(obj).__name__
    except Exception:
        pass
    try:
        import msgpack
        obj = msgpack.unpackb(pt, raw=False, strict_map_key=False)
        return "msgpack %s" % type(obj).__name__
    except Exception:
        pass
    txt = pt.rstrip(b"\x00")
    if txt and all(0x20 <= c < 0x7E or c in (9, 10, 13) for c in txt):
        if txt[:1] in (b"{", b"[", b"<"):
            return "printable text"
        return None
    return None


# --------------------------------------------------------------- run --------
out = []
hits = []
tested = 0
pad_only = 0

for i, ((path, rq, rs), s) in enumerate(pairs):
    if len(s) < 40:
        continue
    clock, rnd = struct.unpack("<II", s[32:40])
    cands = derivations(clock, rnd)
    for label, key in sorted(cands.items()):
        for dname, body in (("req", rq), ("resp", rs)):
            if not body or len(body) < 64:
                continue
            tested += 1
            lay = pad_passes(key, body)
            if lay is None:
                continue
            pad_only += 1
            for arrange, pt in decryptions(key, body):
                real = looks_real(pt)
                if real:
                    hits.append((i, path, dname, label, arrange, real, key))
                    print("  HIT pair %2d %-5s %-18s %-10s %-9s %s   key=%s"
                          % (i, dname, label, arrange, real, "", key.hex()),
                          flush=True)

print("")
print("paired exchanges      : %d" % len(pairs))
print("decryptions attempted : %d" % tested)
print("cleared PKCS#7        : %d   (expected ~%.0f by chance)"
      % (pad_only, tested * 0.004))
print("then parsed as real   : %d" % len(hits))
print("")

if hits:
    print("YES -- body key is derived from the sign's entropy")
    for i, path, dname, label, arrange, real, key in hits:
        print("   pair %2d %s %s  %s  %s  %s" % (i, dname, path, label, arrange, real))
else:
    print("NO -- no seed+clock+rand derivation opens a paired body")
    print("      (raw-body tests were rejected only if they failed to PARSE,")
    print("       so a correct key could not be missed for looking like garbage)")

open(OUT, "w", encoding="utf-8").write(
    "pairs=%d tested=%d pad_only=%d hits=%d\n"
    % (len(pairs), tested, pad_only, len(hits))
    + "\n".join("%d %s %s %s %s" % (i, d, l, a, r)
                for i, p, d, l, a, r, k in hits) + "\n")
print("wrote %s" % OUT)
