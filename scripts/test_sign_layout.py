"""Retest all 13 sign cookies with the byte layout the disassembly actually shows.

The earlier test only checked   HMAC(K, body) == sign_raw[0:20].
But 0x7b39a28 runs the classic two-pass HMAC and the second `final` APPENDS:

    inner = SHA1(ipad || body)
    outer = SHA1(opad || inner)
    sign_raw = inner || outer          -> exactly 40 bytes

which is precisely the observed shape (two distinct 20-byte halves).  A test
that only looked at the first 20 bytes would reject the right key.

The live probe just proved the server validates sign, so K cannot contain
/dev/urandom entropy -- it has to be something the server also knows.  The
only such literal in the function is the hardcoded seed.

Ends with a printed YES/NO over all 13 pairs at once.
"""
import base64
import hashlib
import hmac
import itertools
import re

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
MITM = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.mitm"

SEED = b"Xrq-RtAF_91MAE82"

raw = open(LOG, "rb").read().split(b"\n")
bodies, name = [], None
for line in raw:
    if line.startswith(b"### REQ POST"):
        m = re.search(rb"gate_([A-Z_]+)", line)
        name = m.group(1).decode() if m else "?"
    elif line.startswith(b"REQHEX: ") and name:
        bodies.append((name, bytes.fromhex(line[8:].strip().decode())))
        name = None

signs = [base64.b64decode(m.group(1))
         for m in re.finditer(rb"sign=([A-Za-z0-9+/=]+)", open(MITM, "rb").read())]

n = min(len(bodies), len(signs))
pairs = [(bodies[i][0], bodies[i][1], signs[i]) for i in range(n)]
print("pairs = %d   raw sign lengths = %s" % (n, sorted({len(s) for _, _, s in pairs})))
print()


def halves(key, msg, hf):
    """Reproduce 0x7b39a28 exactly: block-size pad, xor 0x36 / 0x5c, two passes."""
    blk = hf().block_size
    k = (key + b"\x00" * blk)[:blk]
    ip = bytes(c ^ 0x36 for c in k)
    op = bytes(c ^ 0x5c for c in k)
    inner = hf(ip + msg).digest()
    outer = hf(op + inner).digest()
    return inner, outer


KEYS = {
    "seed": SEED,
    "seed|": SEED + b"|",
    "seed-pipe0": SEED + b"|0",
    "seed*4": SEED * 4,
    "seed-upper": SEED.upper(),
    "sha256(seed)": hashlib.sha256(SEED).digest(),
    "seed-no-pad-64": SEED + b"\x00" * 48,
}

print("--- 40-byte form: inner || outer and outer || inner ---")
found = []
for kn, kv in KEYS.items():
    for hn, hf in (("sha1", hashlib.sha1), ("md5", hashlib.md5)):
        for order in ("io", "oi"):
            ok_all = True
            for _, b, s in pairs:
                i, o = halves(kv, b, hf)
                cand = (i + o) if order == "io" else (o + i)
                if cand != s:
                    ok_all = False
                    break
            if ok_all:
                found.append((kn, hn, order))
                print("  MATCH  key=%s  %s  order=%s" % (kn, hn, order))

if not found:
    # ---- also test the plain HMAC prefix, now that layout is understood ----
    print("  no 40-byte inner||outer match")
    print()
    print("--- plain HMAC(K, body) compared at the right offset ---")
    for kn, kv in KEYS.items():
        for hn, hf in (("sha1", hashlib.sha1), ("sha256", hashlib.sha256)):
            d = hf().digest_size
            for off in (0, 20, 40 - d):
                if off < 0:
                    continue
                if all(hmac.new(kv, b, hf).digest() == s[off:off + d]
                       for _, b, s in pairs):
                    found.append((kn, hn, "off%d" % off))
                    print("  MATCH  key=%s  HMAC-%s at offset %d" % (kn, hn, off))

print()
# ---------------------------------------------------------------- verdict --
tested = len(KEYS) * 2 * 2 + len(KEYS) * 2 * 3
if found:
    print("YES -- construction identified: %s" % (found,))
else:
    print("NO -- %d combinations tested against all %d pairs at once"
          % (tested, n))
