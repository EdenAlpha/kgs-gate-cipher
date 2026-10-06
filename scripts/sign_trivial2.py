"""Re-run the trivial-key test with the hashes actually implied by the code.

Why the previous test (sign_trivial.py) cannot be trusted:
  * `halves()` hardcodes hashlib.sha1 and every layout used `d = hashlib.sha1`,
    so ONLY SHA-1 was ever tried.
  * yet the sign builder stores w9 = 0x20 into the MAC context at ctx+8, and
    0x20 = 32 bytes = a SHA-256-sized digest.  That was never tested.
  * the caller passes w1 = 0x28 (40) to base64, and the buffer at x29-0x38 is
    exactly 40 bytes (canary sits at x29-0x10), so a 40-byte value is encoded.

So: every plausible hash x every partial-write key, plus a sweep of the
number the stream writes (key = seed "|" N) for N in 0..99999.

A hit must match ALL recorded pairs -- one pair alone is not evidence.
"""
import base64
import hashlib
import hmac
import re
import sys

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
MITM = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.mitm"
SEED = b"Xrq-RtAF_91MAE82"

# ------------------------------------------------------------------ corpus --
raw = open(LOG, "rb").read().split(b"\n")
bodies, name = [], None
for line in raw:
    if line.startswith(b"### REQ POST"):
        m = re.search(rb"gate_([A-Z_]+)", line)
        name = m.group(1).decode() if m else None
    elif line.startswith(b"REQHEX: ") and name:
        bodies.append(bytes.fromhex(line[8:].strip().decode()))
        name = None

signs = [base64.b64decode(m.group(1))
         for m in re.finditer(rb"sign=([A-Za-z0-9+/=]+)", open(MITM, "rb").read())]
n = min(len(bodies), len(signs))
pairs = list(zip(bodies[:n], signs[:n]))
print("gate bodies = %d   signs = %d   pairs = %d" % (len(bodies), len(signs), n))
print("sign lengths = %s" % sorted({len(s) for _, s in pairs}))
if not pairs:
    sys.exit("no pairs -- parsing failed")

# ------------------------------------------------------------------ hashes --
# hmac.new() needs a no-arg FACTORY (something it can call to get a fresh
# hash object) -- passing a digest function raises TypeError.  Each entry is
# (label, factory).
CANDIDATES = ["sha1", "sha256", "sha224", "sha384", "sha512", "md5",
              "sha3_256", "sha3_512", "ripemd160", "sm3"]

HASHES = []


def _make_new(name):
    # hmac calls digest_cons(key) -- factory must accept optional data
    def make(data=None):
        h = hashlib.new(name)
        if data:
            h.update(data)
        return h
    return make


def _make_blake(dl):
    def make(data=None):
        h = hashlib.blake2b(digest_size=dl)
        if data:
            h.update(data)
        return h
    return make


for name_ in CANDIDATES:
    try:
        getattr(hashlib, name_)()
        HASHES.append((name_, getattr(hashlib, name_)))
    except Exception:
        try:
            hashlib.new(name_)
            HASHES.append((name_, _make_new(name_)))
        except Exception:
            pass

for dl in (40, 32, 20):
    try:
        hashlib.blake2b(digest_size=dl).digest()
        HASHES.append(("blake2b-%d" % dl, _make_blake(dl)))
    except Exception:
        pass

print("hashes available: %s" % ", ".join(h for h, _ in HASHES))

# -------------------------------------------------------------------- keys --
KEYS = [
    (b"", "empty (nothing landed)"),
    (b"|", "pipe only"),
    (SEED, "seed only"),
    (SEED + b"|", "seed + pipe (<< failed)"),
    (SEED + b"|0", "seed + pipe + 0"),
    (b"0", "number only"),
    (b"|" + SEED, "pipe + seed"),
    (SEED + b"|" + SEED, "seed pipe seed"),
    (SEED * 4, "seed x4 (long-key path)"),
    (SEED * 5, "seed x5"),
    (SEED + b"|0", "seed|0"),
    (b"Xrq-RtAF_91MAE82\n", "seed + newline"),
    (SEED + b"|" + b"0" * 10, "seed + pipe + 10 zeros"),
]


def halves(key, msg, hf):
    blk = hf().block_size
    k = (key + b"\x00" * blk)[:blk]
    # build via factory + update(): hf is a no-arg factory, not a digest fn
    h = hf()
    h.update(bytes(c ^ 0x36 for c in k) + msg)
    inner = h.digest()
    h = hf()
    h.update(bytes(c ^ 0x5c for c in k) + inner)
    outer = h.digest()
    return inner, outer


def ok(key, b, s, hf):
    """Does this key explain this (body, sign) under this hash?"""
    mac = hmac.new(key, b, hf).digest()
    d = len(mac)
    if s == mac:
        return True
    if len(s) >= d and (s[:d] == mac or s[-d:] == mac):
        return True
    i, o = halves(key, b, hf)
    if s == i + o:
        return True
    if len(s) >= 2 * d and (s[:2 * d] == i + o or s[-2 * d:] == i + o):
        return True
    # base64 form: maybe the sign text equals b64(mac) up to its length
    enc = base64.b64encode(mac)
    if s == enc[:len(s)] and len(s) <= len(enc):
        return True
    return False


# --------------------------------------------------------- stage A: keys ----
print()
print("=" * 70)
print("STAGE A  -- partial-write keys x every hash, against ALL %d pairs" % n)
print("=" * 70)
hitsA = []
for key, label in KEYS:
    for hname, hf in HASHES:
        if all(ok(key, b, s, hf) for b, s in pairs):
            hitsA.append((key, hname, label))
            print("  HIT  key=%r  hash=%s   (%s)" % (key, hname, label))

# ------------------------------------------ stage B: seed + "|" + number -----
print()
print("=" * 70)
print("STAGE B  -- key = seed | N  for N in 0..99999 (sha256, then sha1)")
print("=" * 70)
hitsB = []
b0, s0 = pairs[0]
for hname, hf in (("sha256", hashlib.sha256), ("sha1", hashlib.sha1),
                  ("blake2b-40", _make_blake(40))):
    for N in range(100000):
        k = SEED + b"|" + str(N).encode()
        if ok(k, b0, s0, hf):
            if all(ok(k, b, s, hf) for b, s in pairs):
                hitsB.append((k, hname, N))
                print("  HIT  N=%d  hash=%s" % (N, hname))
                break
            print("  partial (pair 0 only) N=%d hash=%s -- rejected" % (N, hname))

print()
if hitsA or hitsB:
    print("YES -- key found:")
    for k, h, lbl in hitsA + hitsB:
        print("   %r   [%s]   %s" % (k, h, lbl))
else:
    print("NO -- %d partial keys x %d hashes, plus N sweep 0..99999,"
          " all against %d pairs" % (len(KEYS), len(HASHES), n))
