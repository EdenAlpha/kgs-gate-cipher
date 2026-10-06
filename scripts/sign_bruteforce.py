"""Find the fixed MAC key for the `sign` cookie by sweeping libUE4.so's strings.

Established by live probe (see sign_probe2.txt):
  * a real sign for a DIFFERENT body -> 500
  * 40 random bytes                  -> 500
  * the body's own sign              -> 200, both pairs, hours after capture
  => sign is a real MAC over the body with a FIXED key the server also holds.

The disassembly of 0x7b39a28 gives the construction exactly: zero-pad the key
to the 64-byte block, xor with 0x36 (ipad) / 0x5c (opad), absorb ipad, absorb
the body, final -> inner; then reset, absorb opad, absorb inner, final ->
outer.  The 40-byte cookie is two 20-byte halves, so SHA-1.

Three layouts are tested because the tail of the function may overwrite rather
than append:

    HMAC-SHA1(K, body) == sign[0:20]
    inner || outer     == sign[0:40]
    outer || inner     == sign[0:40]

Key candidates: every printable run in libUE4.so, plus that run with the
hardcoded seed prepended or appended.  Pair 0 is used as a cheap filter, then
any survivor must match all 13 pairs at once.

Ends with a printed YES/NO.
"""
import base64
import hashlib
import hmac
import re
import struct

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
MITM = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.mitm"

SEED = b"Xrq-RtAF_91MAE82"

# ------------------------------------------------------------ oracle -------
raw = open(LOG, "rb").read().split(b"\n")
bodies, name = [], None
for line in raw:
    if line.startswith(b"### REQ POST"):
        m = re.search(rb"gate_([A-Z_]+)", line)
        name = m.group(1).decode() if m else "?"
    elif line.startswith(b"REQHEX: ") and name:
        bodies.append(bytes.fromhex(line[8:].strip().decode()))
        name = None
signs = [base64.b64decode(m.group(1))
         for m in re.finditer(rb"sign=([A-Za-z0-9+/=]+)", open(MITM, "rb").read())]
n = min(len(bodies), len(signs))
pairs = list(zip(bodies[:n], signs[:n]))
print("oracle: %d (body, sign) pairs, sign lengths %s"
      % (n, sorted({len(s) for _, s in pairs})))
b0, s0 = pairs[0]

# ----------------------------------------------------- candidate keys ------
d = open(SO, "rb").read()
runs = set(m.group(0) for m in re.finditer(rb"[\x20-\x7e]{4,80}", d))
print("printable runs >=4 chars in libUE4.so: %d" % len(runs))

keys = set(runs)
keys.add(SEED)
for r in runs:
    keys.add(SEED + r)
    keys.add(r + SEED)
print("total key candidates (run / seed+run / run+seed): %d" % len(keys))


def half(k, msg):
    blk = 64
    kk = (k + b"\x00" * blk)[:blk]
    ip = bytes(c ^ 0x36 for c in kk)
    op = bytes(c ^ 0x5c for c in kk)
    inner = hashlib.sha1(ip + msg).digest()
    outer = hashlib.sha1(op + inner).digest()
    return inner, outer


def matches(k):
    i, o = half(k, b0)
    return (i + o == s0) or (o + i == s0) or i == s0[:20] or o == s0[:20]


def matches_with(k, b, s):
    i, o = half(k, b)
    return (i + o == s) or (o + i == s) or i == s[:20] or o == s[:20]


hits = [k for k in keys if matches(k)]
print("survivors after pair-0 filter: %d" % len(hits))

confirmed = [k for k in hits if all(matches_with(k, b, s) for b, s in pairs)]


print()
if confirmed:
    print("YES -- key found:")
    for k in confirmed:
        print("   %r" % k)
else:
    print("NO -- %d key candidates x 3 layouts tested against pair 0; "
          "%d survivors re-checked against all %d pairs."
          % (len(keys), len(hits), n))
