"""Test the trivial-key hypothesis for the sign cookie.

The disassembly says the HMAC key is the content of an ostringstream that
receives, in order:

    write(seed, 16)   write("|", 1)   << (mt_random ^ clock_ns)

A random+time component cannot be verified by the server -- yet the live probe
proved the server DOES verify it (wrong sign -> 500, right sign -> 200) and
that recorded signs replay hours later.  The only consistent readings are:

  (a) the stream writes never land (sentry/ios not ready), so str() is empty,
      or only a prefix of them landed
  (b) the key is a runtime value we simply have not tried

This tests (a): every trivial key the partial-write cases could produce.
Ends with a printed YES/NO against all 13 pairs at once.
"""
import base64
import hashlib
import hmac
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
        bodies.append(bytes.fromhex(line[8:].strip().decode()))
        name = None
signs = [base64.b64decode(m.group(1))
         for m in re.finditer(rb"sign=([A-Za-z0-9+/=]+)", open(MITM, "rb").read())]
n = min(len(bodies), len(signs))
pairs = list(zip(bodies[:n], signs[:n]))
print("pairs = %d" % n)

# every partial state the stream could be left in
KEYS = [
    b"",                       # nothing landed
    b"|",                      # pipe landed, seed write failed
    SEED,                      # seed landed, pipe failed
    SEED + b"|",               # pipe landed, << failed
    SEED + b"|0",              # << landed with 0
    b"0",                      # only the number
    b"|" + SEED,               # order reversed
    b"|0" + SEED,
    SEED + SEED,
    SEED * 4,                  # long-key path (>=65 forces the copy branch)
    SEED * 5,
]


def halves(key, msg, hf=hashlib.sha1):
    blk = hf().block_size
    k = (key + b"\x00" * blk)[:blk]
    inner = hf(bytes(c ^ 0x36 for c in k) + msg).digest()
    outer = hf(bytes(c ^ 0x5c for c in k) + inner).digest()
    return inner, outer


def layouts(key, b, s):
    i, o = halves(key, b)
    d = hashlib.sha1
    return (i + o == s or o + i == s
            or hmac.new(key, b, d).digest() == s[:20]
            or hmac.new(key, b, d).digest() == s[20:]
            or i == s[:20] or o == s[20:])


hits = [k for k in KEYS if all(layouts(k, b, s) for b, s in pairs)]
print()
if hits:
    print("YES -- key found:")
    for k in hits:
        print("   %r" % k)
else:
    print("NO -- %d trivial keys x 5 layouts tested against all %d pairs at once"
          % (len(KEYS), n))
