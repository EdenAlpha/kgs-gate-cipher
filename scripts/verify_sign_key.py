"""Final test: does the sign carry its own key material?

Hypothesis (from the disassembly of FUN_07c38a44):

    MAC buffer lives at x29-0x38 and is base64'd with an explicit length of 40.
      offsets  0..31 : HMAC-SHA256(key, body)      <- Final() writes 32 bytes
                       ([ctx+8] was set to 0x20 = 32)
      offsets 32..35 : stur w24, [x29, #-0x18]      <- clock   (u32 LE)
      offsets 36..39 : stur w0,  [x29, #-0x14]      <- random  (u32 LE)

    key = b"Xrq-RtAF_91MAE82" + b"|" + str(random ^ clock)   (unsigned decimal)

The server can therefore rebuild the key from the sign it just received -- which
is exactly what reconciles "key contains clock+random" with "a recorded sign
replays successfully hours later".

Reports per-pair, then a single YES/NO against all 13 pairs.
"""
import base64
import hashlib
import hmac
import re
import struct

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
MITM = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.mitm"
SEED = b"Xrq-RtAF_91MAE82"

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
print("pairs = %d   sign bytes = %s" % (n, sorted({len(s) for _, s in pairs})))

HASHES = [("sha256", hashlib.sha256), ("sha1", hashlib.sha1),
          ("sha384", hashlib.sha384), ("sha512", hashlib.sha512),
          ("md5", hashlib.md5), ("sha224", hashlib.sha224)]

# layout variants: where the entropy sits, and in what byte order
LAYOUTS = [
    ("mac@0:32 | clock@32 LE | rand@36 LE", "clock_rand", "<"),
    ("mac@0:32 | rand@32 LE | clock@36 LE", "rand_clock", "<"),
    ("mac@0:32 | clock@32 BE | rand@36 BE", "clock_rand", ">"),
    ("mac@0:32 | rand@32 BE | clock@6 BE", "rand_clock", ">"),
]


def candidate_keys(s, order, endian):
    """Every key the byte layout could imply."""
    a, b = struct.unpack(endian + "II", s[32:40])
    if order == "clock_rand":
        clock, rnd = a, b
    else:
        rnd, clock = a, b
    combos = [
        rnd ^ clock,
        (rnd ^ clock) & 0x1FFFFFFF,          # mask to the 29-bit draw
        rnd,
        clock,
        (rnd + clock) & 0xFFFFFFFF,
        (clock - rnd) & 0xFFFFFFFF,
    ]
    return combos, clock, rnd


found = []
print()
CASES = [("clock_rand", "<", "clock@32 LE rand@36 LE"),
         ("rand_clock", "<", "rand@32 LE clock@36 LE"),
         ("clock_rand", ">", "clock@32 BE rand@36 BE"),
         ("rand_clock", ">", "rand@32 BE clock@36 BE")]
for order, endian, oname in CASES:
    for hname, hf in HASHES:
        good = 0
        firstkey = None
        dlen = hf().digest_size
        for body, s in pairs:
            if len(s) < 40:
                continue
            combos, clock, rnd = candidate_keys(s, order, endian)
            hit = None
            for N in combos:
                key = SEED + b"|" + str(N).encode()
                if hmac.new(key, body, hf).digest() == s[:dlen]:
                    hit = (N, key)
                    break
            if hit:
                good += 1
                firstkey = firstkey or hit
        if good == len(pairs):
            print("YES  layout=%s  hash=%s  all %d pairs" % (oname, hname, good))
            found.append((oname, hname, firstkey))
            break
    if found:
        break

# ---- explicit, readable single-layout run (the primary hypothesis) --------
print()
print("=" * 72)
print("PRIMARY: mac@0:32, clock@32 LE, rand@36 LE, key = seed|str(rand^clock)")
print("=" * 72)
ok_count = 0
for i, (body, s) in enumerate(pairs):
    clock, rnd = struct.unpack("<II", s[32:40])
    N = (rnd ^ clock) & 0xFFFFFFFF
    key = SEED + b"|" + str(N).encode()
    mac = hmac.new(key, body, hashlib.sha256).digest()
    match = (mac == s[:32])
    ok_count += 1 if match else 0
    print("  pair %2d  clock=%-11u rand=%-11u N=%-11u sha256:%s"
          % (i, clock, rnd, N, "MATCH" if match else "no"))

print()
if ok_count == len(pairs):
    print("YES -- key recovered and verified against ALL %d pairs" % len(pairs))
elif ok_count:
    print("PARTIAL -- %d of %d pairs matched" % (ok_count, len(pairs)))
else:
    print("NO -- primary layout failed")

if found:
    print()
    print("other layouts that matched everything:")
    for oname, hname, firstkey in found:
        print("   %s  [%s]  first N=%s" % (oname, hname, firstkey[0]))
