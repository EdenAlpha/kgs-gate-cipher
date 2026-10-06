"""Does the literal Xrq-RtAF_91MAE82 seed the 40-byte sign cookie?

Ghidra shows FUN_07c38a44 loads exactly two string literals:
    00c8f1b1  "Xrq-RtAF_91MAE82"   at 07c38aa4  (near the top)
    00cb6471  "sign="              at 07c38db8  (near the bottom)
i.e. it takes a 16-character seed, does something, then writes the cookie.

sign is 40 bytes = two SHA-1 digests. So the search is: build a pool of
SHA-1/HMAC-SHA-1/SHA-256-truncated values over every component we have
(seed, body, IV, ciphertext, msgid) and test every ordered PAIR of them
against all 13 recorded sign/body pairs at once.

A hit must reproduce all 13. One coincidence proves nothing.
"""
import base64
import hashlib
import hmac
import os
import re

ROOT = r"C:\Users\Administrator\AppData\Local\Temp\2"
MITM = os.path.join(ROOT, "rec2", "flows.mitm")
LOG = os.path.join(ROOT, "rec2", "flows.log")
SEED = b"Xrq-RtAF_91MAE82"

raw = open(LOG, "rb").read()
bodies, name = [], None
for line in raw.split(b"\n"):
    if line.startswith(b"### REQ POST"):
        m = re.search(rb"gate_([A-Z_]+)", line)
        name = m.group(1).decode() if m else "?"
    elif line.startswith(b"REQHEX: ") and name:
        bodies.append((name, bytes.fromhex(line[8:].strip().decode())))
        name = None

d = open(MITM, "rb").read()
signs = [base64.b64decode(m.group(1))
         for m in re.finditer(rb"sign=([A-Za-z0-9+/=]+)", d)]

n = min(len(bodies), len(signs))
pairs = [(bodies[i], signs[i]) for i in range(n)]
print("pairs: %d   seed: %r   sign bytes: %d" % (n, SEED.decode(), len(signs[0])))
for (nm, b), s in pairs[:3]:
    print("   %-34s %3dB  %s" % (nm, len(b), s.hex()[:32]))

# ---- pool of 20-byte halves -------------------------------------------
pool = {}          # label -> bytes


def add(label, val):
    if val is not None and len(val) == 20:
        pool[label] = val


for (nm, body) in pairs:
    break  # components that depend on the body are built per-pair below

BODY_COMPONENTS = ("body", "iv", "ct")


def halves(nm, body):
    """All 20-byte values we can build for this one pair."""
    iv, ct = body[:16], body[16:]
    mid = nm.encode()
    comps = {"seed": SEED, "body": body, "iv": iv, "ct": ct, "msgid": mid,
             "seed+body": SEED + body, "body+seed": body + SEED,
             "seed+iv": SEED + iv, "iv+seed": iv + SEED,
             "seed+ct": SEED + ct, "ct+seed": ct + SEED,
             "seed+msgid": SEED + mid, "msgid+seed": mid + SEED,
             "seed+iv+ct": SEED + iv + ct, "iv+seed+body": iv + SEED + body}
    out = {}
    for lab, v in comps.items():
        out["sha1(" + lab + ")"] = hashlib.sha1(v).digest()
        out["sha256(" + lab + ")[:20]"] = hashlib.sha256(v).digest()[:20]
        out["md5(" + lab + ")"] = hashlib.md5(v).digest()
        out["hmac(seed," + lab + ")"] = hmac.new(SEED, v, hashlib.sha1).digest()
    return out


# ---- test every ordered pair of halves ---------------------------------
first = halves(*pairs[0][0])
labels = sorted(first)
print("half-values per pair: %d   ordered pairs tried: %d" % (
    len(labels), len(labels) ** 2))

hits = []
for a in labels:
    for b in labels:
        ok = True
        for (nm, body), sg in pairs:
            h = halves(nm, body)
            if h[a] + h[b] != sg:
                ok = False
                break
        if ok:
            hits.append((a, b))
            print("MATCH: sign = %s || %s" % (a, b))

if not hits:
    print("NO MATCH: %d ordered half-pairs tested against %d pairs"
          % (len(labels) ** 2, n))

# also try a single 40-byte construction directly
print("--- single-value constructions ---")
single_hits = 0
for (nm, body), sg in pairs:
    iv, ct = body[:16], body[16:]
    cands = {
        "sha1(seed)+sha1(body)": hashlib.sha1(SEED).digest() + hashlib.sha1(body).digest(),
        "sha1(seed)+sha1(iv)": hashlib.sha1(SEED).digest() + hashlib.sha1(iv).digest(),
        "sha1(iv)+sha1(ct)": hashlib.sha1(iv).digest() + hashlib.sha1(ct).digest(),
        "hmac(seed,body)*2": hmac.new(SEED, body, hashlib.sha1).digest() * 2,
    }
    for lab, v in cands.items():
        if v == sg:
            print("MATCH: %s  (%s)" % (lab, nm))
            single_hits += 1
if not single_hits:
    print("NO MATCH: %d single constructions x %d pairs" % (4, n))
