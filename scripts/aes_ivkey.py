"""Is the AES key derived from the IV that rides along with each message?

Why this is the leading hypothesis now:
  * 160,822,937 contiguous-window tests against libUE4.so  -> NO
      so the key is not stored as 32 raw bytes in the file
  * 61 seed/sign-derived candidates x 21 gate responses    -> NO
      so it is not built from the sign's fixed seed either
  * every recorded request and response length is a multiple of 16
      -> both directions really are AES-CBC
  * the sign just proved this codebase likes to carry key material
      inside the message itself (clock+random at offsets 32..39)

If key = f(IV) where IV = first 16 bytes of the message, then:
  - the key never exists in the file      (matches the window scan)
  - it differs per message                (matches "runtime only")
  - the server derives it from what it received (self-consistent)

For each construction, EVERY gate response must unlock -- a construction that
only opens one message is a coincidence, not the answer.
"""
import hashlib
import os
import re

BASE = r"C:\Users\Administrator\AppData\Local\Temp\2"
LOG = os.path.join(BASE, "rec2", "flows.log")
OUT = os.path.join(BASE, "aes_ivkey.txt")
SEED = b"Xrq-RtAF_91MAE82"
GZIP = b"\x1f\x8b\x08"

out = []


def say(s=""):
    out.append(str(s))


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def looks_like_plain(b):
    if not b:
        return False
    if b[:3] == GZIP:
        return True
    return min(b) >= 0x20 and max(b) <= 0x7E


# --------------------------------------------------------------- corpus -----
lines = open(LOG, "rb").read().split(b"\n")
msgs = []
name = None
pending = None
for ln in lines:
    if ln.startswith(b"### REQ POST"):
        m = re.search(rb"gate_([A-Z_]+)", ln)
        name = m.group(1).decode() if m else None
        pending = None
    elif ln.startswith(b"REQHEX: ") and name:
        try:
            pending = bytes.fromhex(ln[8:].strip().decode())
        except Exception:
            pending = None
    elif ln.startswith(b"RESPHEX: ") and pending is not None:
        try:
            resp = bytes.fromhex(ln[9:].strip().decode())
        except Exception:
            resp = None
        if resp:
            msgs.append(("REQ", name, pending))
            msgs.append(("RESP", name, resp))
        pending = None
        name = None

# also every gate-shaped body regardless of pairing (more data points)
allbodies = [b for dirn, nm, b in msgs if b and len(b) >= 32]
say("gate messages: %d   (req+resp)" % len(msgs))
say("bodies >= 32 B: %d" % len(allbodies))
say("length mod 16 = %s" % sorted({len(b) % 16 for b in allbodies}))
say("")

# ------------------------------------------------------- constructions ------
# each: (label, key_fn(iv, body))   -- key must be 16/24/32 bytes
CONSTS = [b"", SEED, b"pes22", b"pes-custom-encrypt", b"AES256",
          b"pes22-game", b"konami", b"eFootball"]

def k32(x):
    return hashlib.sha256(x).digest()


CONSTRUCTS = [
    ("key = SHA256(iv)", lambda iv, body: hashlib.sha256(iv).digest()),
    ("key = iv || iv", lambda iv, body: iv + iv),
    ("key = MD5(iv)||MD5(iv)", lambda iv, body: hashlib.md5(iv).digest() * 2),
    ("key = SHA1(iv) + SHA1(iv)[:12]", lambda iv, body:
        hashlib.sha1(iv).digest() + hashlib.sha1(iv).digest()[:12]),
    ("key = SHA256(iv||iv)", lambda iv, body: hashlib.sha256(iv + iv).digest()),
    ("key = SHA256(SEED||iv)", lambda iv, body: hashlib.sha256(SEED + iv).digest()),
    ("key = SHA256(iv||SEED)", lambda iv, body: hashlib.sha256(iv + SEED).digest()),
    ("key = SHA256('sign='||iv)", lambda iv, body: hashlib.sha256(b"sign=" + iv).digest()),
    ("key = SHA256(iv||body[:64])", lambda iv, body:
        hashlib.sha256(iv + body[:64]).digest()),
    ("key = SHA256(body[:16])", lambda iv, body: hashlib.sha256(body[:16]).digest()),
    ("key = SHA256(iv||SEED||iv)", lambda iv, body:
        hashlib.sha256(iv + SEED + iv).digest()),
]
for c in CONSTS:
    CONSTRUCTS.append(("key = SHA256(%r||iv)" % c[:12],
                       lambda iv, body, c=c: hashlib.sha256(c + iv).digest()))
    CONSTRUCTS.append(("key = SHA256(iv||%r)" % c[:12],
                       lambda iv, body, c=c: hashlib.sha256(iv + c).digest()))

say("constructions tested: %d" % len(CONSTRUCTS))
say("")

# ------------------------------------------------------------------ test -----
say("=" * 78)
say("RESULT  (a construction must open EVERY body, not just one)")
say("=" * 78)

zero = b"\x00" * 16
results = []
for label, fn in CONSTRUCTS:
    opened = 0
    detail = []
    for body in allbodies:
        iv = body[:16]
        try:
            key = fn(iv, body)
        except Exception:
            continue
        if len(key) not in (16, 24, 32):
            continue
        good = False
        for iv_used in (iv, zero):
            try:
                dec = Cipher(algorithms.AES(key), modes.CBC(iv_used)).decryptor()
                pt = dec.update(body[16:]) + dec.finalize()
            except Exception:
                continue
            if looks_like_plain(pt):
                good = True
                break
        if good:
            opened += 1
            detail.append(label)
    if opened:
        results.append((opened, label))

results.sort(reverse=True)
for opened, label in results[:15]:
    say("  opened %3d / %d   %s" % (opened, len(allbodies), label))
if not results:
    say("  (no construction opened even one body)")

say("")
best = results[0][0] if results else 0
if best == len(allbodies):
    print("YES -- construction opens all %d bodies" % len(allbodies))
elif best:
    print("PARTIAL -- best %d/%d" % (best, len(allbodies)))
else:
    print("NO")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
