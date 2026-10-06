"""Is the 40-byte sign cookie a hash of the request body we already have?

The mitm capture gives a sign value for each of the first 13 gate requests,
and flows.log gives those same 13 bodies in the same order -- so every
sign/body pair is known exactly. If sign is a keyless construction
(SHA1 of the body, of the IV, of the ciphertext, or a pair of them
concatenated) it will show up immediately, with no key guessing.

Prints the first match, or NO MATCH with how many constructions were tried.
"""
import base64
import hashlib
import hmac
import os
import re

ROOT = r"C:\Users\Administrator\AppData\Local\Temp\2"
MITM = os.path.join(ROOT, "rec2", "flows.mitm")
LOG = os.path.join(ROOT, "rec2", "flows.log")

# --- bodies, in capture order -----------------------------------------
raw = open(LOG, "rb").read()
bodies = []
name = None
for line in raw.split(b"\n"):
    if line.startswith(b"### REQ POST"):
        m = re.search(rb"gate_([A-Z_]+)", line)
        name = m.group(1).decode() if m else "?"
    elif line.startswith(b"REQHEX: ") and name:
        bodies.append((name, bytes.fromhex(line[8:].strip().decode())))
        name = None

# --- signs, in capture order ------------------------------------------
d = open(MITM, "rb").read()
signs = []
for m in re.finditer(rb"sign=([A-Za-z0-9+/=]+)", d):
    signs.append(base64.b64decode(m.group(1)))

print("bodies: %d   signs: %d" % (len(bodies), len(signs)))
n = min(len(bodies), len(signs))
print("sign lengths: %s" % sorted({len(s) for s in signs}))
if n == 0:
    print("NO MATCH: nothing to pair")
    raise SystemExit(0)

pairs = [(bodies[i], signs[i]) for i in range(n)]
print("pairs: %d   first: %s / %dB / sign[:8]=%s"
      % (n, pairs[0][0][0], len(pairs[0][0][1]), pairs[0][1][:8].hex()))

tried = set()


def check(label, fn):
    """True if the construction reproduces every paired sign."""
    tried.add(label)
    for (nm, body), sg in pairs:
        iv, ct = body[:16], body[16:]
        try:
            if fn(body, iv, ct) != sg:
                return False
        except Exception:
            return False
    print("MATCH: %s" % label)
    return True


# keyless constructions -- a 40-byte sign has to be two 20-byte digests,
# or a 20-byte digest plus something else we can name
constructs = {
    "sha1(body)":        lambda b, iv, ct: hashlib.sha1(b).digest(),
    "sha1(iv)":          lambda b, iv, ct: hashlib.sha1(iv).digest(),
    "sha1(ct)":          lambda b, iv, ct: hashlib.sha1(ct).digest(),
    "sha1(iv)||sha1(ct)": lambda b, iv, ct: hashlib.sha1(iv).digest() + hashlib.sha1(ct).digest(),
    "sha1(ct)||sha1(iv)": lambda b, iv, ct: hashlib.sha1(ct).digest() + hashlib.sha1(iv).digest(),
    "sha1(body)||sha1(iv)": lambda b, iv, ct: hashlib.sha1(b).digest() + hashlib.sha1(iv).digest(),
    "sha1(iv)||sha1(body)": lambda b, iv, ct: hashlib.sha1(iv).digest() + hashlib.sha1(b).digest(),
    "sha1(ct)||sha1(body)": lambda b, iv, ct: hashlib.sha1(ct).digest() + hashlib.sha1(b).digest(),
    "sha1(body)||sha1(ct)": lambda b, iv, ct: hashlib.sha1(b).digest() + hashlib.sha1(ct).digest(),
    "sha1(body)*2":      lambda b, iv, ct: hashlib.sha1(b).digest() * 2,
    "sha1(iv)*2":        lambda b, iv, ct: hashlib.sha1(iv).digest() * 2,
    "sha1(ct)*2":        lambda b, iv, ct: hashlib.sha1(ct).digest() * 2,
    "sha1(iv)+body":     lambda b, iv, ct: hashlib.sha1(iv + b).digest(),
    "sha1(body+iv)":     lambda b, iv, ct: hashlib.sha1(b + iv).digest(),
    "sha1(ct)+":         lambda b, iv, ct: hashlib.sha1(ct + b).digest(),
}

hits = [lab for lab, fn in constructs.items() if check(lab, fn)]
if not hits:
    print("NO MATCH: %d keyless constructions tested against %d pairs"
          % (len(tried), n))
    # show the shapes so the next step can be reasoned about
    print("sign[:4] per pair:")
    for (nm, body), sg in pairs[:6]:
        print("  %-34s %3dB  %s" % (nm, len(body), sg[:8].hex()))
