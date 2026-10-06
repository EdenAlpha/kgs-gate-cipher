"""AES-256 body key: test DERIVED keys the sliding-window scan could never find.

The 160,822,937-offset scan (NO) only tested contiguous 32-byte windows of
libUE4.so.  It is blind to any key that is COMPUTED, for example:

    key = SHA256(seed)                  <- derived, not stored
    key = seed || seed                  <- two copies, never adjacent in file
    key = seed || 16 zero bytes
    key = SHA256(seed "|" N)            <- N is per-request, from the sign
    key = (seed "|" N) padded to 32
    key = sign[0:32]                    <- the HMAC itself

Now that the sign is fully solved we KNOW N for every captured request, so
those per-request candidates become testable.

Method: parse REQ/RESP hex pairs from flows.log, keep gate pairs, try each
candidate against every gate response under both IV layouts, and report any
plaintext that is printable ASCII or gzip -- same acceptance rule as the scan.
"""
import hashlib
import os
import re
from itertools import islice

BASE = r"C:\Users\Administrator\AppData\Local\Temp\2"
LOG = os.path.join(BASE, "rec2", "flows.log")
MITM = os.path.join(BASE, "rec2", "flows.mitm")
OUT = os.path.join(BASE, "aes_derived.txt")
SEED = b"Xrq-RtAF_91MAE82"
GZIP = b"\x1f\x8b\x08"

out = []


def say(s=""):
    out.append(str(s))


# ------------------------------------------------------------- AES import ---
Cipher = algorithms = modes = None
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception as e:                                              # noqa: BLE001
    say("cryptography import failed: %s" % e)

if Cipher is None:
    open(OUT, "w", encoding="utf-8").write("\n".join(out))
    raise SystemExit("no AES library")


def looks_like_plain(b):
    if not b:
        return False
    if b[:3] == GZIP:
        return True
    return min(b) >= 0x20 and max(b) <= 0x7E


# --------------------------------------------------------------- corpus -----
lines = open(LOG, "rb").read().split(b"\n")
gate_pairs = []
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
            gate_pairs.append((name, pending, resp))
        pending = None
        name = None

say("gate REQ/RESP pairs: %d" % len(gate_pairs))
for nm, rq, rs in gate_pairs:
    say("   %-26s req=%-6d resp=%d" % (nm, len(rq), len(rs)))
say("")

# ------------------------------------------------------------ sign harvest ---
import base64
import struct

signs = [base64.b64decode(m.group(1))
         for m in re.finditer(rb"sign=([A-Za-z0-9+/=]+)", open(MITM, "rb").read())]
Ns = []
for s in signs:
    if len(s) >= 40:
        clock, rnd = struct.unpack("<II", s[32:40])
        Ns.append((rnd ^ clock) & 0xFFFFFFFF)
say("signs: %d   distinct N values: %d" % (len(signs), len(set(Ns))))
say("")

# -------------------------------------------------------- candidate keys -----
CANDS = []
def add(label, k):
    if isinstance(k, str):
        k = k.encode()
    if len(k) >= 16:
        CANDS.append((label, k))


add("seed || seed", SEED * 2)
add("seed || zeros(16)", SEED + b"\x00" * 16)
add("zeros(16) || seed", b"\x00" * 16 + SEED)
add("SHA256(seed)", hashlib.sha256(SEED).digest())
add("SHA256(seed|)", hashlib.sha256(SEED + b"|").digest())
add("SHA256('sign=')", hashlib.sha256(b"sign=").digest())
add("MD5(seed)||MD5(seed)", hashlib.md5(SEED).digest() * 2)
add("SHA1(seed)||SHA1(seed)", hashlib.sha1(SEED).digest() * 2)
add("SEED alone (16B)", SEED)

for i, N in enumerate(Ns):
    k = SEED + b"|" + str(N).encode()
    add("SHA256(seed|N%d)" % N, hashlib.sha256(k).digest())
    if len(k) >= 32:
        add("seed|N%d [:32]" % N, k[:32])
    else:
        add("seed|N%d +zeros" % N, k + b"\x00" * (32 - len(k)))
    if i >= 13:
        break

# the HMAC output itself, as a key
for i, s in enumerate(signs[:13]):
    if len(s) >= 32:
        add("sign%d[0:32]" % i, s[:32])
    add("SHA256(sign%d)" % i, hashlib.sha256(s).digest())

# de-dup
seen, uniq = set(), []
for lbl, k in CANDS:
    if k not in seen:
        seen.add(k)
        uniq.append((lbl, k))
CANDS = uniq
say("candidate keys: %d" % len(CANDS))
say("")

# ------------------------------------------------------------------ test -----
say("=" * 78)
say("RESULT")
say("=" * 78)

zero_iv = b"\x00" * 16
hits = []
tested = 0
for lbl, key in CANDS:
    if len(key) not in (16, 24, 32):
        # AES-192/256 only accept those; pad/truncate for information only
        key2 = (key + b"\x00" * 32)[:32]
    else:
        key2 = key
    klen = len(key2) * 8
    if klen not in (128, 192, 256):
        continue
    for nm, rq, rs in gate_pairs:
        for iv in (rs[:16], zero_iv):
            if len(rs) <= 16:
                continue
            try:
                dec = Cipher(algorithms.AES(key2), modes.CBC(iv)).decryptor()
                pt = dec.update(rs[16:]) + dec.finalize()
            except Exception:
                continue
            tested += 1
            if looks_like_plain(pt):
                hits.append((lbl, nm, "iv=resp[0:16]" if iv is not rs[:16] else "iv=zeros",
                             pt[:60]))
                say("  HIT  %-34s %-24s %s" % (lbl, nm,
                                                "iv=resp[0:16]" if iv is not rs[:16] else "iv=zeros"))
                say("        head: %r" % pt[:60])

say("")
say("decryptions attempted: %d" % tested)
if hits:
    print("YES")
else:
    say("NO -- no derived key unlocks any recorded gate response")
    print("NO")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
