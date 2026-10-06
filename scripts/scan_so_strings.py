"""Find the gate body key by testing every string in libUE4.so as key material.

Oracle -- a candidate passes only if a real recorded body decrypts to
something that random bytes cannot be:

    * gunzip succeeds, or
    * the whole thing decodes as msgpack, or
    * every byte is printable ASCII (the gate answers application/json,
      and the 2400-byte response for CMD_GET_SERVER_ENV is JSON)

For a wrong key the probability that 176 random bytes all land in the
printable range is about 1e-76, so a pass is a real pass.

Candidates per string s:  s as a key (if 16/24/32 bytes), zero-padded
truncations, sha256, sha512[:32], md5*2, sha1 padded, and base64 decode.
"""
import base64
import gzip
import hashlib
import os
import re
import sys

import msgpack
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"

data = open(LOG, "rb").read()
bodies, name, rname = [], None, None
for line in data.split(b"\n"):
    if line.startswith(b"### REQ POST"):
        m = re.search(rb"gate_([A-Z_]+)", line)
        name = m.group(1).decode() if m else "?"
    elif line.startswith(b"### RESP POST"):
        m = re.search(rb"gate_([A-Z_]+)", line)
        rname = m.group(1).decode() if m else "?"
    elif line.startswith(b"REQHEX: ") and name:
        bodies.append(("REQ/" + name, bytes.fromhex(line[8:].strip().decode())))
        name = None
    elif line.startswith(b"RESPHEX: ") and rname:
        bodies.append(("RESP/" + rname, bytes.fromhex(line[8:].strip().decode())))
        rname = None

# the JSON response is the best probe: its first byte must be { or [
probe = next(b for k, b in bodies if k.startswith("RESP/CMD_GET_SERVER_ENV"))
print("probe: RESP/CMD_GET_SERVER_ENV %d bytes" % len(probe))


def printable(pt):
    return bool(pt) and all(32 <= c < 127 or c in (9, 10, 13) for c in pt)


def good(pt):
    if pt is None:
        return False
    if printable(pt):
        return "json"
    try:
        gzip.decompress(pt)
        return "gzip"
    except Exception:
        pass
    try:
        msgpack.unpackb(pt, raw=False, strict_map_key=False)
        return "msgpack"
    except Exception:
        return False


def test(key, blob, layout="iv16"):
    if layout == "iv16":
        iv, ct = blob[:16], blob[16:]
    elif layout == "iv0":
        iv, ct = b"\x00" * 16, blob
    else:
        return None
    if len(ct) % 16 or not ct or len(key) not in (16, 24, 32):
        return None
    try:
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return good(d.update(ct) + d.finalize())
    except Exception:
        return None


def variants(s):
    out = []
    if len(s) in (16, 24, 32):
        out.append(("raw", s))
    out.append(("pad0", s.ljust(32, b"\x00")[:32]))
    out.append(("sha256", hashlib.sha256(s).digest()))
    out.append(("sha512", hashlib.sha512(s).digest()[:32]))
    out.append(("md5x2", hashlib.md5(s).digest() * 2))
    out.append(("sha1p", hashlib.sha1(s).digest().ljust(32, b"\x00")))
    if len(s) >= 24:
        try:
            pad = s + b"=" * ((4 - len(s) % 4) % 4)
            dec = base64.b64decode(pad, validate=False)
            if len(dec) in (16, 24, 32):
                out.append(("b64", dec))
        except Exception:
            pass
    return out


# ---- gather strings -----------------------------------------------------
blob = open(SO, "rb").read()
print("libUE4.so: %d bytes" % len(blob))
strings = []
cur = bytearray()
for c in blob:
    if 32 <= c < 127:
        cur.append(c)
    else:
        if 6 <= len(cur) <= 200:
            strings.append(bytes(cur))
        cur.clear()
if 6 <= len(cur) <= 200:
    strings.append(bytes(cur))
print("strings: %d" % len(strings))

seen = set()
tested = 0
hits = []
for s in strings:
    for tag, key in variants(s):
        if key in seen:
            continue
        seen.add(key)
        tested += 1
        r = test(key, probe)
        if r:
            hits.append((tag, key, s, r))
            print("PARTIAL HIT %s key=%s str=%r -> %s"
                  % (tag, key.hex(), s[:60], r))
    if tested % 200000 == 0:
        print("  ... %d keys tested, %d hits" % (tested, len(hits)))

print("tested %d distinct keys over %d strings" % (tested, len(strings)))

if not hits:
    print("NO MATCH: 0 keys passed the oracle on the probe body")
    sys.exit(0)

print("--- confirming on all %d bodies ---" % len(bodies))
for tag, key, s, r in hits:
    ok = 0
    kinds = set()
    for k, b in bodies:
        rr = test(key, b)
        if rr:
            ok += 1
            kinds.add(rr)
    print("key=%s (%s, str=%r) passes %d/%d kinds=%s"
          % (key.hex(), tag, s[:60], ok, len(bodies), sorted(kinds)))
    if ok == len(bodies):
        print("MATCH key=%s" % key.hex())
