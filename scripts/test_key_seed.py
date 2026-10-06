"""Offline test: can the shipped constant produce the gate body key?

Two questions, one answer each, printed as YES/NO:

  Q1  Does a key derived from `CgkI2KWEy_UIEAIQTw` (found in libUE4.so at
      0x9c689b, 277 bytes from the gate/gate_ URL builder) decrypt a real
      recorded gate body?
  Q2  If not, does anything else offline -- the session auth_code -- ?

A body is IV[16] || AES-256-CBC(key, ct), ct = gzip(msgpack(...)). So the
test is: decrypt, gunzip, and look for messagepack structure. No guessing
about plaintext -- gunzip either succeeds or it raises.
"""
import base64
import gzip
import hashlib
import os
import re
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))
SECRET = b"CgkI2KWEy_UIEAIQTw"          # libUE4.so @ 0x9c689b
LOG = os.path.join(HERE, "rec2", "flows.log")
AUTH_FILE = None                          # filled in if gamedata is present

# ---- test bodies -------------------------------------------------------
raw = open(LOG, "rb").read()
bodies = []
cur_name, cur_hex = None, None
for line in raw.split(b"\n"):
    if line.startswith(b"### REQ POST"):
        cur_name = re.search(rb"gate_([A-Z_]+)", line).group(1).decode()
        cur_hex = None
    elif line.startswith(b"REQHEX: ") and cur_name:
        cur_hex = line[8:].strip()
        bodies.append((cur_name, bytes.fromhex(cur_hex.decode())))
        cur_name = None

print("test bodies: %d (first: %s, %d bytes)" % (
    len(bodies), bodies[0][0], len(bodies[0][1])))


def looks_like_msgpack(b):
    # msgpack fixmap/fixarray/str/int prefixes the payload types a gate
    # response would use. Any of these is enough to call it a hit.
    if not b:
        return False
    t = b[0]
    return (0x80 <= t <= 0x8f) or (0x90 <= t <= 0x9f) or t in (
        0xa0, 0xc0, 0xc2, 0xc3) or (0xd8 <= t <= 0xdb) or t in (0xca, 0xcb)


def try_key(name, key, ct):
    if len(key) not in (16, 24, 32):
        return False
    try:
        dec = Cipher(algorithms.AES(key), modes.CBC(ct["iv"])).decryptor()
        pt = dec.update(ct["body"]) + dec.finalize()
        try:
            pt = gzip.decompress(pt)
        except Exception:
            pass
        return looks_like_msgpack(pt)
    except Exception:
        return False


def run(label, candidates):
    """Print YES + the winning key, or NO + how many were tried."""
    tried = 0
    for name, key in candidates:
        tried += 1
        for bname, blob in bodies[:6]:
            iv, body = blob[:16], blob[16:]
            if try_key(name, key, {"iv": iv, "body": body}):
                print("MATCH key=%s  body=%s" % (key.hex(), bname))
                print("YES: %s" % label)
                return True
    print("NO: %s -- %d candidates x %d bodies, no match"
          % (label, tried, min(6, len(bodies))))
    return False


# ---- candidate set A: the shipped constant --------------------------------
cands = []
cands.append(("raw19-pad", SECRET.ljust(32, b"\x00")))
cands.append(("raw19-trunc", SECRET[:32]))
cands.append(("sha256", hashlib.sha256(SECRET).digest()))
cands.append(("md5x2", hashlib.md5(SECRET).digest() * 2))
cands.append(("sha1-pad", hashlib.sha1(SECRET).digest().ljust(32, b"\x00")))
for salt in (b"gate", b"pes22", b"konami", b"sign", b""):
    cands.append(("sha256(salt+sec)", hashlib.sha256(salt + SECRET).digest()))
    cands.append(("sha256(sec+salt)", hashlib.sha256(SECRET + salt).digest()))
run("constant CgkI2KWEy_UIEAIQTw", cands)

# ---- candidate set B: the per-session auth_code --------------------------
ac = None
if AUTH_FILE and os.path.exists(AUTH_FILE):
    m = re.search(rb'"auth_code":"([0-9a-f]+)"', open(AUTH_FILE, "rb").read())
    if m:
        ac = m.group(1)
if ac:
    cands = [("sha256(auth)", hashlib.sha256(ac).digest()),
             ("raw-hex-pad", bytes.fromhex(ac.decode()).ljust(32, b"\x00"))]
    run("session auth_code", cands)
else:
    print("SKIP: no local auth_code file -- session set B not tested")

print("DONE")
