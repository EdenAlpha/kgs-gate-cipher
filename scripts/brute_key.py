"""Brute-force the gate body key with a criterion that cannot false-positive.

A hit must do one of two things, both of which random garbage essentially
never does:

  * gunzip cleanly (magic 1f 8b must survive decryption), or
  * decode as msgpack all the way to the last byte.

The earlier run used a loose "looks like msgpack" byte-prefix check and
matched on random data. That reported MATCH and it was wrong: 0 of 21
bodies gunzipped. This version prints PASS only on the strict tests.
"""
import gzip
import hashlib
import os
import re
import sys

import msgpack
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))
SECRET = b"CgkI2KWEy_UIEAIQTw"
raw = open(os.path.join(HERE, "rec2", "flows.log"), "rb").read()

bodies, rname, name = [], None, None
for line in raw.split(b"\n"):
    if line.startswith(b"### REQ POST"):
        m = re.search(rb"gate_([A-Z_]+)", line)
        name = m.group(1).decode() if m else "?"
    elif line.startswith(b"### RESP POST"):
        m = re.search(rb"gate_([A-Z_]+)", line)
        rname = m.group(1).decode() if m else "?"
    elif line.startswith(b"REQHEX: ") and name:
        bodies.append(("REQ", name, bytes.fromhex(line[8:].strip().decode())))
        name = None
    elif line.startswith(b"RESPHEX: ") and rname:
        bodies.append(("RESP", rname, bytes.fromhex(line[8:].strip().decode())))
        rname = None

print("bodies: %d (%d req / %d resp)" % (
    len(bodies), sum(1 for b in bodies if b[0] == "REQ"),
    sum(1 for b in bodies if b[0] == "RESP")))


def decrypt(key, blob, layout):
    if layout == "iv16":
        iv, ct = blob[:16], blob[16:]
    elif layout == "iv0":
        iv, ct = b"\x00" * 16, blob
    elif layout == "tail16":
        iv, ct = blob[-16:], blob[:-16]
    else:
        return None
    if len(ct) % 16 or not ct:
        return None
    try:
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return d.update(ct) + d.finalize()
    except Exception:
        return None


def strict(pt):
    """True only if the plaintext is provably real."""
    if pt is None:
        return None
    try:
        return ("gzip", gzip.decompress(pt))
    except Exception:
        pass
    try:
        ob = msgpack.unpackb(pt, raw=False, strict_map_key=False)
        if ob is not None:
            return ("msgpack", ob)
    except Exception:
        pass
    return None


def candidates():
    out = []
    # the shipped constant, every padding scheme
    out += [("raw-ljust0", SECRET.ljust(32, b"\x00")),
            ("raw-rjust0", SECRET.rjust(32, b"\x00")),
            ("raw-left", SECRET[:32]),
            ("sha256", hashlib.sha256(SECRET).digest()),
            ("sha512-32", hashlib.sha512(SECRET).digest()[:32]),
            ("md5x2", hashlib.md5(SECRET).digest() * 2),
            ("sha1-ljust", hashlib.sha1(SECRET).digest().ljust(32, b"\x00"))]
    for salt in (b"", b"gate", b"Gate", b"pes22", b"pes", b"PES", b"konami",
                 b"Konami", b"efootball", b"sign", b"check_sum", b"aes256",
                 b"AES256", b"pes-custom-encrypt", b"GateInfo"):
        out.append(("sha256(s+k)", hashlib.sha256(salt + SECRET).digest()))
        out.append(("sha256(k+s)", hashlib.sha256(SECRET + salt).digest()))
        out.append(("hmac", hashlib.pbkdf2_hmac("sha256", SECRET, salt, 1, 32)))
    # session material that is known locally
    for s in (b"2024123327", b"ASMH685222982", b"online_user_id_data.dat",
              b"jp.konami.pesam", b"pes22-game.cs.konami.net"):
        out.append(("sha256(sess)", hashlib.sha256(s).digest()))
        out.append(("sha256(s+k)", hashlib.sha256(s + SECRET).digest()))
        out.append(("sha256(k+s)", hashlib.sha256(SECRET + s).digest()))
    return out


cands = candidates()
layouts = ("iv16", "iv0", "tail16")
print("candidates: %d  layouts: %d  tests: %d" % (
    len(cands), len(layouts), len(cands) * len(layouts)))

# screen on one request body first (cheapest), confirm on all if it hits
probe = next(b for b in bodies if b[0] == "REQ")
hits = []
for nm, key in cands:
    if len(key) not in (16, 24, 32):
        continue
    for lay in layouts:
        pt = strict(decrypt(key, probe[2], lay))
        if pt:
            hits.append((nm, key, lay, pt[0]))

if not hits:
    print("NO MATCH: %d candidates x %d layouts on 1 body, "
          "and 0 passed gunzip/msgpack" % (len(cands), len(layouts)))
    sys.exit(0)

print("candidates that passed the probe: %d" % len(hits))
for nm, key, lay, kind in hits:
    good = 0
    for k, bnm, blob in bodies:
        if strict(decrypt(key, blob, lay)):
            good += 1
    print("CANDIDATE %-14s layout=%-7s %s  passes %d/%d bodies"
          % (nm, lay, key.hex(), good, len(bodies)))
    if good == len(bodies):
        print("MATCH key=%s" % key.hex())
