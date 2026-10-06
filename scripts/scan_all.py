"""Scan every string in every code file, under every plausible mode.

What we know for certain:
  * request  header pes-custom-encrypt: AES256, body 176 bytes
  * response header Content-Type application/json, body 2400 bytes
  * both lengths are multiples of 16, so CBC-with-padding is possible
  * a wrong key never yields printable ASCII or a gzip stream

What we do not know: the mode, the IV convention, or where the key comes
from. So this enumerates modes {CBC, CFB, OFB, CTR} with IV = first 16
bytes plus ECB, and variants of every string in libUE4.so, the dex files
and every apk.

Oracle (a pass is a pass): gunzip ok, or full msgpack decode, or every
byte printable ASCII. Random plaintext passing on 176 bytes is ~1e-76.
"""
import base64
import gzip
import hashlib
import os
import re
import sys
import zipfile

import msgpack
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = r"C:\Users\Administrator\AppData\Local\Temp\2"
SO = os.path.join(ROOT, "game", "libUE4.so")
LOG = os.path.join(ROOT, "rec2", "flows.log")
GAME = os.path.join(ROOT, "game")

# ---- recorded bodies ----------------------------------------------------
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

# two probes, one request and one response, so a mode that only fits one
# direction cannot masquerade as a hit
probes = [next(b for k, b in bodies if k == "RESP/CMD_GET_SERVER_ENV"),
          next(b for k, b in bodies if k == "REQ/CMD_GET_SERVER_ENV")]
print("probes: %s" % ", ".join("%dB" % len(p) for p in probes))

MODES = ("cbc", "cfb", "ofb", "ctr", "ecb")


def first_block(mode, key, blob):
    """Return the first 16 plaintext bytes under the given mode, or None."""
    try:
        if mode == "ecb":
            c = Cipher(algorithms.AES(key), modes.ECB())
            return c.decryptor().update(blob[:16])
        iv = blob[:16]
        ct = blob[16:]
        if not ct:
            return None
        if mode == "cbc":
            return Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(ct[:16])
        if mode == "ctr":
            c = Cipher(algorithms.AES(key), modes.CTR(iv))
            return c.encryptor().update(ct[:16])          # CTR keystream = encrypt(iv)
        if mode == "cfb":
            c = Cipher(algorithms.AES(key), modes.CFB(iv))
            return c.encryptor().update(b"\x00" * 16)[:len(ct[:16])] if False else \
                bytes(a ^ b for a, b in zip(ct[:16],
                      Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(iv)))
        if mode == "ofb":
            ks = Cipher(algorithms.AES(key), modes.OFB(iv)).encryptor().update(b"\x00" * 16)
            return bytes(a ^ b for a, b in zip(ct[:16], ks))
    except Exception:
        return None
    return None


def plaintext(mode, key, blob):
    if mode == "ecb":
        iv, ct = b"", blob
        if len(ct) % 16:
            return None
        return Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(ct)
    iv, ct = blob[:16], blob[16:]
    if not ct or len(ct) % 16:
        return None
    try:
        if mode == "cbc":
            return Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(ct)
        if mode == "ctr":
            return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(ct)
        if mode == "cfb":
            c = Cipher(algorithms.AES(key), modes.CFB(iv))
            return c.decryptor().update(ct)
        if mode == "ofb":
            return Cipher(algorithms.AES(key), modes.OFB(iv)).decryptor().update(ct)
    except Exception:
        return None
    return None


def good(pt):
    if not pt:
        return None
    if all(32 <= c < 127 or c in (9, 10, 13) for c in pt):
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
        return None


# first-byte shapes a real body can start with: gzip magic, JSON braces,
# msgpack map/array/str/int. Anything else cannot be a body.
PLAUSIBLE = set([0x1f, 0x7b, 0x5b, 0xc0, 0xc2, 0xc3, 0xca, 0xcb])
PLAUSIBLE |= set(range(0x80, 0x90))
PLAUSIBLE |= set(range(0xa0, 0xc0))
PLAUSIBLE |= set(range(0xd8, 0xdc))
PLAUSIBLE |= set(range(0xcc, 0xd5))


def variants(s):
    out = []
    if len(s) in (16, 24, 32):
        out.append(s)
    out.append(s.ljust(32, b"\x00")[:32])
    out.append(hashlib.sha256(s).digest())
    out.append(hashlib.sha512(s).digest()[:32])
    out.append(hashlib.md5(s).digest() * 2)
    out.append(hashlib.sha1(s).digest().ljust(32, b"\x00"))
    if len(s) >= 24:
        try:
            dec = base64.b64decode(s + b"=" * ((4 - len(s) % 4) % 4))
            if len(dec) in (16, 24, 32):
                out.append(dec)
        except Exception:
            pass
    return out


# ---- string sources -----------------------------------------------------
def strings_from_bytes(b, minlen=6, maxlen=200):
    out, cur = [], bytearray()
    for c in b:
        if 32 <= c < 127:
            cur.append(c)
        else:
            if minlen <= len(cur) <= maxlen:
                out.append(bytes(cur))
            cur.clear()
    if minlen <= len(cur) <= maxlen:
        out.append(bytes(cur))
    return out


sources = {}
sources["libUE4.so"] = strings_from_bytes(open(SO, "rb").read())
for fn in sorted(os.listdir(GAME)):
    if fn.endswith(".dex"):
        sources[fn] = strings_from_bytes(open(os.path.join(GAME, fn), "rb").read())
    elif fn.endswith(".apk"):
        try:
            z = zipfile.ZipFile(os.path.join(GAME, fn))
            buf = b"".join(z.read(n) for n in z.namelist() if n.endswith(".dex"))
            if buf:
                sources[fn] = strings_from_bytes(buf)
        except Exception as e:
            print("skip %s: %s" % (fn, e))

for k, v in sources.items():
    print("strings %-28s %d" % (k, len(v)))

all_s = []
seen_s = set()
for v in sources.values():
    for s in v:
        if s not in seen_s:
            seen_s.add(s)
            all_s.append(s)
print("unique strings: %d" % len(all_s))

# ---- the scan -----------------------------------------------------------
seen_keys = set()
tested = 0
cands = []          # keys that looked plausible on at least one probe
for s in all_s:
    for key in variants(s):
        if key in seen_keys:
            continue
        seen_keys.add(key)
        tested += 1
        for mi, mode in enumerate(MODES):
            fb = first_block(mode, key, probes[0])
            if fb is None or fb[0] not in PLAUSIBLE:
                continue
            fb2 = first_block(mode, key, probes[1])
            if fb2 is None or fb2[0] not in PLAUSIBLE:
                continue
            cands.append((key, mode, s))
            print("CANDIDATE key=%s mode=%s str=%r p0=%02x/%02x"
                  % (key.hex(), mode, s[:50], fb[0], fb2[0]))
    if tested % 250000 == 0:
        print("  ... %d keys, %d mode-candidates" % (tested, len(cands)))

print("keys tested: %d   survived first-byte filter: %d" % (tested, len(cands)))
if not cands:
    print("NO MATCH: no key/mode pair produced a plausible first byte on "
          "both probes")
    sys.exit(0)

print("--- full decrypt check ---")
for key, mode, s in cands:
    ok = 0
    kinds = set()
    for k, b in bodies:
        pt = plaintext(mode, key, b)
        g = good(pt)
        if g:
            ok += 1
            kinds.add(g)
    print("key=%s mode=%s str=%r passes %d/%d kinds=%s"
          % (key.hex(), mode, s[:50], ok, len(bodies), sorted(kinds)))
    if ok == len(bodies):
        print("MATCH key=%s mode=%s" % (key.hex(), mode))
