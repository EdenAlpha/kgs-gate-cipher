"""Try the two recovered keys against every captured gate body.

Wire framing established in walk_enc.txt: the sender prepends 8 bytes taken
from state+0x4c, and the decrypt path requires len>=9 and len%8==0, strips 8,
then hands the remainder to vtable[6] with w2 = #8 (mode 0) or #0x10 (mode 1).

Observed lengths confirm the framing: every captured body minus 8 is an exact
multiple of 8, and minus 16 an exact multiple of 16 -- so both an 8-byte-block
cipher with an 8-byte prefix and a 16-byte-block cipher with a 16-byte prefix
survive the arithmetic.  That cannot be settled by counting, so it is settled
by trying both.

Candidate keys (derive_keys.py):
    KEY A  56 bytes  -> context 0xa4a98d8  (mode 0)   56 = Blowfish max key
    KEY B  32 bytes  -> context 0xa4a98d0  (mode 1)   32 = AES-256 key

Oracle is the strict one agreed for this work: the WHOLE plaintext must gunzip
cleanly, decode fully as msgpack, parse as JSON, or be entirely printable
ASCII.  Padding that merely happens to clear, or a plausible-looking first
block, is not a hit.
"""
import gzip
import json
import re
import sys

from Crypto.Cipher import (AES, ARC2, ARC4, Blowfish, CAST, ChaCha20, DES,
                           DES3, Salsa20)

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\try_decrypt.txt"

KEY_A = bytes.fromhex(
    "a2df2319c1e5ec1e206a724b5709de77b728609eedbbfaaa939ab3d7bb4d7f77"
    "c135147cb76b4c2efa0249fad843a9d5cc38cae19cc41c90")
KEY_B = bytes.fromhex(
    "43740981523cdc171e71de2ccab1a5a9b86f4b833196c55facd4bd25846c33f5")

try:
    import msgpack
except Exception:
    msgpack = None

out = []


def say(s=""):
    out.append(str(s))


# ----------------------------------------------------------------- corpus ---
def load_bodies():
    recs = []
    cur = None
    for line in open(LOG, "r", encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        m = re.match(r"### (REQ|RESP) POST (\S+)", line)
        if m:
            cur = {"kind": m.group(1), "path": m.group(2)}
            recs.append(cur)
            continue
        if cur is None:
            continue
        if line.startswith("REQHEX: "):
            cur["hex"] = line[8:].strip()
        elif line.startswith("RESPHEX: "):
            cur["hex"] = line[9:].strip()
    good = []
    for r in recs:
        h = r.get("hex")
        if not h or len(h) % 2:
            continue
        r["body"] = bytes.fromhex(h)
        if "gate" in r["path"]:
            good.append(r)
    return good


BODIES = load_bodies()
say("gate bodies: %d" % len(BODIES))
for r in BODIES:
    say("  %-6s %-58s %d bytes" % (r["kind"], r["path"], len(r["body"])))
say("")

# ------------------------------------------------------------------ oracle ---
PRINTABLE = set(range(32, 127)) | {9, 10, 13}


def oracle(pt):
    """Return (tag, sample) only if the WHOLE plaintext is valid."""
    if not pt:
        return None
    if pt[:2] == b"\x1f\x8b":
        try:
            d = gzip.decompress(pt)
        except Exception:
            return None
        if d and (all(c in PRINTABLE for c in d[:2000])):
            return ("gzip", d[:120])
        return None
    if msgpack is not None:
        try:
            o = msgpack.unpackb(pt, raw=False, strict_map_key=False)
            return ("msgpack", repr(o)[:120])
        except Exception:
            pass
    if all(c in PRINTABLE for c in pt):
        s = pt.decode("ascii", "replace")
        return ("ascii", s[:120])
    return None


# ----------------------------------------------------------------- keys ------
KEYS = {
    "A56": KEY_A, "B32": KEY_B,
    "A32": KEY_A[:32], "A24": KEY_A[:24], "A16": KEY_A[:16],
    "B24": KEY_B[:24], "B16": KEY_B[:16],
}

# cipher factory: (label, fn(key, mode_args) -> decryptor) per mode
BLOCK8 = {"blowfish": (Blowfish, 8), "des": (DES, 8), "des3": (DES3, 8),
          "arc2": (ARC2, 8), "cast": (CAST, 8)}
BLOCK16 = {"aes": (AES, 16)}
STREAM = {"arc4": ARC4}

MODES8 = ("ECB", "CBC", "CFB", "OFB")
MODES16 = ("ECB", "CBC", "CFB", "OFB", "CTR")


def try_one(cipher_name, key, mode, body):
    """Try every prefix/IV layout for this (cipher, key, mode, body)."""
    hits = []
    layouts = []
    for pre in (0, 8, 16):
        rest = body[pre:]
        layouts.append((pre, rest))
    for pre, rest in layouts:
        # raw stream / no-IV
        try:
            if cipher_name in STREAM:
                c = STREAM[cipher_name].new(key, nonce=rest[:8] if pre else b"\x00" * 8)
                pt = c.decrypt(rest)
                h = oracle(pt)
                if h:
                    hits.append(("raw/stream pre=%d" % pre, pt, h))
                c = STREAM[cipher_name].new(key, nonce=b"\x00" * 8)
                pt = c.decrypt(rest)
                h = oracle(pt)
                if h:
                    hits.append(("raw/stream zero-nonce pre=%d" % pre, pt, h))
                continue
            blk = (BLOCK8 if cipher_name in BLOCK8 else BLOCK16)[cipher_name][0]
        except Exception:
            continue

        ivs = [None]
        if mode != "ECB":
            ivs += [b"\x00" * (8 if cipher_name in BLOCK8 else 16),
                    body[:16], body[:8], body[8:24], body[pre:pre + 16],
                    KEY_A[:16], KEY_B[:16]]
        for iv in ivs:
            if mode == "CTR":
                if iv is None:
                    iv = b"\x00" * 16
                elif len(iv) != 16:
                    continue
            if iv is not None and len(iv) not in (8, 16):
                continue
            try:
                if mode == "ECB":
                    c = blk.new(key, blk.MODE_ECB)
                elif mode == "CTR":
                    from Crypto.Util import Counter
                    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
                    c = blk.new(key, blk.MODE_CTR, counter=ctr)
                else:
                    c = blk.new(key, getattr(blk, "MODE_" + mode), iv=iv)
                pt = c.decrypt(rest)
            except Exception:
                continue
            h = oracle(pt)
            if h:
                hits.append(("pre=%d mode=%s iv=%s" % (pre, mode,
                               "none" if iv is None else iv[:16].hex()),
                             pt, h))
    return hits


# ------------------------------------------------------------------ run ------
TEST = BODIES[:4]

say("=" * 78)
say("SWEEP  (oracle = whole plaintext must parse)")
say("=" * 78)

results = []
n = 0
for cname in (list(BLOCK8) + list(BLOCK16) + list(STREAM)):
    modes = MODES8 if cname in BLOCK8 else (MODES16 if cname in BLOCK16
                                             else ("RAW",))
    for kname, key in KEYS.items():
        for mode in modes:
            for idx, r in enumerate(TEST):
                n += 1
                for desc, pt, h in try_one(cname, key, mode, r["body"]):
                    results.append((cname, kname, mode, idx, desc, h))
say("combinations tested: %d (4 bodies each)" % n)
say("raw hits: %d" % len(results))
say("")

# keep only (cipher,key,mode,layout) that hit EVERY tested body
from collections import defaultdict

by = defaultdict(set)
detail = {}
for cname, kname, mode, idx, desc, h in results:
    key = (cname, kname, mode, desc)
    by[key].add(idx)
    detail.setdefault(key, h)

ALL = set(range(len(TEST)))
say("=" * 78)
say("HITS CONFIRMED ON ALL %d TESTED BODIES" % len(TEST))
say("=" * 78)
full = [k for k, v in by.items() if v == ALL]
if not full:
    say("  none")
for k in full:
    say("  cipher=%-8s key=%-4s mode=%-4s layout=%s" % k)
    say("      -> %s  %r" % detail[k])
say("")
say("partial hits (some bodies only):")
for k, v in sorted(by.items(), key=lambda kv: -len(kv[1])):
    if k in full:
        continue
    say("  %d/%d  cipher=%-8s key=%-4s mode=%-4s layout=%s"
        % (len(v), len(TEST), k[0], k[1], k[2], k[3]))

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
