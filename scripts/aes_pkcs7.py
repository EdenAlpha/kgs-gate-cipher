"""AES-256 sweep over the gate bodies with a PKCS#7 oracle (not a parse oracle).

Why this exists
---------------
Two facts say the gate is not Blowfish-with-Key-A:

  1. bf_exact.py proved the game's block routine is *stock* Blowfish and still
     got 0/42, so the algorithm is not the problem -- the key/framing is.
  2. Every one of the 42 bodies is a multiple of 16.  With an 8-byte IV prefix
     and an 8-byte block that forces the plaintext block count to be odd in all
     42 cases (p=2^-42).  With a 16-byte prefix and a 16-byte block it is
     automatic.  The wire is 16-byte aligned.

That is exactly the mode-1 path: 0x7b38268 reads ctx->+0x30, mode 1 selects
context 0xa4a98d0 whose key is the 32-byte Key B, and mode 1 passes w2=#0x10
(16-byte block) to the pad/unpad helpers.  32 = AES-256 key size, and the
request header says `pes-custom-encrypt: AES256`.

The earlier try_decrypt.py rejected candidates unless the plaintext *parsed*
(gzip/msgpack/ASCII), which silently throws away protobuf -- the most likely
plaintext.  Here the oracle is PKCS#7 validity across all bodies, and raw
bytes are printed so nothing plausible can be hidden by an oracle.
"""
import re
import struct
import itertools

from Crypto.Cipher import AES

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\aes_pkcs7.txt"

KEY_A = bytes.fromhex(
    "a2df2319c1e5ec1e206a724b5709de77b728609eedbbfaaa939ab3d7bb4d7f77"
    "c135147cb76b4c2efa0249fad843a9d5cc38cae19cc41c90")
KEY_B = bytes.fromhex(
    "43740981523cdc171e71de2ccab1a5a9b86f4b833196c55facd4bd25846c33f5")

out = []


def say(s=""):
    out.append(str(s))


def unpad(b, bs):
    if not b:
        return None
    n = b[-1]
    if n < 1 or n > bs or n > len(b) or b[-n:] != bytes([n]) * n:
        return None
    return b[:-n]


# --------------------------------------------------------------- corpus -----
recs, cur = [], None
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

bodies = []
for r in recs:
    h = r.get("hex")
    if h and len(h) % 2 == 0 and "/gate/" in r["path"]:
        r["body"] = bytes.fromhex(h)
        bodies.append(r)

say("gate bodies: %d   sizes: %s" % (len(bodies),
                                     sorted({len(b["body"]) for b in bodies})))

KEYS = {
    "B32": KEY_B,
    "B24": KEY_B[:24],
    "B16": KEY_B[:16],
    "A32": KEY_A[:32],
    "A24": KEY_A[:24],
    "A16": KEY_A[:16],
    "A56->B32": KEY_A[:32],   # placeholder, listed separately below
}
del KEYS["A56->B32"]

PREFIXES = [0, 8, 16]


def ivs_for(body, pre):
    """Every IV reading that survives arithmetic for this prefix."""
    c = [b"\x00" * 16]
    if pre >= 16:
        c.append(body[:16])          # IV carried in its own prefix
        c.append(body[8:24])         # 8-byte junk then IV
    if pre == 8:
        c.append(body[:8] + body[8:16])   # = body[:16] read as IV, ct from 8
        c.append(body[:8] + b"\x00" * 8)
        c.append(body[8:16] + body[:8])
    if pre == 0:
        c.append(body[:16])
        c.append(body[8:24])
    if len(body) >= 24:
        c.append(body[-16:])
    seen, uniq = set(), []
    for x in c:
        if len(x) == 16 and x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


say("=" * 78)
say("PKCS#7 (block 16) over all %d bodies -- AES-256" % len(bodies))
say("=" * 78)

results = []
for kname, key in KEYS.items():
    for pre in PREFIXES:
        for iv in ivs_for(bodies[0]["body"], pre):
            ok, tried, sample = 0, 0, []
            for r in bodies:
                b = r["body"]
                if len(b) <= pre:
                    continue
                ct = b[pre:]
                if len(ct) % 16:
                    continue
                tried += 1
                try:
                    pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)
                except Exception:
                    continue
                u = unpad(pt, 16)
                if u is not None:
                    ok += 1
                    if len(sample) < 2:
                        sample.append((r["kind"], r["path"], pt))
            results.append((ok, tried, kname, pre, iv, sample))

results.sort(key=lambda t: -t[0])
for ok, tried, kname, pre, iv, sample in results[:24]:
    say("  %3d/%-3d  key=%-4s pre=%d iv=%s"
        % (ok, tried, kname, pre, iv[:16].hex()))

best = results[0]
say("")
if best[0] >= 3:
    say("HIT -- %d/%d with key=%s pre=%d iv=%s"
        % (best[0], best[1], best[2], best[3], best[4][:16].hex()))
    key = KEYS[best[2]]
    pre, iv = best[3], best[4]
    say("")
    say("raw bytes (no oracle applied):")
    for r in bodies:
        b = r["body"]
        ct = b[pre:]
        if len(ct) % 16:
            continue
        pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)
        u = unpad(pt, 16)
        good = u is not None
        data = u if good else pt
        say("-" * 78)
        say("%s %s  %d bytes  pkcs7=%s" % (r["kind"], r["path"], len(b), good))
        say("  hex   %s" % data[:200].hex())
        say("  ascii %s" % "".join(chr(x) if 32 <= x < 127 else "."
                                   for x in data[:200]))
else:
    say("NO candidate reached 3/%d.  Highest was %d/%d (%s pre=%d)."
        % (len(bodies), best[0], best[1], best[2], best[3]))

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
