"""Stop trusting the oracle; look at the bytes.

Two questions the previous sweep could not answer:

1. Is the 8-byte prefix an IV?  Captures of the same endpoint appear twice in
   flows.log.  If the plaintext is identical and only the IV changes, then
     ECB  -> every block identical
     CBC  -> block 1 changes and the change cascades, so every block differs
   That settles the mode without needing a plaintext.

2. What does Blowfish actually come out as?  The oracle demanded the whole
   plaintext be gzip/msgpack/ASCII.  If the payload is protobuf, or has a
   binary header, every right answer would have been thrown away.  So this
   prints raw bytes for the plausible (cipher, key, mode, prefix) tuples and
   lets the data speak.
"""
import gzip
import itertools
import struct

from Crypto.Cipher import Blowfish

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\bf_look.txt"

KEY_A = bytes.fromhex(
    "a2df2319c1e5ec1e206a724b5709de77b728609eedbbfaaa939ab3d7bb4d7f77"
    "c135147cb76b4c2efa0249fad843a9d5cc38cae19cc41c90")
KEY_B = bytes.fromhex(
    "43740981523cdc171e71de2ccab1a5a9b86f4b833196c55facd4bd25846c33f5")

try:
    import msgpack
    HAVE_MSGPACK = True
except Exception:
    msgpack = None
    HAVE_MSGPACK = False

out = []


def say(s=""):
    out.append(str(s))


def vis(b, n=64):
    b = b[:n]
    return "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in b)


# ------------------------------------------------------------- corpus -------
import re

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
    if h and len(h) % 2 == 0 and "gate" in r["path"]:
        r["body"] = bytes.fromhex(h)
        bodies.append(r)

say("gate bodies: %d   msgpack available: %s" % (len(bodies), HAVE_MSGPACK))
say("")

# ------------------------------------------- 1. duplicate-capture diff ------
say("=" * 78)
say("1. DUPLICATE CAPTURES  (does a repeated endpoint repeat its ciphertext?)")
say("=" * 78)
groups = {}
for i, r in enumerate(bodies):
    groups.setdefault((r["path"], r["kind"], len(r["body"])), []).append(i)

for key, idxs in groups.items():
    if len(idxs) < 2:
        continue
    path, kind, ln = key
    say("  %s %s  %d bytes   captures=%d"
        % (kind, path.split("/")[-1], ln, len(idxs)))
    for a, b in itertools.combinations(idxs, 2):
        ba, bb = bodies[a]["body"], bodies[b]["body"]
        same = sum(1 for x, y in zip(ba, bb) if x == y)
        first = next((k for k in range(min(len(ba), len(bb)))
                      if ba[k] != bb[k]), None)
        # compare from byte 8 (after the prefix) in 8-byte blocks
        blocks = min(len(ba), len(bb)) // 8
        diffblocks = [k for k in range(blocks)
                      if ba[k * 8:k * 8 + 8] != bb[k * 8:k * 8 + 8]]
        say("     pair %d/%d: first diff at %s, bytes equal %d/%d"
            % (a, b, first, same, len(ba)))
        say("        differing 8-byte blocks: %s"
            % (diffblocks if len(diffblocks) <= 24
               else "%d of %d (all)" % (len(diffblocks), blocks)))
        say("        prefix8 equal: %s   blocks 1..: all equal? %s"
            % (ba[:8] == bb[:8],
               all(k in diffblocks for k in range(1, blocks)) is False
               and len(diffblocks) <= 1))
    say("")

# ------------------------------------- 2. raw Blowfish output inspection ----
say("=" * 78)
say("2. BLOWFISH OUTPUT, RAW  (first 64 bytes shown regardless of validity)")
say("=" * 78)

CANDS = []
for kname, key in (("A56", KEY_A), ("A32", KEY_A[:32]), ("A24", KEY_A[:24]),
                   ("A16", KEY_A[:16]), ("B32", KEY_B), ("B16", KEY_B[:16])):
    for pre in (0, 8, 16):
        for mode in ("ECB", "CBC", "OFB", "CFB"):
            CANDS.append((kname, key, pre, mode))

# pick a few representative bodies: one request and one response
sample = []
seen = set()
for r in bodies:
    tag = (r["path"], r["kind"], len(r["body"]))
    if tag in seen:
        continue
    seen.add(tag)
    sample.append(r)
    if len(sample) >= 4:
        break

for r in sample:
    body = r["body"]
    say("-" * 78)
    say("%s %s  %d bytes" % (r["kind"], r["path"], len(body)))
    say("  raw head: %s  %s" % (body[:32].hex(), vis(body, 32)))
    for kname, key, pre, mode in CANDS:
        rest = body[pre:]
        if len(rest) % 8:
            continue
        ivs = [b"\x00" * 8] if mode != "ECB" else [None]
        if mode != "ECB":
            ivs += [body[:8], rest[:8] if len(rest) >= 8 else None]
        for iv in ivs:
            if iv is None and mode != "ECB":
                continue
            if mode == "ECB":
                iv = None
            if iv is not None and len(iv) != 8:
                continue
            try:
                c = Blowfish.new(key, getattr(Blowfish, "MODE_" + mode),
                                  iv=iv)
                pt = c.decrypt(rest)
            except Exception:
                continue
            score = sum(1 for ch in pt if 0x20 <= ch < 0x7F)
            ratio = score / max(1, len(pt))
            tag = "ASCII" if ratio > 0.9 else ""
            if pt[:2] == b"\x1f\x8b":
                tag = "GZIP"
                try:
                    pt = gzip.decompress(pt)
                except Exception:
                    tag = "GZIP(bad)"
            if HAVE_MSGPACK:
                try:
                    o = msgpack.unpackb(pt, raw=False, strict_map_key=False)
                    tag = "MSGPACK %r" % (o,)
                except Exception:
                    pass
            if tag or ratio > 0.5:
                say("    k=%-3s pre=%d %-3s iv=%-16s ascii=%3d%% %-10s %s"
                    % (kname, pre, mode,
                       "none" if iv is None else iv.hex(),
                       int(ratio * 100), tag, vis(pt, 48)))
    say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
