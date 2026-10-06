"""Open every non-gate reply and look for material handed to the client.

The gate bodies are the encrypted ones; 106 other replies are plain gzip and
have never been inspected.  If the client does not carry a fixed key in its
files -- which is what every sweep so far keeps coming back with -- then the
key (or a seed for it) may be delivered by the server at runtime, in exactly
one of these earlier plain responses.

So: decompress all of them, group by path, and report anything that looks like
key material -- long high-entropy runs, base64 blobs, or config mentioning
encryption -- rather than assuming the answer has to live in the binary.
"""
import gzip
import re
import zlib
from collections import defaultdict

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\plain_responses.txt"

raw = open(LOG, "rb").read().split(b"\n")
recs = []
path = rq = rs = None
for line in raw:
    if line.startswith(b"### REQ ") or line.startswith(b"### RESP "):
        m = re.search(rb"\s(/\S+)", line)
        path = m.group(1).decode() if m else None
        rq = rs = None
    elif line.startswith(b"REQHEX: "):
        try:
            rq = bytes.fromhex(line[8:].strip().decode())
        except ValueError:
            rq = None
    elif line.startswith(b"RESPHEX: "):
        try:
            rs = bytes.fromhex(line[9:].strip().decode())
        except ValueError:
            rs = None
        if path and rs:
            recs.append((path, rq, rs))
        path = rq = rs = None

out = []


def say(s=""):
    out.append(str(s))


def decompress(b):
    if b[:2] == b"\x1f\x8b":
        try:
            return zlib.decompress(b, 16 + zlib.MAX_WBITS), "gzip"
        except Exception as e:
            return None, "gzip FAILED %s" % str(e)[:40]
    try:
        return zlib.decompress(b), "zlib"
    except Exception:
        pass
    try:
        return zlib.decompress(b, -zlib.MAX_WBITS), "raw-deflate"
    except Exception:
        pass
    if b[:1] in (b"{", b"[", b"<") or all(0x20 <= c < 0x7F for c in b[:64]):
        return b, "plain"
    return None, "not compressed, not text"


say("=" * 78)
say("NON-GATE REPLIES (%d total records in flows.log)" % len(recs))
say("=" * 78)

plain = []
still_encrypted = []
by_path = defaultdict(list)
for path, rq, rs in recs:
    if "/gate/" in path:
        continue
    data, how = decompress(rs)
    by_path[path].append((how, data, rs))
    if data is None:
        still_encrypted.append((path, how, len(rs)))
    else:
        plain.append((path, how, data, len(rs)))

say("")
say("decoded: %d      undecodable: %d" % (len(plain), len(still_encrypted)))
say("")
say("--- paths, by decoded size (largest first) ---")
agg = defaultdict(lambda: [0, 0, None])
for path, how, data, n in plain:
    agg[path][0] += 1
    agg[path][1] += len(data)
    agg[path][2] = how
for path, (c, tot, how) in sorted(agg.items(), key=lambda t: -t[1][1])[:40]:
    say("  %5d replies  %8d bytes  %-12s  %s" % (c, tot, how, path))
if still_encrypted:
    say("")
    say("--- replies that did NOT decode (candidates for further encryption) ---")
    for path, how, n in still_encrypted[:30]:
        say("  %-12s %6d bytes  %s" % (how, n, path))

# ------------------------------------------- hunt for anything key-shaped ---
say("")
say("=" * 78)
say("SCAN OF DECOMPRESSED CONTENT FOR KEY-SHAPED MATERIAL")
say("=" * 78)

KEYISH = re.compile(
    rb"(?:key|secret|aes|encrypt|cipher|token|seed|salt|password|passwd|"
    rb"credential)", re.I)

B64ISH = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")

hits_key = 0
hits_b64 = 0
shown_key = 0
shown_b64 = 0
for path, how, data, n in plain:
    for m in KEYISH.finditer(data):
        hits_key += 1
        if shown_key < 40:
            lo = max(0, m.start() - 70)
            ctx = bytes(c if 0x20 <= c < 0x7F else 0x2E
                        for c in data[lo:m.end() + 90])
            say("  [kw] %-46s %r" % (path.rsplit("/", 1)[-1], ctx.decode("ascii")))
            shown_key += 1
    for m in B64ISH.finditer(data):
        hits_b64 += 1
        if shown_b64 < 40:
            s = m.group()
            # a 32-byte key shows up as 44 base64 chars; call that out
            tag = "32B?" if len(s) in (43, 44) else "len=%d" % len(s)
            say("  [b64] %-44s %s %s"
                % (path.rsplit("/", 1)[-1], tag, s[:60].decode("ascii")))
            shown_b64 += 1
say("")
say("keyword matches: %d   base64-ish runs: %d" % (hits_key, hits_b64))

# ------------------------------------------------- does any look like raw key
say("")
say("=" * 78)
say("HIGH-ENTROPY 16/24/32-BYTE RUNS INSIDE DECOMPRESSED REPLIES")
say("=" * 78)
import math
from collections import Counter


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


found = 0
for path, how, data, n in plain:
    # slide a 32-byte window; flag runs that look random AND not all-same-byte
    for i in range(0, max(0, len(data) - 31)):
        w = data[i:i + 32]
        if len(set(w)) < 24:
            continue
        if ent(w) < 4.6:          # 32 draws over 256 values, high bar
            continue
        # reject the common case of binary structure (lengths, offsets)
        if w[0] < 0x20 and w[1] < 0x20:
            continue
        found += 1
        if found <= 25:
            say("  %s @%d  %s  ent=%.2f"
                % (path.rsplit("/", 1)[-1], i, w.hex(), ent(w)))
        break
say("")
say("candidates flagged: %d" % found)

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
