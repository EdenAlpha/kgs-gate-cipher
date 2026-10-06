"""Open the 106 plain replies -- they live in flows.mitm, not flows.log.

First attempt assumed they were in flows.log; flows.log turns out to hold only
the 21 encrypted gate exchanges, which is why that run found nothing.  The
plain bodies are in the 68 MB mitm capture.

Rather than learn the container format, this walks the capture for gzip stream
signatures (1f 8b 08) and decompresses each in place.  Everything that opens is
then scanned for key-shaped material: long high-entropy runs, base64 blobs of
key length, and config wording about encryption.

Question being answered: if no fixed key exists anywhere in the game's files,
does the server hand one over beforehand?
"""
import math
import re
import zlib
from collections import Counter, defaultdict

MITM = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.mitm"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\mitm_plain.txt"

data = open(MITM, "rb").read()
print("flows.mitm: %d bytes" % len(data))

MAGIC = b"\x1f\x8b\x08"
found = []
i = data.find(MAGIC)
while i >= 0:
    for wbits in (16 + zlib.MAX_WBITS,):
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(data[i:i + 8_000_000])
            out += d.flush()
            if len(out) >= 40:
                found.append((i, out))
            break
        except Exception:
            continue
    i = data.find(MAGIC, i + 1)

print("gzip streams decompressed: %d   total payload %d bytes"
      % (len(found), sum(len(o) for _, o in found)))

out = []


def say(s=""):
    out.append(str(s))


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


say("=" * 78)
say("GZIP STREAMS IN flows.mitm  (%d)" % len(found))
say("=" * 78)
for off, o in sorted(found, key=lambda t: -len(t[1]))[:30]:
    head = bytes(c if 0x20 <= c < 0x7F else 0x2E for c in o[:70])
    say("  off 0x%08x  %7d -> %7d   %r" % (off, 0, len(o), head.decode("ascii")))

# --------------------------------------------------- key-shaped content -----
KEYISH = re.compile(
    rb"(?:[^A-Za-z]{0,12})(?:aes|encrypt|cipher|secret|seed|salt|password|"
    rb"passwd|pes-custom|aes256|aes-256)([^A-Za-z]{0,12})", re.I)
B64ISH = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")

say("")
say("=" * 78)
say("ENCRYPTION-RELATED WORDING INSIDE THE PLAIN REPLIES")
say("=" * 78)
k = 0
for off, o in found:
    for m in KEYISH.finditer(o):
        k += 1
        if k <= 50:
            lo = max(0, m.start() - 80)
            ctx = bytes(c if 0x20 <= c < 0x7F else 0x2E
                        for c in o[lo:m.end() + 110])
            say("  off 0x%x len %-6d %r" % (off, len(o), ctx.decode("ascii")))
say("")
say("keyword hits: %d" % k)

say("")
say("=" * 78)
say("BASE64 RUNS OF KEY-INTERESTING LENGTH")
say("=" * 78)
b = 0
for off, o in found:
    for m in B64ISH.finditer(o):
        s = m.group()
        b += 1
        if b <= 60:
            tag = "44 chars = 32 decoded bytes" if len(s) in (43, 44) \
                else "len %d = ~%d bytes" % (len(s), len(s) * 3 // 4)
            say("  off 0x%x  %-26s %s" % (off, tag, s[:64].decode("ascii")))
say("")
say("base64 runs: %d" % b)

# --------------------------------------------------- high-entropy blobs -----
say("")
say("=" * 78)
say("HIGH-ENTROPY 32-BYTE RUNS (a stored key would look like this)")
say("=" * 78)
n = 0
for off, o in found:
    if len(o) < 32:
        continue
    i = 0
    while i <= len(o) - 32:
        w = o[i:i + 32]
        if len(set(w)) >= 26 and ent(w) >= 4.7:
            n += 1
            if n <= 30:
                say("  stream@0x%x  payload+%d  %s  ent=%.2f"
                    % (off, i, w.hex(), ent(w)))
            i += 32
        else:
            i += 1
say("")
say("flagged: %d" % n)

# --------------------------------------------------- what are these files ----
say("")
say("=" * 78)
say("WHAT THE PLAIN REPLIES CONTAIN (first printable run of each)")
say("=" * 78)
for off, o in sorted(found, key=lambda t: -len(t[1]))[:25]:
    m = re.search(rb"[\x20-\x7e]{12,}", o)
    say("  len %-7d off 0x%x  %s"
        % (len(o), off, (m.group()[:90].decode("ascii") if m else "<binary>")))

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
