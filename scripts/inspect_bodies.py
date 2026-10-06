"""Is the gate body actually ciphertext, or is it just msgpack?

Every conclusion so far rests on one untested assumption: that a gate reply is
AES output.  The evidence was only that the bytes are not printable and that
every body length is a multiple of 16.

But those two facts are also explained if the body is plain msgpack padded to a
16-byte boundary -- and if it is plain msgpack, then there is no key to find at
all, which would explain why four independent key searches came back empty:

    * 1,383,714 text keys          NO
    * 160,822,937 windows, printable oracle   NO
    * 160,822,937 windows, PKCS#7 oracle      NO
    * seed / sign / IV derived keys NO

Test, no interpretation up front: print for every gate body the first bytes,
its length mod 16, the msgpack type its leading byte decodes to, and the byte
entropy.  A msgpack map header (0x80..0x8f / 0xde / 0xdf) at offset 0 would be
conclusive; uniformly high entropy with no structure would mean ciphertext.
"""
import math
import re
from collections import Counter

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\inspect_bodies.txt"

# msgpack format byte -> meaning, restricted to what a real object would start
# with.  Ciphertext must never produce one of these in a plausible spot.
def msgpack_type(b):
    if b <= 0x7F:
        return "positive fixint %d" % b
    if b >= 0xE0:
        return "negative fixint %d" % (b - 256)
    if 0x80 <= b <= 0x8F:
        return "fixmap with %d pairs" % (b & 0x0F)
    if 0x90 <= b <= 0x9F:
        return "fixarray of %d" % (b & 0x0F)
    if 0xA0 <= b <= 0xBF:
        return "fixstr len %d" % (b & 0x1F)
    return {
        0xC0: "nil", 0xC2: "false", 0xC3: "true",
        0xC4: "bin8", 0xC5: "bin16", 0xC6: "bin32",
        0xC7: "ext8", 0xC8: "ext16", 0xC9: "ext32",
        0xCA: "float32", 0xCB: "float64",
        0xCC: "uint8", 0xCD: "uint16", 0xCE: "uint32", 0xCF: "uint64",
        0xD0: "int8", 0xD1: "int16", 0xD2: "int32", 0xD3: "int64",
        0xD9: "str8", 0xDA: "str16", 0xDB: "str32",
        0xDC: "array16", 0xDD: "array32",
        0xDE: "map16", 0xDF: "map32",
        0xD4: "fixext1", 0xD5: "fixext2", 0xD6: "fixext4",
        0xD7: "fixext8", 0xD8: "fixext16",
    }.get(b, "UNKNOWN 0x%02x" % b)


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def try_msgpack(blob):
    """Does the WHOLE body decode as one msgpack value?  That is the real test."""
    try:
        import msgpack as mp
    except ImportError:
        return "msgpack module unavailable"
    try:
        obj, idx = mp.unpackb(blob, raw=False, strict_map_key=False,
                              return_index=True) if False else (None, None)
    except Exception:
        pass
    try:
        import msgpack
        unpk = msgpack.Unpacker(None)
        unpk.feed(blob)
        obj = next(unpk)
        used = unpk.tell() if hasattr(unpk, "tell") else None
        return "decodes as %s (consumed %s of %d bytes)" % (
            type(obj).__name__, used, len(blob))
    except StopIteration:
        return "empty"
    except Exception as e:
        return "FAILS: %s" % str(e)[:70]


raw = open(LOG, "rb").read().split(b"\n")
exch, path, preq, presp = [], None, None, None
for line in raw:
    if line.startswith(b"### REQ "):
        m = re.search(rb"\s(/\S+)", line)
        path = m.group(1).decode() if m else None
        preq = presp = None
    elif line.startswith(b"REQHEX: "):
        try:
            preq = bytes.fromhex(line[8:].strip().decode())
        except ValueError:
            preq = None
    elif line.startswith(b"REQLEN: "):
        pass
    elif line.startswith(b"RESPHEX: "):
        try:
            presp = bytes.fromhex(line[9:].strip().decode())
        except ValueError:
            presp = None
        if path:
            exch.append((path, preq, presp))
        path, preq, presp = None, None, None

out = []


def say(s=""):
    out.append(str(s))


def report(tag, body):
    if not body:
        say("    %-4s <none>" % tag)
        return
    lead = body[:48]
    say("    %-4s len=%-6d len%%16=%-3d  b0=0x%02x  %s"
        % (tag, len(body), len(body) % 16, body[0], msgpack_type(body[0])))
    say("         head : %s" % lead[:24].hex())
    say("         tail : %s" % body[-16:].hex())
    say("         entropy(first 512)=%.2f bits/byte   whole=%.2f"
        % (entropy(body[:512]), entropy(body)))
    say("         full msgpack decode: %s" % try_msgpack(body))
    # structure probe: if a fixmap/map16 header, list a few key names found
    for m in re.finditer(rb"[\x20-\x7e]{5,}", body[:400]):
        say("         ascii run @%d: %r" % (m.start(), m.group()[:50]))
        break


say("=" * 78)
say("GATE EXCHANGE BODY INSPECTION  (%d exchanges)" % len(exch))
say("=" * 78)
gate = [e for e in exch if "/gate/" in e[0]]
for path, rq, rs in gate[:8]:
    say("")
    say("  %s" % path)
    report("REQ", rq)
    report("RESP", rs)

say("")
say("=" * 78)
say("SUMMARY")
say("=" * 78)
import statistics
rl = [len(e[1]) for e in gate if e[1]]
sl = [len(e[2]) for e in gate if e[2]]
say("  gate requests : %d   lengths %s" % (len(rl), rl))
say("  gate responses: %d   lengths %s" % (len(sl), sl))
say("  all requests  %%16==0 : %s" % all(x % 16 == 0 for x in rl))
say("  all responses %%16==0 : %s" % all(x % 16 == 0 for x in sl))
say("  response b0 distribution: %s"
    % dict(Counter(e[2][0] for e in gate if e[2])))
say("  request  b0 distribution: %s"
    % dict(Counter(e[1][0] for e in gate if e[1])))

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
