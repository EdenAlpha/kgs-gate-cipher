"""Confirm the gate wire format by *fully parsing* every plaintext.

Result of aes_pkcs7.py: key = Key B (32 B), AES-256-CBC, PKCS#7 block 16,
42/42 bodies.  This script applies the framing that the code predicts for
mode 1 (16-byte IV prefix, matching how mode 0 prepends its 8-byte IV at
state+0x4c) and then decompresses:

    body = IV(16) || ciphertext
    pt   = AES-256-CBC-decrypt(ct, key=Key B, iv) , PKCS#7-unpadded to 16
    req  -> zlib   (starts 78 da)
    resp -> gzip   (starts 1f 8b 08)

A candidate only counts if gzip/zlib consumes the *whole* plaintext with no
bytes left over, for all 42 -- padding alone is not enough.
"""
import gzip
import re
import zlib

from Crypto.Cipher import AES

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\aes_gate.txt"

KEY_B = bytes.fromhex(
    "43740981523cdc171e71de2ccab1a5a9b86f4b833196c55facd4bd25846c33f5")

out = []


def say(s=""):
    out.append(str(s))


def unpad(b, bs=16):
    if not b:
        return None
    n = b[-1]
    if n < 1 or n > bs or n > len(b) or b[-n:] != bytes([n]) * n:
        return None
    return b[:-n]


def inflate(data):
    """Return (kind, bytes) consuming the input exactly, else (None, None)."""
    for kind, fn in (("gzip", gzip.decompress), ("zlib", zlib.decompress)):
        try:
            d = fn(data)
        except Exception:
            continue
        return kind, d
    # raw deflate fallback
    for wbits in (-15, 15):
        try:
            d = zlib.decompressobj(wbits).decompress(data)
            return ("raw-deflate%d" % wbits), d
        except Exception:
            continue
    return None, None


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

bodies = [r for r in recs
          if r.get("hex") and len(r["hex"]) % 2 == 0 and "/gate/" in r["path"]]
for r in bodies:
    r["body"] = bytes.fromhex(r["hex"])

say("framing: body[0:16]=IV  body[16:]=ct   key=Key B  AES-256-CBC  pad=16")
say("bodies: %d" % len(bodies))
say("=" * 78)

full_ok = 0
for r in bodies:
    b = r["body"]
    ct = b[16:]
    pt = AES.new(KEY_B, AES.MODE_CBC, iv=b[:16]).decrypt(ct)
    u = unpad(pt)
    if u is None:
        say("%s %s  PKCS#7 FAIL" % (r["kind"], r["path"]))
        continue
    kind, d = inflate(u)
    ok = d is not None
    # must consume exactly: decompressobj leftover check
    exact = False
    if ok:
        try:
            obj = zlib.decompressobj(15 + 16 if kind == "gzip" else 15)
            got = obj.decompress(u) + obj.flush()
            exact = (got == d and not obj.unused_data)
        except Exception:
            exact = False
        full_ok += 1
    say("%s %-58s pad=ok inflate=%-6s exact=%-5s plain=%-6s out=%s"
        % (r["kind"], r["path"], kind, exact, len(u),
           len(d) if d is not None else "-"))

say("")
say("bodies whose plaintext fully decompresses: %d/%d" % (full_ok, len(bodies)))

# ------------------------------------------------- dump one pair verbatim ----
say("")
say("=" * 78)
say("ONE PAIR, VERBATIM")
say("=" * 78)
for r in bodies:
    if r["path"].endswith("gate_CMD_GET_SERVER_ENV.php"):
        b = r["body"]
        pt = unpad(AES.new(KEY_B, AES.MODE_CBC, iv=b[:16]).decrypt(b[16:]))
        kind, d = inflate(pt)
        say("")
        say("--- %s %s ---" % (r["kind"], r["path"]))
        say("wire     %d bytes   IV=%s" % (len(b), b[:16].hex()))
        say("plain    %d bytes   %s" % (len(pt), kind))
        say("plainhex %s" % pt[:160].hex())
        say("plainasc %s" % "".join(chr(x) if 32 <= x < 127 else "."
                                    for x in pt[:160]))
        if d is not None:
            say("inflated %d bytes" % len(d))
            say("infhex   %s" % d[:300].hex())
            say("infasc   %s" % "".join(chr(x) if 32 <= x < 127 else "."
                                        for x in d[:300]))

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
