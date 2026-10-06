"""Confirm the recovered framing by PKCS#7 validity across every gate body.

The disassembly now reads unambiguously:

  encrypt_mode0 0x7b2cbb0
      state = init_cipher_state(key = ctx+0x08)          # 56-byte Key A
      iv    = 8 random bytes at state+0x4c               # 0x7b2d1f8
      pad   = PKCS#7 to a multiple of 8                  # 0x7b2c7ec
      for each 8-byte block:                             # 0x7b2ce94
          swab -> vtable[0] 0x7b2e17c -> swab
      body  = state+0x4c || ciphertext

  vtable[0] 0x7b2e17c  = Blowfish-CBC encrypt
      block ^= obj+0x1050 ; 0x7b2d404 (Blowfish core) ; obj+0x1050 = ciphertext
  vtable[1] 0x7b2e244  = Blowfish-CBC decrypt
      save ct ; 0x7b2d794 (Blowfish core) ; block ^= iv ; iv = saved ct

  key schedule 0x7b2db24 = textbook Blowfish: pi P-array from 0xc8d92c,
      memcpy 4096 B of S-boxes from 0xc8d974, key words cycled big-endian,
      521 expansion rounds filling P[18] and four 256-word S-boxes.

The two swabs cancel (byte-swap is a position permutation and XOR is
byte-wise), so on the wire this is plain Blowfish-CBC with IV = body[0:8].

Why this test rather than another parse
---------------------------------------
The earlier sweep demanded that one (cipher, key, mode, prefix) tuple parse on
all four sampled bodies, which a correct key would fail if even one of those
payloads is protobuf rather than text.  PKCS#7 padding is an independent,
per-body check: a right key clears it on all 42 bodies, a wrong key clears it
by chance on about 0.4% of them.  So padding validity is reported for every
candidate over the whole corpus, and the plaintext is then printed for whatever
survives.
"""
import struct

from Crypto.Cipher import Blowfish

LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\bf_cbc_final.txt"

KEY_A = bytes.fromhex(
    "a2df2319c1e5ec1e206a724b5709de77b728609eedbbfaaa939ab3d7bb4d7f77"
    "c135147cb76b4c2efa0249fad843a9d5cc38cae19cc41c90")
KEY_B = bytes.fromhex(
    "43740981523cdc171e71de2ccab1a5a9b86f4b833196c55facd4bd25846c33f5")

out = []


def say(s=""):
    out.append(str(s))


def unpad_ok(b):
    """True if b ends in valid PKCS#7 for an 8-byte block."""
    if not b:
        return False
    n = b[-1]
    if n < 1 or n > 8 or n > len(b):
        return False
    return b[-n:] == bytes([n]) * n


# ---------------------------------------------------------------- corpus ----
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
    if h and len(h) % 2 == 0 and "/gate/" in r["path"]:
        r["body"] = bytes.fromhex(h)
        bodies.append(r)

say("gate bodies: %d   (sizes: %s)"
    % (len(bodies), sorted({len(r["body"]) for r in bodies})))
say("")

# ------------------------------------------------- padding validity sweep ---
CANDS = []
for kname, key in (("A56", KEY_A), ("A32", KEY_A[:32]), ("A24", KEY_A[:24]),
                   ("A16", KEY_A[:16]), ("B32", KEY_B), ("B16", KEY_B[:16])):
    for pre in (8, 16, 0):
        for mode in ("CBC", "ECB"):
            CANDS.append((kname, key, pre, mode))

say("=" * 78)
say("PKCS#7 VALIDITY ACROSS ALL %d BODIES (right key clears all of them)" %
    len(bodies))
say("=" * 78)
say("  %-5s %-4s %-4s %-6s  %-10s" % ("key", "pre", "mode", "iv", "valid"))
results = []
for kname, key, pre, mode in CANDS:
    for ivname, ivf in (("body[:8]", lambda b, p: b[:8]),
                        ("body[8:16]", lambda b, p: b[8:16]),
                        ("zero", lambda b, p: b"\x00" * 8)):
        if mode == "ECB" and ivname != "zero":
            continue
        ok, tried = 0, 0
        for r in bodies:
            b = r["body"]
            rest = b[pre:]
            if len(rest) == 0 or len(rest) % 8:
                continue
            tried += 1
            iv = ivf(b, pre) if mode != "ECB" else None
            if iv is not None and len(iv) != 8:
                continue
            try:
                c = Blowfish.new(key, getattr(Blowfish, "MODE_" + mode), iv=iv)
                pt = c.decrypt(rest)
            except Exception:
                continue
            if unpad_ok(pt):
                ok += 1
        results.append((ok, tried, kname, pre, mode, ivname, key))
        flag = ""
        if tried and ok >= max(3, int(tried * 0.6)):
            flag = "   <<<<"
        say("  %-5s %-4d %-4s %-6s  %3d/%-3d%s"
            % (kname, pre, mode, ivname, ok, tried, flag))

results.sort(key=lambda t: -t[0])
say("")
say("best: %d/%d valid with key=%s pre=%d mode=%s iv=%s"
    % (results[0][0], results[0][1], results[0][2], results[0][3],
       results[0][4], results[0][5]))
say("")

# ------------------------------------------------------- print survivors ----
if results[0][0] >= 3:
    ok, tried, kname, pre, mode, ivname, key = results[0]
    say("=" * 78)
    say("PLAINTEXT  key=%s pre=%d mode=%s iv=%s" % (kname, pre, mode, ivname))
    say("=" * 78)
    for r in bodies:
        b = r["body"]
        rest = b[pre:]
        if not rest or len(rest) % 8:
            continue
        iv = b[:8] if mode != "ECB" else None
        try:
            c = Blowfish.new(key, getattr(Blowfish, "MODE_" + mode), iv=iv)
            pt = c.decrypt(rest)
        except Exception:
            continue
        good = unpad_ok(pt)
        if good:
            pt = pt[:len(pt) - pt[-1]]
        say("-" * 78)
        say("%s %s  %d bytes  pkcs7=%s" % (r["kind"], r["path"], len(b), good))
        say("  %s" % pt[:300])
        say("  ascii: %s" % "".join(chr(x) if 0x20 <= x < 0x7F else "."
                                    for x in pt[:300]))
    say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
