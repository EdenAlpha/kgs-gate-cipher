"""Transliterate the recovered Blowfish from ARM64 to Python, then decrypt the gate.

Why transliteration and not pycryptodome
----------------------------------------
Every earlier attempt fed the gate bodies to a *stock* Blowfish and got 0/42.
The core 0x7b2d404 is now read instruction by instruction and it is not quite
any published variant:

  * its round loop hoists the P XOR of round i+1 into round i (harmless -- XOR
    commutes, F sees the same values), and
  * the output registers come back swapped: `*x1 = b_final`, `*x2 = a_final`,
    so the block halves leave in the opposite order to how they entered.

Because a library cannot be trusted to make the same two choices, the routines
below are written straight from `walk_core.txt` and `cipher_vtable.txt`.  The
one place a stock library *is* used is as a cross-check, printed at the top:
if the transliteration agrees with pycryptodome then the two are the same
cipher and the difference lies elsewhere.

Addresses in the comments are the disassembly VAs so each claim can be checked
against the dump it came from.

Wire format recovered from code
-------------------------------
    encrypt_mode0 0x7b2cbb0   state = init(ctx+0x08)   # 56-byte Key A
                              pad PKCS#7 to 8         # 0x7b2c7ec
                              iv = 8 random bytes     # 0x7b2d164 / 0x7b2d1f8
                              body = iv || ciphertext
    transform 0x7b2ce94       per block: swab -> cipher[6] -> swab
    vtable[0] 0x7b2e17c       block ^= iv ; core ; iv = block       (CBC enc)
    vtable[1] 0x7b2e244       save ct ; core ; block ^= iv ; iv = ct (CBC dec)
    swab                      reverse bytes within each 4-byte half,
                              i.e. the LE<->BE conversion Blowfish needs

So with C[-1] = iv:
    C_i = swab( core_enc( swab( P_i XOR C_{i-1} ) ) )
    P_i = swab( core_dec( swab( C_i ) ) ) XOR C_{i-1}
"""
import re
import struct

from Crypto.Cipher import Blowfish

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
LOG = r"C:\Users\Administrator\AppData\Local\Temp\2\rec2\flows.log"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\bf_exact.txt"

M = 0xFFFFFFFF

# Key A / Key B: recovered by derive_keys.py from the .rodata blobs, i.e.
# out[i] = blob[i] ^ T1[i%9] ^ T2[i%12] ^ 0x75, applied at startup by 0x7d64fb0.
KEY_A = bytes.fromhex(
    "a2df2319c1e5ec1e206a724b5709de77b728609eedbbfaaa939ab3d7bb4d7f77"
    "c135147cb76b4c2efa0249fad843a9d5cc38cae19cc41c90")
KEY_B = bytes.fromhex(
    "43740981523cdc171e71de2ccab1a5a9b86f4b833196c55facd4bd25846c33f5")

# Blowfish tables, read as little-endian because the core does `ldr w`:
#   P[18] 72 bytes @ 0xc8d92c   (0x7b2db3c -> 0xc8d92c)
#   S[4*256] 4096 bytes @ 0xc8d974  (0x7b2db5c -> 0xc8d974)
P_OFF, P_LEN = 0xC8D92C, 72
S_OFF, S_LEN = 0xC8D974, 4096

out = []


def say(s=""):
    out.append(str(s))


def swab(b):
    """0x7b2d354 / 0x7b2d398: reverse bytes in each 4-byte half."""
    return b[3::-1] + b[7:3:-1]


def xor8(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def F(S, x):
    """((S0[b3] + S1[b2]) ^ S2[b1]) + S3[b0] -- 0x7b2d41c..0x7b2d454."""
    b3 = (x >> 24) & 0xFF
    b2 = (x >> 16) & 0xFF
    b1 = (x >> 8) & 0xFF
    b0 = x & 0xFF
    t = (S[b3] + S[256 + b2]) & M      # add  w14, w14, w17
    t ^= S[512 + b1]                   # eor  w14, w14, w15
    return (t + S[768 + b0]) & M       # add  w14, w14, w16


def core_enc(P, S, x1, x2):
    """0x7b2d404.  Returns (*x1_out, *x2_out)."""
    a = (P[0] ^ x1) & M
    b = (P[1] ^ x2) & M
    b ^= F(S, a)                                    # F#1
    for k in range(1, 8):                           # F#2 .. F#15
        f = F(S, b)
        a ^= P[2 * k]
        b ^= P[2 * k + 1]
        a ^= f
        b ^= F(S, a)
    f = F(S, b)                                     # F#16
    a ^= P[16]
    b ^= P[17]
    a ^= f
    return b & M, a & M


def core_dec(P, S, x1, x2):
    """0x7b2d794 -- P walked backwards, halves mirrored."""
    a = (P[17] ^ x1) & M
    b = (P[16] ^ x2) & M
    b ^= F(S, a)
    for j in range(1, 8):                           # pairs (15,14)..(3,2)
        f = F(S, b)
        a ^= P[17 - 2 * j]
        b ^= P[16 - 2 * j]
        a ^= f
        b ^= F(S, a)
    f = F(S, b)
    a ^= P[1]
    b ^= P[0]
    a ^= f
    return b & M, a & M


def key_schedule(key):
    """0x7b2db24 -- verbatim from the disassembly.

    1. P and S are copied from .rodata (72 B and a 4096 B memcpy).
    2. P[i] ^= big-endian word built from key[4i..4i+3], cycling over keylen;
       the wrap is `msub w9, w14, w20, w9` at 0x7b2dbe8.
    3. seed (0,0) -- `str xzr, [sp]` at 0x7b2dc0c -- then 9 chained core_enc
       calls store P[0..17] in pairs, reading back the previous output each
       time, then four 128-iteration loops fill S0..S3.
    """
    P = list(struct.unpack("<18I", DATA[P_OFF:P_OFF + P_LEN]))
    S = list(struct.unpack("<1024I", DATA[S_OFF:S_OFF + S_LEN]))

    n = len(key)
    idx = 0
    for i in range(18):
        w = 0
        for _ in range(4):
            w = ((w << 8) | key[idx % n]) & M
            idx += 1
        P[i] ^= w

    x1 = x2 = 0
    for k in range(9):
        x1, x2 = core_enc(P, S, x1, x2)
        P[2 * k] = x1
        P[2 * k + 1] = x2

    for s in range(4):
        base = 256 * s
        for i in range(0, 256, 2):
            x1, x2 = core_enc(P, S, x1, x2)
            S[base + i] = x1
            S[base + i + 1] = x2
    return P, S


def block_dec(P, S, c, prev):
    """P_i = swab(core_dec(swab(C_i))) XOR C_{i-1}   (or XOR iv for i = 0)."""
    lo, hi = struct.unpack("<II", swab(c))
    b, a = core_dec(P, S, lo, hi)
    return xor8(swab(struct.pack("<II", b, a)), prev)


def block_enc(P, S, p, prev):
    lo, hi = struct.unpack("<II", swab(xor8(p, prev)))
    b, a = core_enc(P, S, lo, hi)
    return swab(struct.pack("<II", b, a))


def unpad(b):
    if not b:
        return None
    n = b[-1]
    if n < 1 or n > 8 or n > len(b) or b[-n:] != bytes([n]) * n:
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

# ------------------------------------------------------- sanity of tables ----
DATA = open(SO, "rb").read()
say("P[0] = 0x%08x   S[0] = 0x%08x   S[255] = 0x%08x   S[511] = 0x%08x"
    % (struct.unpack("<I", DATA[P_OFF:P_OFF + 4])[0],
       struct.unpack("<I", DATA[S_OFF:S_OFF + 4])[0],
       struct.unpack("<I", DATA[S_OFF + 4 * 255:S_OFF + 4 * 255 + 4])[0],
       struct.unpack("<I", DATA[S_OFF + 4 * 511:S_OFF + 4 * 511 + 4])[0]))
say("    (standard Blowfish wants P[0]=0x243f6a88, S0[0]=0xd1310ba6, "
    "S1[255]=0xfa43a425)")
say("")

# --------------------------------------------- is it stock Blowfish? -------
say("=" * 78)
say("CROSS-CHECK: does the transliteration match a library implementation?")
say("=" * 78)
PA, SA = key_schedule(KEY_A)
probe = bytes(range(8))
mine = block_enc(PA, SA, probe, b"\x00" * 8)
stock = Blowfish.new(KEY_A, Blowfish.MODE_ECB).encrypt(probe)
say("plaintext        %s" % probe.hex())
say("transliteration  %s" % mine.hex())
say("pycryptodome     %s" % stock.hex())
say("identical        %s" % (mine == stock))
say("")

# --------------------------------------------------------- decrypt sweep ----
say("=" * 78)
say("PKCS#7 validity over all %d bodies" % len(bodies))
say("=" * 78)

P32, S32 = key_schedule(KEY_A[:32])
PB, SB = key_schedule(KEY_B)
CANDS = [
    ("A56", (PA, SA), 8),
    ("A32", (P32, S32), 8),
    ("B32", (PB, SB), 8),
]

for cname, (P, S), pre in CANDS:
    for ivname, ivf in (("body[:8]", lambda b: b[:8]),
                        ("body[-8:]", lambda b: b[-8:]),
                        ("zero", lambda b: b"\x00" * 8)):
        ok, tried, shown = 0, 0, []
        for r in bodies:
            b = r["body"]
            if pre and len(b) < pre + 8:
                continue
            ct = b[pre:]
            if not ct or len(ct) % 8:
                continue
            tried += 1
            iv = ivf(b)
            prev = iv
            pt = b""
            try:
                for i in range(0, len(ct), 8):
                    blk = block_dec(P, S, ct[i:i + 8], prev)
                    pt += blk
                    prev = ct[i:i + 8]
            except Exception:
                continue
            u = unpad(pt)
            if u is not None:
                ok += 1
                if len(shown) < 3:
                    shown.append((r["path"], r["kind"], u))
        flag = "   <<<<" if tried and ok >= max(3, int(tried * 0.6)) else ""
        say("  key=%-4s pre=%d iv=%-10s  %3d/%-3d%s"
            % (cname, pre, ivname, ok, tried, flag))
        if ok >= 3:
            for p, k, u in shown:
                say("      %s %s -> %s" % (k, p, u[:200]))

# ------------------------------------------------------------- if it hits ---
best_ok, best = -1, None
for cname, (P, S), pre in CANDS:
    ok = 0
    for r in bodies:
        b = r["body"]
        ct = b[pre:]
        if not ct or len(ct) % 8:
            continue
        prev, pt = b[:8], b""
        for i in range(0, len(ct), 8):
            pt += block_dec(P, S, ct[i:i + 8], prev)
            prev = ct[i:i + 8]
        if unpad(pt) is not None:
            ok += 1
    if ok > best_ok:
        best_ok, best = ok, (cname, P, S, pre)

if best_ok >= 3:
    cname, P, S, pre = best
    say("")
    say("=" * 78)
    say("PLAINTEXT  key=%s pre=%d" % (cname, pre))
    say("=" * 78)
    for r in bodies:
        b = r["body"]
        ct = b[pre:]
        if not ct or len(ct) % 8:
            continue
        prev, pt = b[:8], b""
        for i in range(0, len(ct), 8):
            pt += block_dec(P, S, ct[i:i + 8], prev)
            prev = ct[i:i + 8]
        u = unpad(pt)
        good = u is not None
        if good:
            pt = u
        say("-" * 78)
        say("%s %s  %d bytes  pkcs7=%s" % (r["kind"], r["path"], len(b), good))
        say("  raw   %s" % pt[:240].hex())
        say("  ascii %s" % "".join(chr(x) if 0x20 <= x < 0x7F else "."
                                   for x in pt[:240]))

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
