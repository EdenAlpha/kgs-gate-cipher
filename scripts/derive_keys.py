"""Reproduce the two XOR loops of 0x7d64fb0 and print the real keys.

Everything the generator uses is a file-backed constant:

    T1 (9 bytes)   0x9823b40   91 96 9a 94 96 9a 93 98 a0
    T2 (12 bytes)  0x9823b49   58 6c 7e 39 28 2e 39 2b 29 2b 2f 19

    loop A  src 0x9823af8, 56 bytes  -> bufA 0xa4b0158  -> context A (0xa4a98d8)
    loop B  src 0x9823ba8, 32 bytes  -> bufB 0xa4b0170  -> context B (0xa4a98d0)

    idx1 = i - 9  * ((i * 57)  >> 9)     == i mod 9   over the range in play
    idx2 = i - 12 * ((i * 171) >> 11)    == i mod 12
    out[i] = src[i] ^ T1[idx1] ^ T2[idx2] ^ 0x75

The index arithmetic is reproduced instruction-for-instruction (32-bit wrap,
then uxtb) rather than simplified to i%9 -- an approximation here would hand
back a plausible-looking key that decrypts nothing.
"""
import struct

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\derived_keys.txt"

BLOB_A = 0x9823AF0
BLOB_B = 0x9823BA0

SRC_A, SRC_B = 0x9823AF8, 0x9823BA8
LEN_A, LEN_B = 0x38, 0x20
T1_A, T2_A = 0x9823B40, 0x9823B49
T1_B, T2_B = 0x9823BD8, 0x9823BE1

d = open(SO, "rb").read()


def _delta(va):
    if va >= 0x9906CC0:
        return 0xC000
    if va >= 0x8B75140:
        return 0x8000
    if va >= 0x28293C0:
        return 0x4000
    return 0x0


def get(va, n):
    o = va - _delta(va)
    return d[o:o + n]


M1, S1, D1 = 57, 9, 9      # mul w16,w15,w9 ; lsr #9 ; *9
M2, S2, D2 = 171, 11, 12   # mul w15,w15,w10 ; lsr #11 ; msub w11=12


def derive(src, t1, t2):
    """Exactly the loop body, in the order the instructions execute."""
    out = bytearray()
    for i in range(len(src)):
        w15 = i & 0xFF
        w16 = (w15 * M1) & 0xFFFFFFFF
        w17 = (w15 * M2) & 0xFFFFFFFF
        w16 = (w16 >> S1) & 0xFFFFFFFF
        w17 = (w17 >> S2) & 0xFFFFFFFF
        w16 = (w16 + (w16 << 3)) & 0xFFFFFFFF          # add w16,w16,w16,lsl#3
        idx2 = (i - (w17 * D2)) & 0xFFFFFFFF           # msub w15,w15,w11,w8
        idx1 = (i - w16) & 0xFFFFFFFF                  # sub w16,w8,w16
        b = src[i] ^ t1[idx1 & 0xFF] ^ t2[idx2 & 0xFF] ^ 0x75
        out.append(b & 0xFF)
    return bytes(out)


def show(tag, src, t1, t2, n):
    key = derive(src[:n], t1, t2)
    pr = all(0x20 <= c < 0x7F for c in key)
    say("=" * 78)
    say("%s   %d bytes   printable=%s" % (tag, len(key), pr))
    say("=" * 78)
    say("  src : %s" % src[:n].hex())
    say("  T1  : %s   (%d bytes)" % (t1.hex(), len(t1)))
    say("  T2  : %s   (%d bytes)" % (t2.hex(), len(t2)))
    say("  KEY : %s" % key.hex())
    say("  ascii: %s" % ("".join(chr(c) if 0x20 <= c < 0x7F else "."
                                for c in key)))
    say("")
    return key


out = []


def say(s=""):
    out.append(str(s))


srcA, t1A, t2A = get(SRC_A, LEN_A), get(T1_A, 9), get(T2_A, 12)
srcB, t1B, t2B = get(SRC_B, LEN_B), get(T1_B, 9), get(T2_B, 12)

say("blob A header+length : %s" % get(BLOB_A, 0x50).hex())
say("blob B header+length : %s" % get(BLOB_B, 0x38).hex())
say("T1 identical across blobs: %s" % (t1A == t1B))
say("T2 identical across blobs: %s" % (t2A == t2B))
say("")

# sanity: show the index sequences actually produced over the real ranges
def idx_of(i):
    w15 = i & 0xFF
    w16 = ((w15 * M1) & 0xFFFFFFFF) >> S1
    w17 = ((w15 * M2) & 0xFFFFFFFF) >> S2
    w16 = (w16 + (w16 << 3)) & 0xFFFFFFFF
    idx2 = (i - (w17 * D2)) & 0xFFFFFFFF
    idx1 = (i - w16) & 0xFFFFFFFF
    return idx1 & 0xFF, idx2 & 0xFF


say("idx1 for i=0..55 : %s" % [idx_of(i)[0] for i in range(56)])
say("idx2 for i=0..55 : %s" % [idx_of(i)[1] for i in range(56)])
say("idx1 == i mod 9  : %s"
    % all(idx_of(i)[0] == i % 9 for i in range(56)))
say("idx2 == i mod 12 : %s"
    % all(idx_of(i)[1] == i % 12 for i in range(56)))
say("")

ka = show("KEY A  (bufA 0xa4b0158 -> context 0xa4a98d8, 56 bytes)",
          srcA, t1A, t2A, LEN_A)
kb = show("KEY B  (bufB 0xa4b0170 -> context 0xa4a98d0, 32 bytes)",
          srcB, t1B, t2B, LEN_B)

say("=" * 78)
say("PROBES")
say("=" * 78)
say("  A[:32] = %s" % ka[:32].hex())
say("  A[24:] = %s" % ka[24:].hex())
say("  A[:16] = %s" % ka[:16].hex())
say("  A[16:32] = %s" % ka[16:32].hex())
say("  A[32:] = %s" % ka[32:].hex())
say("  md5(A)[:8] = %s" % __import__("hashlib").md5(ka).hexdigest())
say("  sha256(A)[:32] = %s" % __import__("hashlib").sha256(ka).hexdigest()[:32])
say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
