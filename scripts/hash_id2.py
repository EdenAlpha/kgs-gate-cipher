"""Identify the hash that produces the 40-byte sign MAC.

The sign-builder passes w1 = 0x28 (40) as the MAC length, and the captured
signs decode to exactly 40 bytes -- so this is NOT a plain HMAC-SHA1 (20) or
HMAC-SHA256 (32).  Any key sweep built on those sizes could never match.

Facts sought, by reading not guessing:
  1. which hash -- its round constants are unique per algorithm
  2. one context or two (two IVs => inner||outer concatenated = 40 bytes)
  3. confirm 0x74b8d24 / 0x74b8d5c really are base64 (as the tail implies)
  4. confirm 0x31b542c really is basic_stringbuf::str()

Addresses are ELF VAs; segment delta is 0x4000 in this range (verified earlier
against the known-good sign builder 0x7b38a44 -> file 0x7b34a44).
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\hash_id2.txt"

d = open(SO, "rb").read()
DELTA = 0x4000
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

out = []


def say(s=""):
    out.append(str(s))


# known round-constant fingerprints, little-endian 32/64-bit immediates
FINGERPRINTS = {
    # SHA-1 round constants
    "SHA-1 K1 (0x5A827999)": struct.pack("<I", 0x5A827999),
    "SHA-1 K2 (0x6ED9EBA1)": struct.pack("<I", 0x6ED9EBA1),
    "SHA-1 K3 (0x8F1BBCDC)": struct.pack("<I", 0x8F1BBCDC),
    "SHA-1 K4 (0xCA62C1D6)": struct.pack("<I", 0xCA62C1D6),
    "SHA-1 IV (0x67452301)": struct.pack("<I", 0x67452301),
    "SHA-1 IV (0xEFCDAB89)": struct.pack("<I", 0xEFCDAB89),
    "SHA-1 IV (0x98BADCFE)": struct.pack("<I", 0x98BADCFE),
    "SHA-1 IV (0x10325476)": struct.pack("<I", 0x10325476),
    # SHA-256
    "SHA-256 K (0x428A2F98)": struct.pack("<I", 0x428A2F98),
    "SHA-256 IV (0x6A09E667)": struct.pack("<I", 0x6A09E667),
    "SHA-256 IV (0xBB67AE85)": struct.pack("<I", 0xBB67AE85),
    "SHA-256 tail (0x5BE0CD19)": struct.pack("<I", 0x5BE0CD19),
    # MD5
    "MD5 T1 (0xD76AA478)": struct.pack("<I", 0xD76AA478),
    "MD5 T2 (0xE8C7B756)": struct.pack("<I", 0xE8C7B756),
    # SHA-512 / SHA-384 (64-bit)
    "SHA-512 IV (0x6A09E667F3BCC908)": struct.pack("<Q", 0x6A09E667F3BCC908),
    "SHA-512 K (0x428A2F98D728AE22)": struct.pack("<Q", 0x428A2F98D728AE22),
    "SHA-512 tail (0x5BE0CD19C3F7DBAC)".replace("`", ""): struct.pack(
        "<Q", 0x5BE0CD19C3F7DBAC),
    # SHA-3 / Keccak round constants
    "SHA3 RC[0] (0x0000000000000001)": struct.pack("<Q", 0x0000000000000001),
    # Blake2b IV is same as SHA-512 IV (reported above)
    # CRC32 poly (appears in zlib implementations)
    "CRC32 poly (0xEDB88320)": struct.pack("<I", 0xEDB88320),
    # base64 alphabet marker
    "base64 tail 'z+/\\0'": b"z+/\x00",
    "base64 URL tail 'z-_\\0'": b"z-_ \x00",
}


def disasm(label, va, size, max_insns=70):
    off = va - DELTA
    say("=" * 78)
    say(label)
    say("ELF VA 0x%x   file 0x%x" % (va, off))
    say("=" * 78)
    n = 0
    for insn in md.disasm(d[off:off + size], va):
        note = ""
        if insn.mnemonic == "bl":
            note = "   <- PLT" if insn.op_str.startswith("#0x8b3") else ""
        say("  0x%08x  %-8s %s%s" % (insn.address, insn.mnemonic,
                                     insn.op_str, note))
        n += 1
        if n >= max_insns:
            say("  ... (%d+ instructions)" % n)
            break
        if insn.mnemonic == "ret" and n > 8:
            break
    say("")


def scan(label, va, size):
    off = va - DELTA
    blob = d[off:off + size]
    say("=" * 78)
    say("FINGERPRINT SCAN: %s" % label)
    say("ELF VA 0x%x .. 0x%x   (%d bytes)" % (va, va + size, size))
    say("=" * 78)
    hits = 0
    for name, pat in FINGERPRINTS.items():
        idxs = []
        start = 0
        while True:
            i = blob.find(pat, start)
            if i < 0:
                break
            idxs.append(va + i)
            start = i + 1
        if idxs:
            hits += 1
            say("  %-34s x%-3d at %s" % (name, len(idxs),
                                         ", ".join("0x%x" % x for x in idxs[:6])))
    if not hits:
        say("  (no known hash constants present in this range)")
    say("")


# 1. the MAC function itself
scan("0x7b39a28  (the call that writes the MAC)", 0x7B39A28, 0x400)
disasm("0x7b39a28  -- the MAC / 'HMAC' call", 0x7B39A28, 0x400, 90)

# 2. the base64-ish helpers from the tail
scan("0x74b8d24 / 0x74b8d5c  (base64 helpers?)", 0x74B8D00, 0x300)
disasm("0x74b8d24  -- sized as malloc(len+1) input", 0x74B8D24, 0x40, 25)
disasm("0x74b8d5c  -- called with w1=40, writes into that buffer",
       0x74B8D5C, 0x60, 35)

# 3. str()
disasm("0x31b542c  -- called twice on the stringbuf (assumed str())",
       0x31B542C, 0x80, 40)

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
