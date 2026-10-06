"""Which crypto is actually compiled into libUE4.so?

Reasoning so far: the request path has no AES/OpenSSL import in .rela.plt, so
if the body is encrypted at all the cipher is statically linked.  Statically
linked ciphers leave unmistakable fingerprints -- a 256-byte AES S-box, the
SHA-256 round constants, ChaCha's 'expand 32-byte k'.  Locating those tables
gives us the cipher's address; locating who READS them gives us the encrypt
routine; and that routine's caller is where the key comes from.

No guessing: each hit is reported with its file offset and section, and every
table's first bytes are printed so a false match (e.g. random data) is obvious.
"""
import struct

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\crypto_tables.txt"

d = open(SO, "rb").read()
FL = len(d)
out = []


def say(s=""):
    out.append(str(s))


# ------------------------------------------------------- PT_LOAD file map ---
LOADS = [(0x00000000, 0x28253B0, 0x0),
         (0x28293C0, 0x6347D80, 0x4000),
         (0x8B75140, 0x0D8DB80, 0x8000),
         (0x9906CC0, 0x00063D84, 0xC000)]


def off2va(off):
    for v, fs, dl in LOADS:
        fo = v - dl
        if fo <= off < fo + fs:
            return off + dl
    return None


# ------------------------------------------------------------- sections -----
e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def sec(i):
    o = e_shoff + i * e_shentsize
    return struct.unpack_from("<IIQQQQIIQQ", d, o)


shstr = sec(e_shstrndx)
SECS = []
for i in range(e_shnum):
    s = sec(i)
    nm = d[shstr[4] + s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    SECS.append({"name": nm, "off": s[4], "size": s[5], "addr": s[3]})
SECS.sort(key=lambda s: s["off"])


def section_of(off):
    for s in SECS:
        if s["off"] <= off < s["off"] + s["size"]:
            return s["name"]
    return "?"


# ------------------------------------------------------------ the tables ----
TABLES = {
    "AES S-box (fwd)":
        bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
               0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]),
    "AES S-box (inv)":
        bytes([0x52, 0x09, 0xAD, 0x6D, 0x6F, 0x79, 0xE4, 0x93,
               0x3F, 0x64, 0xC5, 0x95, 0xA9, 0x7F, 0xFF, 0xF1]),
    "AES Rcon (01,02,04..36)":
        bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
               0x1B, 0x36]),
    "SHA-256 K[0..3]":
        bytes([0x98, 0x2F, 0x8A, 0x42, 0x91, 0x44, 0x37, 0x71,
               0xCF, 0xFB, 0xC0, 0xB5, 0xA5, 0xDB, 0xB5, 0xE9]),
    "SHA-256 K[12..13]":          # 0x580fcc5b, 0xbb001ad2
        bytes([0x5B, 0xCC, 0x0F, 0x58, 0xD2, 0x1A, 0x00, 0xBB]),
    "ChaCha sigma 'expand 32k'":
        b"expand 32-byte k",
    "SHA-1 init (0123456789abcdeF fedcba9876543210)":
        bytes([0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89,
               0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76]),
    "MD5 init (0123456789abcdeF ...)":
        bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
               0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]),
    "BLAKE2s IV (6A09E667..)":
        bytes([0x67, 0xE6, 0x09, 0x6A, 0x85, 0xAE, 0x67, 0xBB]),
    "BLAKE2b IV (6A09E667.. 243F6A88)":
        bytes([0x08, 0xC9, 0xBC, 0xF3, 0x67, 0xE6, 0x09, 0x6A]),
    "AES Te0 table (a56363c6 ...)":
        bytes([0xC6, 0x63, 0x63, 0xA5, 0xC8, 0x77, 0x77, 0xF1]),
    "CRC32 poly 0xEDB88320 (LE)":
        bytes([0x20, 0x83, 0xB8, 0xED]),
    "crc32 IEEE reflected table[0]=0x00000000, [1]=0x77073096":
        bytes([0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77]),
}

say("=" * 78)
say("CRYPTO TABLE FINGERPRINTS IN libUE4.so   (%d bytes)" % FL)
say("=" * 78)
found = {}
for name, pat in TABLES.items():
    hits = []
    start = 0
    while True:
        i = d.find(pat, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
        if len(hits) >= 8:
            break
    found[name] = hits
    if hits:
        say("")
        say("HIT  %s   (%d occurrence(s))" % (name, len(hits)))
        for h in hits[:8]:
            va = off2va(h)
            say("      off 0x%08x   va %s   sect %s"
                % (h, ("0x%08x" % va) if va else "<none>", section_of(h)))
            say("        first 32: %s" % d[h:h + 32].hex())
    else:
        say("miss %s" % name)

# ------------------------------------------------ AES S-box full-length ------
# A real S-box is exactly 256 distinct bytes; check any 16-byte hit really is
# the start of one, so a chance match in random data cannot masquerade.
sbox = bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
              0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])
say("")
say("=" * 78)
say("VALIDATING any AES S-box hit (needs 256 bytes, all distinct)")
say("=" * 78)
for h in found.get("AES S-box (fwd)", []):
    box = d[h:h + 256]
    ok = len(box) == 256 and len(set(box)) == 256
    say("  off 0x%08x : 256 bytes, distinct=%s  -> %s"
        % (h, len(set(box)), "REAL AES S-BOX" if ok else "not a real S-box"))

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
