"""Identify the hash behind the sign HMAC, then test it against the 13 real signs.

Three things, in one pass:
  1. The HMAC ctx at sp+0x180 gets its vtable from *(0x98dec28)+0x10.
     Follow that (through the APS2/RELA relocations if needed) and print the
     function pointers -> we can name the digest from its code.
  2. String-scan libUE4.so for the digest/library names directly.
  3. Empirical check: is sign_raw[0:N] == HMAC(key, body) for N in {20,32,40}?
     and do the two halves of the 40 raw bytes differ (i.e. is 40 real)?
"""
import base64
import hashlib
import hmac
import re
import struct
import os

ROOT = r"C:\Users\Administrator\AppData\Local\Temp\2"
SO = os.path.join(ROOT, "game", "libUE4.so")
MITM = os.path.join(ROOT, "rec2", "flows.mitm")
LOG = os.path.join(ROOT, "rec2", "flows.log")
SEED = b"Xrq-RtAF_91MAE82"

d = open(SO, "rb").read()

# ---------------------------------------------------------------- ELF ----
e_phoff, = struct.unpack_from("<Q", d, 0x20)
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
segs = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, = struct.unpack_from("<I", d, o)
    p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
    if p_type == 1:
        segs.append((p_offset, p_vaddr, p_filesz))


def va2off(v):
    for po, pv, ps in segs:
        if pv <= v < pv + ps:
            return po + (v - pv)
    return None


print("=" * 72)
print("1. digest / crypto library names present in libUE4.so")
print("=" * 72)
pats = [b"SHA256", b"SHA-256", b"sha256", b"SHA1", b"SHA-1", b"sha1",
        b"MD5", b"HMAC", b"hmac", b"Blowfish", b"blowfish", b"CryptoPP",
        b"Botan", b"mbedtls", b"evp_Encrypt", b"AES_set_encrypt",
        b"AES_encrypt", b"AES_cbc_encrypt", b"EVP_aes_256", b"EVP_Encrypt",
        b"EVP_Digest", b"EVP_MD_CTX", b"EVP_sha", b"RIPEMD", b"SHA3"]
for p in pats:
    n = d.count(p)
    if n:
        i = d.find(p)
        print("  %-16s x%-4d first@0x%x  %r" % (p.decode(), n, i,
                                                 d[max(0, i - 24):i + 40][:64]))

# ------------------------------- 2. hash ctx vtable ----------------------
print()
print("=" * 72)
print("2. HMAC context vtable")
print("=" * 72)
slot = va2off(0x98dec28)
raw = struct.unpack_from("<Q", d, slot)[0]
print("  *(0x98dec28) on disk = 0x%x" % raw)

# follow R_AARCH64_RELATIVE-style relocations for that slot if the on-disk
# value is zero (the pointer is supplied by the loader, not the file)
if raw == 0:
    print("  zero -> looking for a relocation whose r_offset == 0x98dec28")
    e_shoff, = struct.unpack_from("<Q", d, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 0x3a)
    shstr = e_shoff + e_shstrndx * e_shentsize
    str_off, = struct.unpack_from("<Q", d, shstr + 24)
    for i in range(e_shnum):
        s = e_shoff + i * e_shentsize
        name_off, sh_type = struct.unpack_from("<II", d, s)
        sh_offset, sh_size, sh_link, sh_info = struct.unpack_from(
            "<QQII", d, s + 24)
        nm = d[str_off + name_off:d.index(b"\x00", str_off + name_off)]
        if sh_type in (4, 9) and b"rela" in nm:        # SHT_RELA / SHT_ANDROID_RELA
            entsz = 24 if sh_type == 4 else 12 * 4
            for j in range(0, sh_size, entsz):
                if sh_type == 4:
                    r_off, r_info, r_add = struct.unpack_from("<QQQ", d, sh_offset + j)
                else:                                   # Android packed: off, info, addend...
                    r_off = struct.unpack_from("<Q", d, sh_offset + j)[0]
                    r_add = struct.unpack_from("<q", d, sh_offset + j + 16)[0]
                if r_off == 0x98dec28:
                    print("  %s: r_offset=0x%x addend=0x%x" % (nm.decode(), r_off, r_add))
                    raw = r_add
                    break
        if raw:
            break

if raw:
    vt = raw + 0x10
    print("  vtable start = 0x%x" % vt)
    fo = va2off(vt)
    if fo is not None:
        for idx in range(6):
            fn = struct.unpack_from("<Q", d, fo + idx * 8)[0]
            print("    vtable[%d] = 0x%x" % (idx, fn))
    tinfo = va2off(raw + 8)
    if tinfo is not None:
        tp = struct.unpack_from("<Q", d, tinfo)[0]
        tfo = va2off(tp)
        if tfo is not None:
            namep = struct.unpack_from("<Q", d, tfo + 8)[0]
            nfo = va2off(namep)
            if nfo is not None:
                end = d.index(b"\x00", nfo)
                print("  typeinfo -> %r" % d[nfo:end])

# ---------------------------------- 3. empirical -------------------------
print()
print("=" * 72)
print("3. the 13 recorded sign cookies")
print("=" * 72)
raw_log = open(LOG, "rb").read()
bodies, name = [], None
for line in raw_log.split(b"\n"):
    if line.startswith(b"### REQ POST"):
        m = re.search(rb"gate_([A-Z_]+)", line)
        name = m.group(1).decode() if m else "?"
    elif line.startswith(b"REQHEX: ") and name:
        bodies.append((name, bytes.fromhex(line[8:].strip().decode())))
        name = None
md = open(MITM, "rb").read()
signs = [base64.b64decode(m.group(1))
         for m in re.finditer(rb"sign=([A-Za-z0-9+/=]+)", md)]
n = min(len(bodies), len(signs))
pairs = [(bodies[i], signs[i]) for i in range(n)]
print("pairs = %d   raw length = %s" % (n, sorted({len(s) for _, s in pairs})))
for i, ((nm, b), s) in enumerate(pairs[:4]):
    print("  %-30s %dB  half1=%s half2=%s" % (
        nm, len(b), s[:20].hex(), s[20:].hex()))
same = sum(1 for _, s in pairs if s[:20] == s[20:])
print("  pairs where first 20 bytes == last 20 bytes: %d/%d" % (same, n))
uniq_tail = len({s[20:] for _, s in pairs})
print("  distinct last-20-byte values: %d/%d" % (uniq_tail, n))

print()
print("-- HMAC tests: key x message x digest, must match ALL %d pairs --" % n)
keys = {"seed": SEED, "seed*4": SEED * 4, "sha256(seed)": hashlib.sha256(SEED).digest()}
msgs = {}
for (nm, b) in pairs:
    msgs[nm] = {"body": b, "iv": b[:16], "ct": b[16:], "seed+body": SEED + b}
hits = 0
for kn, kv in keys.items():
    for mn in next(iter(msgs.values())):
        for hn, hf in (("sha1", hashlib.sha1), ("sha256", hashlib.sha256),
                       ("md5", hashlib.md5)):
            ok = all(hmac.new(kv, msgs[nm][mn], hf).digest()
                     == signs[i][:hf().digest_size]
                     for i, (nm, _) in enumerate(pairs))
            if ok:
                print("  MATCH  key=%s  msg=%s  HMAC-%s" % (kn, mn, hn))
                hits += 1
if not hits:
    print("  NO MATCH: %d key x %d msg x 3 digest combinations tested"
          % (len(keys), len(next(iter(msgs.values())))))
