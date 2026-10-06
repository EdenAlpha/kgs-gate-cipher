"""Where is the AES?  libUE4.so has no S-box, so it is not a table implementation.

The previous scan found SHA-256, MD5, BLAKE2s/b and CRC32 tables but no AES
S-box, no Rcon and no T-table.  On ARM64 that leaves exactly one likely answer:
the Armv8 crypto extensions, where AESE/AESD/AESMC do the whole cipher in
hardware and no table ever exists in memory.

So:
  1. vectorised scan of .text for words in the 0x4E28xxxx class (the
     AESE/AESD/AESMC/AESIMC encoding space), reporting the distinct low-16
     bit patterns so the real instruction set shows itself without me having
     to assert encodings up front
  2. .dynsym / .gnu.hash exported names matching aes/cipher/encrypt/ssl
  3. .rodata C-strings mentioning AES by name
"""
import re
import struct

import numpy as np

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\find_aes_impl.txt"

d = open(SO, "rb").read()
FL = len(d)
out = []


def say(s=""):
    out.append(str(s))


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
    SECS.append({"name": nm, "addr": s[3], "off": s[4], "size": s[5],
                 "entsize": s[9], "flags": s[2]})
by = {s["name"]: s for s in SECS}

# .text is SHF_EXECINSTR (0x4); fall back to the biggest executable section
text = None
for s in SECS:
    if s["name"] == ".text":
        text = s
        break
if text is None:
    cand = [s for s in SECS if s["flags"] & 0x4]
    text = max(cand, key=lambda s: s["size"])
say("executing section: %s   off 0x%x  va 0x%x  size %d"
    % (text["name"], text["off"], text["addr"], text["size"]))
say("")

# ------------------------------------ 1. Armv8 crypto-extension opcodes -----
raw = d[text["off"]:text["off"] + text["size"]]
# pad to a whole number of words
if len(raw) % 4:
    raw += b"\x00" * (4 - len(raw) % 4)
words = np.frombuffer(raw, dtype="<u4")

# 0x4E28xxxx  is the Advanced SIMD crypto class (AESE/AESD/AESMC/AESIMC and
# the SHA-1/SHA-256 group sit alongside it).  Mask the low 10 bits, which hold
# the register fields, and histogram what remains.
CRYPTO_CLASS = 0x4E280000
sel = (words & 0xFFFF0000) == CRYPTO_CLASS
say("words in class 0x4e28xxxx : %d" % int(sel.sum()))

low = words[sel] & 0x0000FC00          # keep the opcode bits, drop Rn/Rd
vals, counts = np.unique(low, return_counts=True)
say("")
say("distinct opcode patterns in that class (low10 -> count):")
for v, c in sorted(zip(vals.tolist(), counts.tolist()),
                   key=lambda t: -t[1]):
    say("   0x%08x   %8d" % (v, c))
say("")

# If the class is empty, widen: look at the whole SIMD fp-instruction space
# 0x4E2xxxxx to be sure nothing was missed by my class guess.
if int(sel.sum()) == 0:
    sel2 = (words & 0xFF000000) == 0x4E000000
    say("wider class 0x4exxxxxx words: %d" % int(sel2.sum()))
    v2, c2 = np.unique(words[sel2] & 0xFFFFFC00, return_counts=True)
    top = sorted(zip(v2.tolist(), c2.tolist()), key=lambda t: -t[1])[:25]
    say("top opcodes:")
    for v, c in top:
        say("   0x%08x   %8d" % (v, c))
    say("")

# Directly assert the four AES opcodes so a hit is unambiguous.
for name, base in (("AESE", 0x4E284800), ("AESD", 0x4E286800),
                   ("AESMC", 0x4E286C00), ("AESIMC", 0x4E287C00)):
    hit = np.nonzero((words & 0xFFFFFC00) == base)[0]
    say("  %-7s mask 0x%08x : %d occurrence(s)" % (name, base, int(hit.size)))
    for i in hit[:5]:
        va = text["addr"] + int(i) * 4
        say("        va 0x%08x   word 0x%08x" % (va, int(words[i])))
say("")

# ------------------------------------------- 2. exported / dynsym names -----
say("=" * 78)
say("SYMBOL NAMES mentioning aes / cipher / encrypt / ssl / tls")
say("=" * 78)
if ".dynsym" in by and ".dynstr" in by:
    ds, dt = by[".dynsym"], by[".dynstr"]
    blob = d[ds["off"]:ds["off"] + ds["size"]]
    entsz = ds["entsize"] or 24
    strs = d[dt["off"]:dt["off"] + dt["size"]]
    pat = re.compile(rb"aes|cipher|encrypt|decrypt|ssl|tls|crypto", re.I)
    n = 0
    for i in range(len(blob) // entsz):
        st_name = struct.unpack_from("<I", blob, i * entsz)[0]
        if st_name >= len(strs):
            continue
        b = strs[st_name:strs.index(b"\x00", st_name)]
        if pat.search(b):
            say("  %s" % b.decode("ascii", "replace"))
            n += 1
            if n > 60:
                say("  ... (truncated)")
                break
    if n == 0:
        say("  none")
say("")

# ------------------------------------------------ 3. rodata strings ---------
say("=" * 78)
say(".rodata C-strings mentioning AES")
say("=" * 78)
ro = by.get(".rodata")
if ro:
    blob = d[ro["off"]:ro["off"] + ro["size"]]
    for m in re.finditer(rb"[\x20-\x7e]{6,}", blob):
        s = m.group()
        if re.search(rb"\bAES\b|AES-?\d|AES_|aes_", s):
            say("  off 0x%08x  %r" % (ro["off"] + m.start(), s[:80]))
say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
