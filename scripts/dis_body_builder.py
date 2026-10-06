"""Where is the body encrypted, and where does the key come from?

Chain now proven end-to-end in the caller @0x7b2e244:
    0x7b2e3b4 -> 0x7b2ef44   (x1 = sp+0x28)   builds the body
    0x7b2e46c -> 0x7b38a44                     signs that same buffer
    0x7b2e4ac  blr [..][0x20]                   sends it (x2=data, x3=size, x5=sign)

The recorded wire bytes were accepted by the live server together with their
sign, so the buffer is ALREADY ciphertext by the time it is signed.  Therefore
the encryptor is 0x7b2ef44 or something it calls.

This dumps:
  1. the three URL strings the caller passes (confirming this is the gate sender)
  2. 0x7b2ef44  -- the body builder, full call list
  3. 0x7b38268  -- the other call just before signing
  4. for every callee: resolved .rela.plt name when it is an import
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\dis_body_builder.txt"

d = open(SO, "rb").read()
DELTA = 0x4000                      # ELF VA -> file offset, this segment
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = []


def say(s=""):
    out.append(str(s))


# ------------------------------------------------------------ PLT names ----
e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def sec(i):
    o = e_shoff + i * e_shentsize
    return struct.unpack_from("<IIQQQQIIQQ", d, o)


shstr = sec(e_shstrndx)
secs = []
for i in range(e_shnum):
    s = sec(i)
    nm = d[shstr[4] + s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    secs.append({"name": nm, "addr": s[3], "off": s[4], "size": s[5],
                 "entsize": s[9]})
by = {s["name"]: s for s in secs}
plt, rela = by[".plt"], by[".rela.plt"]
dynsym, dynstr = by[".dynsym"], by[".dynstr"]


def sym_name(idx):
    off = dynsym["off"] + idx * dynsym["entsize"]
    st_name = struct.unpack_from("<I", d, off)[0]
    b = dynstr["off"] + st_name
    return d[b:d.index(b"\x00", b)].decode("ascii", "replace")


reloc = {}
for i in range(rela["size"] // 24):
    r_offset, r_info, _ = struct.unpack_from("<QQq", d, rela["off"] + i * 24)
    reloc[i] = sym_name(r_info >> 32)


def plt_name(va):
    if va < plt["addr"]:
        return None
    return reloc.get((va - plt["addr"] - 0x20) // 16)


def disasm_at(va, nbytes):
    off = va - DELTA
    return list(md.disasm(d[off:off + nbytes], va))


def find_prologue(site, back=0x6000):
    for va in range(site, site - back, -4):
        ins = disasm_at(va, 4)
        if ins and ins[0].mnemonic == "stp" and \
                ins[0].op_str.startswith("x29, x30, [sp") and \
                ins[0].op_str.rstrip().endswith("]!"):
            return va
    return None


# -------------------------------------------------- 1. URL path strings ----
say("=" * 78)
say("1.  URL-ISH STRINGS THE CALLER PASSES (x1/x2 at 0x7b2e41c..0x7b2e444)")
say("=" * 78)
for va in (0xA4A98E8, 0xA4A9900, 0xA4A9918, 0xA4A98E8 + 0x30):
    off = va - 0                      # segment 1: delta 0
    b = d[off:off + 64]
    end = b.find(b"\x00")
    if end < 0:
        end = 64
    say("  0x%08x  %r" % (va, b[:end]))
say("")


# --------------------------------------------- 2/3. the two callees --------
for label, site, size in (
        ("0x7b2ef44   BODY BUILDER (x1 = sp+0x28)", 0x7B2EF44, 0x200),
        ("0x7b38268   called just before the sign", 0x7B38268, 0x180)):
    say("=" * 78)
    say(label)
    say("=" * 78)
    start = find_prologue(site)
    if start is None:
        say("  no prologue found; disassembling from the site itself")
        start = site
    say("  prologue: 0x%x" % start)
    insns = disasm_at(start, site - start + size)
    say("  instructions: %d   span 0x%x .. 0x%x"
        % (len(insns), insns[0].address, insns[-1].address))
    say("  --- calls ---")
    for i in insns:
        if i.mnemonic != "bl":
            continue
        try:
            tgt = int(i.op_str.lstrip("#"), 16)
        except Exception:
            continue
        nm = plt_name(tgt)
        tag = ("   PLT: %s" % nm) if nm else ""
        idx = insns.index(i)
        ctx = "; ".join("%s %s" % (c.mnemonic, c.op_str)
                        for c in insns[max(0, idx - 3):idx])
        say("    0x%08x -> 0x%08x%s" % (i.address, tgt, tag))
        say("          setup: %s" % ctx)
    # crypto-looking immediates (AES/S-box/padding constants)
    say("  --- notable immediates ---")
    blob = d[start - DELTA:site - DELTA + size]
    for name, pat in (
            ("0x1fffff / mask", struct.pack("<I", 0x1FFFFF)),
            ("NID_aes_256_cbc = 419 = 0x1a3", struct.pack("<I", 0x1A3)),
            ("PKCS7 pad 0x10", None),
    ):
        if pat and blob.find(pat) >= 0:
            say("    found %s at +0x%x" % (name, blob.find(pat)))
    say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
