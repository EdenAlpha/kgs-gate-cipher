"""Map the request-building module and list every call in it.

Why here: the string 'pes-custom-encrypt' (the header that names the cipher)
has 8 xrefs, and four of them fall in 0x7b34d18 / 0x7b35cf4 / 0x7b6ba8 /
0x7b39120 -- a few KB either side of the sign builder at 0x7b38a44.  Whatever
sets 'pes-custom-encrypt: AES256' is in the same module that builds the body,
so the encryptor must be in this range.

Two fixes over the previous attempt:
  * function starts come from the Ghidra dump (FUN_<va>), not a prologue guess
    -- the guess landed inside other functions and the adrp targets it printed
    were past EOF, which is how we knew it was wrong
  * both 'bl' and 'blr' are listed (a virtual/indirect call would be missed)
"""
import re
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
DUMP = r"C:\Users\Administrator\AppData\Local\Temp\2\full1\fulldump_out.txt"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\xref_encrypt.txt"

d = open(SO, "rb").read()
DELTA = 0x4000                 # segment 2: ELF VA -> file offset
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = []


def say(s=""):
    out.append(str(s))


# ------------------------------------------------- function table from dump -
# Ghidra VAs are ELF VAs + 0x100000 in this range (verified on the sign builder)
FUN = sorted(int(m.group(1), 16)
             for m in re.finditer(r"FUN_([0-9a-f]{8})", open(DUMP, "r",
                                                             encoding="utf-8",
                                                             errors="replace").read()))
say("functions in dump: %d   range 0x%x .. 0x%x"
    % (len(FUN), FUN[0], FUN[-1]))
say("")

DUMP_DELTA = 0x100000


def containing_fun(elf_va):
    dv = elf_va + DUMP_DELTA
    lo, hi = 0, len(FUN) - 1
    ans = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if FUN[mid] <= dv:
            ans = FUN[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return ans


# ------------------------------------------------------- PLT symbol names ---
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
    if va < plt["addr"] or va > plt["addr"] + plt["size"]:
        return None
    return reloc.get((va - plt["addr"] - 0x20) // 16)


# ------------------------------------- targets: pes-custom-encrypt xrefs -----
# dump VAs from enc_scan.txt; convert to ELF VAs (six needed +0x100000, two do not)
XREFS = [0x07C23164, 0x07C2EB78, 0x07C34D18, 0x07C35CF4,
         0x07C36BA8, 0x07C39120, 0x07EC024C, 0x07ECAD64]

say("=" * 78)
say("WHICH FUNCTION HOLDS EACH 'pes-custom-encrypt' XREF")
say("=" * 78)
starts = set()
for dv in XREFS:
    elf = dv - DUMP_DELTA
    f = containing_fun(elf)
    fe = (f - DUMP_DELTA) if f else None
    say("  xref dump=0x%08x  elf=0x%08x  -> FUN dump=0x%s  elf=%s"
        % (dv, elf, ("%08x" % f) if f else "????????",
           ("0x%08x" % fe) if fe else "?"))
    if fe:
        starts.add(fe)
say("")

# ------------------------------------- also the two callers we already trust --
for elf in (0x7B38268, 0x7B2EF44):
    f = containing_fun(elf)
    if f:
        starts.add(f - DUMP_DELTA)
say("functions to walk: %s" % ", ".join("0x%x" % s for s in sorted(starts)))
say("")

# ------------------------------------------------------------ walk each ------
CRYPTO_HINTS = ("aes", "cipher", "encrypt", "evp", "cbc", "gcm", "sha", "hmac",
                "rand", "crypt", "digest", "md5")

for st in sorted(starts):
    off = st - DELTA
    if off < 0 or off >= len(d):
        say("=" * 78)
        say("0x%x  -- out of range for this segment" % st)
        say("=" * 78)
        say("")
        continue
    say("=" * 78)
    say("FUNCTION 0x%x" % st)
    say("=" * 78)
    insns = list(md.disasm(d[off:off + 0x2800], st))
    say("  instructions: %d  (0x%x .. 0x%x)"
        % (len(insns), insns[0].address, insns[-1].address))
    for i in insns:
        if i.mnemonic in ("bl", "blr"):
            tgt = None
            nm = None
            if i.mnemonic == "bl":
                try:
                    tgt = int(i.op_str.lstrip("#"), 16)
                except Exception:
                    tgt = None
                nm = plt_name(tgt) if tgt else None
            idx = insns.index(i)
            ctx = "; ".join("%s %s" % (c.mnemonic, c.op_str)
                            for c in insns[max(0, idx - 3):idx])
            tag = ("   PLT: %s" % nm) if nm else ""
            hint = ""
            if nm and any(h in nm.lower() for h in CRYPTO_HINTS):
                hint = "   <<<< CRYPTO?"
            say("    0x%08x %s %s%s%s" % (i.address, i.mnemonic,
                                          i.op_str, tag, hint))
            say("          setup: %s" % ctx)
    say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
