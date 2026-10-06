"""Identify the cipher two independent ways: relocation-resolved vtables, and
magic constants.

Why the section-header path failed
----------------------------------
The vtables live in .data.rel.ro and read back as all zeros from the file,
because every entry is written by an R_AARCH64_RELATIVE relocation at load.
Parsing .rela.dyn through the section headers reported sh_entsize = 1 and
relocation types in the hundreds of millions, i.e. nonsense -- so that path
silently produced a vtable full of nulls and proved nothing.  The dynamic
segment (PT_DYNAMIC -> DT_RELA / DT_RELASZ / DT_RELAENT) is the authoritative
source and does not depend on section headers at all.

Second, independent signal
--------------------------
If the algorithm is a published one, its schedule constants are in the file:
    Blowfish  P[0] = 0x243f6a88   -> 88 6a 3f 24
    TEA/XTEA  delta = 0x9e3779b9   -> b9 79 37 9e
    RC5/RC6   P     = 0xb7e15163   -> 63 51 e1 b7
    Camellia        = 0xa09e667f   -> 7f 66 9e a0
    ChaCha/Salsa    = "expand 32-byte k"
    AES S-box       = 63 7c 77 7b ...
These are searched for as raw little-endian bytes.  A hit here plus a hit
in the vtable agree -> trust both; a disagreement -> read the code.
"""
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\id_cipher.txt"

d = open(SO, "rb").read()
FL = len(d)

out = []


def say(s=""):
    out.append(str(s))


# ------------------------------------------------------------ PT_DYNAMIC ----
e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
e_phentsize = struct.unpack_from("<H", d, 0x36)[0]
e_phnum = struct.unpack_from("<H", d, 0x38)[0]

phdrs = []
for i in range(e_phnum):
    p = struct.unpack_from("<IIQQQQQQ", d, e_phoff + i * e_phentsize)
    phdrs.append({"type": p[0], "flags": p[1], "off": p[2], "va": p[3],
                  "filesz": p[5], "memsz": p[6]})

PT_LOAD = 1


def va2off(va):
    for p in phdrs:
        if p["type"] == PT_LOAD and p["va"] <= va < p["va"] + p["filesz"]:
            return p["off"] + (va - p["va"])
    return None


dyn = None
for p in phdrs:
    if p["type"] == 2:          # PT_DYNAMIC
        dyn = p
        break
say("PT_DYNAMIC: %s" % ("offset 0x%x size 0x%x" % (dyn["off"], dyn["filesz"])
                        if dyn else "NOT FOUND"))

DT = {7: "DT_RELA", 8: "DT_RELASZ", 9: "DT_RELAENT", 0: "DT_NULL"}
tags = {}
off = dyn["off"]
while off + 16 <= dyn["off"] + dyn["filesz"]:
    tag, val = struct.unpack_from("<QQ", d, off)
    off += 16
    if tag == 0:
        break
    if tag in DT:
        tags[DT[tag]] = val
say("tags: %s" % {k: hex(v) for k, v in tags.items()})

rela_va = tags.get("DT_RELA")
rela_sz = tags.get("DT_RELASZ")
rela_ent = tags.get("DT_RELAENT", 24)
rela_off = va2off(rela_va) if rela_va else None
say("DT_RELA va=0x%x -> file 0x%s, sz=0x%x, entsize=%d"
    % (rela_va or 0, ("%x" % rela_off) if rela_off is not None else "?",
       rela_sz or 0, rela_ent))

R_AARCH64_RELATIVE = 1027
R_AARCH64_ABS64 = 257
R_AARCH64_GLOB_DAT = 1025
R_AARCH64_JUMP_SLOT = 1026
RN = {1027: "RELATIVE", 257: "ABS64", 1025: "GLOB_DAT", 1026: "JUMP_SLOT"}

rel = {}
types = {}
if rela_off is not None and rela_sz:
    for i in range(rela_sz // rela_ent):
        r_off, r_info, r_add = struct.unpack_from(
            "<QQq", d, rela_off + i * rela_ent)
        t = r_info & 0xFFFFFFFF
        types[t] = types.get(t, 0) + 1
        if t == R_AARCH64_RELATIVE:
            rel[r_off] = r_add & 0xFFFFFFFFFFFFFFFF

say("relocation types: %s"
    % {RN.get(k, hex(k)): v for k, v in
       sorted(types.items(), key=lambda kv: -kv[1])[:8]})
say("R_AARCH64_RELATIVE entries applied: %d" % len(rel))
say("")

try:
    from collections import Counter
except Exception:
    pass


def u64(va):
    if va in rel:
        return rel[va]
    o = va2off(va)
    if o is not None and o + 8 <= FL:
        return struct.unpack_from("<Q", d, o)[0]
    return None


# ---------------------------------------------------------------- PLT -------
e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def sec(i):
    return struct.unpack_from("<IIQQQQIIQQ", d, e_shoff + i * e_shentsize)


shstr = sec(e_shstrndx)
SECS = {}
for i in range(e_shnum):
    s = sec(i)
    nm = d[shstr[4] + s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    SECS.setdefault(nm, {"addr": s[3], "off": s[4], "size": s[5],
                         "entsize": s[9]})

plt = SECS.get(".plt")
rela_sec = SECS.get(".rela.plt")
dynsym = SECS.get(".dynsym")
dynstr = SECS.get(".dynstr")


def sym_name(i):
    off = dynsym["off"] + i * dynsym["entsize"]
    st_name = struct.unpack_from("<I", d, off)[0]
    b = dynstr["off"] + st_name
    return d[b:d.index(b"\x00", b)].decode("ascii", "replace")


reloc = {}
if rela_sec:
    for i in range(rela_sec["size"] // (rela_sec["entsize"] or 24)):
        _o, r_info, _ = struct.unpack_from(
            "<QQq", d, rela_sec["off"] + i * (rela_sec["entsize"] or 24))
        reloc[i] = sym_name(r_info >> 32)


def plt_name(va):
    if not plt or va < plt["addr"] or va > plt["addr"] + plt["size"]:
        return None
    return reloc.get((va - plt["addr"] - 0x20) // 16)


# ------------------------------------------------- magic constants ----------
say("=" * 78)
say("MAGIC CONSTANTS (independent of the relocation path)")
say("=" * 78)

MAGIC = [
    ("Blowfish P[0]=0x243f6a88", bytes.fromhex("886a3f24")),
    ("Blowfish P[1]=0x7144616c", bytes.fromhex("6c614471")),
    ("TEA/XTEA delta=0x9e3779b9", bytes.fromhex("b979379e")),
    ("RC5/RC6 P=0xb7e15163", bytes.fromhex("6351e1b7")),
    ("Camellia=0xa09e667f", bytes.fromhex("7f669ea0")),
    ("AES S-box[0..7]=637c777b...", bytes.fromhex("637c777bf26b6fc5")),
    ("DES IP table lead 0x1f..", bytes.fromhex("1e0f1d35")),
    ("expand 32-byte k", b"expand 32-byte k"),
    ("expand 16-byte k", b"expand 16-byte k"),
    ("Blowfish ascii", b"Blowfish"),
    ("TwoFish ascii", b"Twofish"),
    ("Salsa20", b"Salsa20"),
    ("ChaCha20", b"ChaCha20"),
    ("AES-256-CBC", b"AES-256-CBC"),
]
for tag, pat in MAGIC:
    hits = []
    start = 0
    while True:
        i = d.find(pat, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
        if len(hits) >= 4:
            break
    say("  %-28s %-22s -> %s%s"
        % (tag, pat[:16].hex() if all(32 <= c < 127 or c >= 0x80 for c in pat)
           else pat[:16].hex(),
           ["0x%x" % h for h in hits],
           "  (+more)" if len(hits) == 4 else ""))
say("")

# ------------------------------------------------- resolve vtables ---------
VT = {
    "cipher state (0x7b2d094 final)": 0x981A620,
    "cipher state (set before memcpy)": 0x981A5B0,
    "context A (56-byte key)": 0x981A590,
    "context B (32-byte key)": 0x981A4A0,
}

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

for tag, va in VT.items():
    say("=" * 78)
    say("VTABLE %s   @ 0x%x" % (tag, va))
    say("=" * 78)
    slots = [u64(va + 8 * i) for i in range(12)]
    for i, p in enumerate(slots):
        nm = plt_name(p) if p else None
        say("  [%2d] +0x%02x  0x%012x  %s"
            % (i, 8 * i, p or 0, ("PLT: %s" % nm) if nm else ""))
    say("")
    for i, p in enumerate(slots):
        if not p or p < 0x28293C0:
            continue
        say("  --- slot %d  vtable[+0x%02x] = 0x%x ---" % (i, 8 * i, p))
        o = va2off(p)
        if o is None:
            say("      not file backed")
            continue
        body = d[o:o + 0x90]
        for ins in md.disasm(body, p):
            say("      0x%08x  %-8s %-44s"
                % (ins.address, ins.mnemonic, ins.op_str))
            if ins.mnemonic in ("bl", "b"):
                try:
                    tgt = int(ins.op_str.lstrip("#"), 16)
                    nm = plt_name(tgt)
                    if nm:
                        say("             PLT: %s" % nm)
                except Exception:
                    pass
            if ins.mnemonic == "ret":
                say("      <<<<")
                break
        say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
