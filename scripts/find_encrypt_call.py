"""Find the function that hands the sign builder its (already encrypted) body.

Chain established so far:
    caller @0x7b2e44c
        x21 = sp+0x28 data   x0/sp+0x28 size   ->  bl 0x7b38a44 (sign builder)
        then a virtual call sends that SAME buffer plus the sign

So the buffer at sp+0x28 is produced somewhere inside the caller's own frame.
Walking that function backwards gives us its callees -- one of them must be the
body builder / encryptor, and it is the code that must name or supply the key.

Method: scan backwards for a real AArch64 function prologue
(`stp x29, x30, [sp, #imm]!`), then disassemble forward and list every `bl`
target with its argument-setup context.
"""
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\find_encrypt_call.txt"

d = open(SO, "rb").read()
DELTA = 0x4000          # ELF VA -> file offset in this segment (verified)
SITE = 0x7B2E44C        # the bl 0x7b38a44 site inside the caller

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = []


def say(s=""):
    out.append(str(s))


def disasm_at(va, nbytes):
    off = va - DELTA
    return list(md.disasm(d[off:off + nbytes], va))


# ---------------------------------------------------- find the prologue -----
say("searching backwards from 0x%x for a function prologue..." % SITE)
start = None
for va in range(SITE, SITE - 0x6000, -4):
    ins = disasm_at(va, 4)
    if not ins:
        continue
    i = ins[0]
    if i.mnemonic == "stp" and i.op_str.startswith("x29, x30, [sp") \
            and i.op_str.rstrip().endswith("]!"):
        start = va
        say("  prologue found at 0x%x :  %s %s" % (va, i.mnemonic, i.op_str))
        break

if start is None:
    say("  no prologue found -- aborting")
    open(OUT, "w", encoding="utf-8").write("\n".join(out))
    raise SystemExit("no prologue")

# ------------------------------------------------- disassemble the caller ---
size = SITE - start + 0x80
insns = disasm_at(start, size)
say("caller spans 0x%x .. 0x%x  (%d instructions shown)" %
    (start, insns[-1].address if insns else start, len(insns)))
say("")

# PLT names (resolved earlier by plt_resolve.py; reuse the same method)
import struct                                                   # noqa: E402
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
                 "entsize": s[9], "link": s[6]})
by = {s["name"]: s for s in secs}
plt, rela, dynsym, dynstr = by[".plt"], by[".rela.plt"], by[".dynsym"], by[".dynstr"]


def sym_name(idx):
    off = dynsym["off"] + idx * dynsym["entsize"]
    st_name = struct.unpack_from("<I", d, off)[0]
    b = dynstr["off"] + st_name
    return d[b:d.index(b"\x00", b)].decode("ascii", "replace")


reloc = {}
n_rela = rela["size"] // 24
for i in range(n_rela):
    r_offset, r_info, _ = struct.unpack_from("<QQq", d, rela["off"] + i * 24)
    reloc[i] = sym_name(r_info >> 32)


def plt_name(va):
    if va < plt["addr"]:
        return None
    idx = (va - plt["addr"] - 0x20) // 16      # PLT[0] is a 32-byte header
    return reloc.get(idx)


# --------------------------------------------------------------- report -----
say("=" * 78)
say("CALLS INSIDE THE CALLER  (0x%x .. )" % start)
say("=" * 78)
for i in insns:
    if i.mnemonic != "bl":
        continue
    try:
        tgt = int(i.op_str.lstrip("#"), 16)
    except Exception:
        continue
    nm = plt_name(tgt)
    tag = ("  PLT: %s" % nm) if nm else ""
    # context: the 3 preceding instructions show argument setup
    idx = insns.index(i)
    ctx = insns[max(0, idx - 3):idx]
    ctxs = "; ".join("%s %s" % (c.mnemonic, c.op_str) for c in ctx)
    say("  0x%08x -> 0x%08x%s" % (i.address, tgt, tag))
    say("        setup: %s" % ctxs)

say("")
say("=" * 78)
say("ALL INSTRUCTIONS AROUND THE SIGN-BUILDER CALL SITE")
say("=" * 78)
for i in insns:
    if abs(i.address - SITE) <= 0x60:
        mark = "  <== sign builder call" if i.address == SITE else ""
        say("  0x%08x  %-8s %s%s" % (i.address, i.mnemonic, i.op_str, mark))

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
