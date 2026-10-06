"""Context around the three pes-custom-encrypt xrefs the last walk missed.

The earlier walk (xref_encrypt2.py) started at 0x7b2e5fc and stopped 0x2800
bytes later, at 0x7b30dfc -- so it never reached 0x7b34d18, 0x7b35cf4 or
0x7b36ba8.  Those three are not global constructors (the constructor ones are
0x7b23164 and 0x7b2eb78, both immediately followed by __cxa_atexit); they are
the sites that ATTACH the header to an outgoing request, so the encryptor call
should sit next to them.

For each site:
  * find the enclosing function by scanning back to the preceding `ret`,
    which is far more reliable here than a prologue guess (the guess landed
    inside other functions and produced adrp targets past EOF)
  * disassemble from that start through the site
  * list every bl / blr with its resolved .rela.plt name
  * resolve every adrp+add pair to a real .rodata string, so we can see the
    literals the code is actually working with
"""
import struct
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
TAG = sys.argv[1] if len(sys.argv) > 1 else "a"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\xref_context_%s.txt" % TAG

d = open(SO, "rb").read()
FL = len(d)
DELTA = 0x4000
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = []


def say(s=""):
    out.append(str(s))


# ------------------------------------------------------- PT_LOAD file map ---
# (vaddr, filesz, delta = vaddr - file offset)
LOADS = [(0x00000000, 0x28253B0, 0x0),
         (0x28293C0, 0x6347D80, 0x4000),
         (0x8B75140, 0x0D8DB80, 0x8000),
         (0x9906CC0, 0x00063D84, 0xC000)]


def va2off(va):
    for v, fs, dl in LOADS:
        if v <= va < v + fs:
            return va - dl
    return None          # .bss: mapped, but no file bytes


def read_str(va, n=48):
    off = va2off(va)
    if off is None:
        return "<bss/va 0x%x not file-backed>" % va
    if off >= FL:
        return "<past EOF, off 0x%x>" % off
    b = d[off:off + n]
    end = b.find(b"\x00")
    if end >= 0:
        b = b[:end]
    if not b:
        return "<empty/zero at 0x%x>" % va
    if all(0x20 <= c < 0x7F for c in b):
        return repr(b.decode("ascii"))
    return "<%d non-printable bytes> %s" % (len(b), b[:16].hex())


# --------------------------------------------------------- PLT symbol names --
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


RET = 0xD65F03C0


def word(va):
    off = va2off(va)
    if off is None or off + 4 > FL:
        return None
    return struct.unpack_from("<I", d, off)[0]


def find_func_start(site, back=0x10000):
    """Nearest preceding plain `ret`; the function begins on the next word."""
    for va in range(site & ~3, (site & ~3) - back, -4):
        if word(va) == RET:
            return va + 4
    return None


SITES = ([int(a, 16) for a in sys.argv[2:]] if len(sys.argv) > 2
         else [0x7B2EB78, 0x7B34D18, 0x7B35CF4, 0x7B36BA8])
print("sites: %s" % ["0x%x" % s for s in SITES])

for site in SITES:
    start = find_func_start(site)
    say("=" * 78)
    say("HEADER XREF 0x%x" % site)
    say("=" * 78)
    if start is None:
        say("  no preceding ret found")
        say("")
        continue
    say("  function start : 0x%x   (%d bytes before the xref)"
        % (start, site - start))
    insns = list(md.disasm(d[start - DELTA:site - DELTA + 0x140], start))
    say("  instructions   : %d   (0x%x .. 0x%x)"
        % (len(insns), insns[0].address, insns[-1].address))
    say("")

    say("  --- calls ---")
    pending = {}
    for i, ins in enumerate(insns):
        if ins.mnemonic == "adrp":
            try:
                page = int(ins.op_str.split(",")[1].strip().lstrip("#"), 16)
                pending[ins.address] = (page, ins.op_str.split(",")[0].strip())
            except Exception:
                pass
        elif ins.mnemonic == "add" and (ins.address - 4) in pending:
            page, reg = pending.pop(ins.address - 4)
            try:
                imm = int(ins.op_str.split(",")[2].strip().lstrip("#"), 16)
                va = page + imm
                say("  [str] 0x%08x  -> 0x%08x  %s"
                    % (ins.address, va, read_str(va)))
            except Exception:
                pass
        if ins.mnemonic in ("bl", "blr"):
            nm = None
            if ins.mnemonic == "bl":
                try:
                    nm = plt_name(int(ins.op_str.lstrip("#"), 16))
                except Exception:
                    pass
            ctx = "; ".join("%s %s" % (c.mnemonic, c.op_str)
                            for c in insns[max(0, i - 3):i])
            tag = ("   PLT: %s" % nm) if nm else ""
            say("    0x%08x %s %s%s" % (ins.address, ins.mnemonic,
                                        ins.op_str, tag))
            say("          setup: %s" % ctx)
    say("")

    say("  --- window around the xref ---")
    for ins in insns:
        if abs(ins.address - site) <= 0x60:
            mark = "   <== header string" if ins.address == site else ""
            say("    0x%08x  %-7s %s%s" % (ins.address, ins.mnemonic,
                                           ins.op_str, mark))
    say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
