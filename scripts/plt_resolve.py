"""Resolve PLT addresses to their real symbol names.

Two claims about how the `sign` key is generated rest on functions we inferred
by argument shape rather than by name:

  * 0x8b352d0 is called as  (7, &ts)  inside 0x2f1ec94, and the result is
    multiplied by 0x3b9aca00 (1e9).  We assumed clock_gettime(CLOCK_BOOTTIME).
    If that is wrong, w24 is not the clock and the key may not be time-based.
  * 0x8b3ac10 is assumed to be ostream::operator<<(unsigned).

Photocopier: read the names out of .rela.plt + .dynsym instead of inferring.

ARM64 PLT layout: PLT[0] is a 32-byte header, then 16 bytes per slot, so
reloc index for address A is  (A - plt_addr)/16 - 1.
"""
import struct
import sys

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\plt_names.txt"

TARGETS = [
    0x8B352D0,   # called as (7, &x)  -> assumed clock_gettime
    0x8B3AC10,   # assumed ostream<<unsigned
    0x8B38590,   # assumed ios_base::init
    0x8B385A0,   # assumed basic_streambuf ctor
    0x8B38820,   # assumed ostream::sentry ctor
    0x8B38600,   # assumed basic_ios::setstate
    0x8B38A10,   # assumed random_device ctor
    0x8B38A20,   # assumed random_device::operator()
    0x8B38A30,   # assumed random_device dtor
    0x8B352C0,   # control: assumed operator delete
]

d = open(SO, "rb").read()
out = []


def say(s=""):
    out.append(str(s))


# ------------------------------------------------------------ sections ------
e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]

sh = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    name_off, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, sh_info, \
        sh_addralign, sh_entsize = struct.unpack_from("<IIQQQQIIQQ", d, o)
    sh.append(dict(name_off=name_off, type=sh_type, addr=sh_addr, off=sh_off,
                   size=sh_size, link=sh_link, entsize=sh_entsize))

strtab_hdr = sh[e_shstrndx]


def sname(s):
    base = strtab_hdr["off"] + s["name_off"]
    end = d.index(b"\x00", base)
    return d[base:end].decode("ascii", "replace")


for s in sh:
    s["name"] = sname(s)

say("sections of interest:")
for s in sh:
    if s["name"] in (".plt", ".rela.plt", ".dynsym", ".dynstr", ".rela.dyn"):
        say("  %-12s type=%-4d addr=0x%09x off=0x%09x size=0x%09x entsize=%d link=%d"
            % (s["name"], s["type"], s["addr"], s["off"], s["size"],
               s["entsize"], s["link"]))
say("")

by_name = {s["name"]: s for s in sh}
plt = by_name.get(".plt")
rela_plt = by_name.get(".rela.plt")
dynsym = by_name.get(".dynsym")
dynstr = by_name.get(".dynstr")

if not all((plt, rela_plt, dynsym, dynstr)):
    say("MISSING a required section -- cannot resolve")
    open(OUT, "w", encoding="utf-8").write("\n".join(out))
    raise SystemExit(1)


def sym_name(idx):
    off = dynsym["off"] + idx * dynsym["entsize"]
    st_name, = struct.unpack_from("<I", d, off)
    base = dynstr["off"] + st_name
    end = d.index(b"\x00", base)
    return d[base:end].decode("ascii", "replace")


# index -> name, via .rela.plt
n_rela = rela_plt["size"] // 24
reloc = {}
for i in range(n_rela):
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", d, rela_plt["off"] + i * 24)
    reloc[i] = (sym_name(r_info >> 32), r_offset)

say(".rela.plt entries: %d" % n_rela)
say("plt section VA    : 0x%x" % plt["addr"])
say("")

say("=" * 78)
say("PLT SYMBOL RESOLUTION")
say("=" * 78)
for va in TARGETS:
    if va < plt["addr"]:
        say("  0x%08x  -- below .plt" % va)
        continue
    slot = (va - plt["addr"]) // 16
    # PLT[0] is a 32-byte header, so the first real slot sits at plt+0x20 and
    # maps to reloc index 0.  Forgetting that shifts every name by one slot
    # (it wrongly named 0x8b352c0 "clock_gettime" when that address frees a
    # string, i.e. operator delete).  Control below must print _ZdlPv.
    idx = (va - plt["addr"] - 0x20) // 16
    if idx < 0 or idx not in reloc:
        say("  0x%08x  -- slot %d, index %d NOT in .rela.plt" % (va, slot, idx))
        continue
    nm, got = reloc[idx]
    say("  0x%08x  ->  %s          (GOT 0x%x)" % (va, nm, got))

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
