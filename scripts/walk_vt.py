"""Disassemble the resolved cipher vtable methods, constants included.

The vtables were zeros until unpack_aps2.py decoded the Android packed
relocation stream.  The four routines that matter are now known:

    vtable[7] 0x7b2c7ec   init / key schedule (called with block size 8)
    vtable[5] 0x7b2ce94   transform
    vtable[6] 0x7b2cf9c   decrypt path
    vtable[2] 0x7b2d144   set_iv (already identified)

This walks each one to its `ret`, resolves adrp+add into concrete addresses so
table references name themselves, and records every `bl` one level down -- the
cipher algorithm is one of those callees, and the printed constants say which.

`func_start()` is deliberately not used: it returns ret+4, which is the
*previous* function's guard clause, so the prologue printed here is taken from
the raw window instead.
"""
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\walk_vt.txt"

d = open(SO, "rb").read()

e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def sec(i):
    return struct.unpack_from("<IIQQQQIIQQ", d, e_shoff + i * e_shentsize)


shstr = sec(e_shstrndx)
SEC = []
for i in range(e_shnum):
    s = sec(i)
    nm = d[shstr[4] + s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    SEC.append({"name": nm, "type": s[1], "flags": s[2], "addr": s[3],
                "off": s[4], "size": s[5]})

TEXT = [s for s in SEC if s["name"] == ".text"][0]
TVA, TSZ = TEXT["addr"], TEXT["size"]
TOFF = TEXT["off"]


def off(va):
    """VA -> file offset using the per-PT_LOAD delta, never a fixed range."""
    for s in SEC:
        if s["addr"] and s["off"] and s["addr"] <= va < s["addr"] + s["size"]:
            return s["off"] + (va - s["addr"])
    return None


md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

TARGETS = [
    (0x7B2C7EC, "vtable[7]  init / key schedule (block size arg)"),
    (0x7B2CE94, "vtable[5]  transform"),
    (0x7B2CF9C, "vtable[6]  decrypt path"),
    (0x7B2D104, "vtable[1]"),
    (0x7B2C88C, "vtable[8]"),
    (0x7B2D354, "vtable[9]"),
    (0x7B2D398, "vtable[10]"),
    (0x7B2D3DC, "vtable[3]"),
    (0x7B2D3E4, "vtable[4]"),
]

out = []


def say(s=""):
    out.append(str(s))


def disasm_window(va, before, after):
    """Return instructions in [va-before, va+after), resynced at a 4-byte
    boundary -- ARM64 is fixed width so this stays on the instruction stream
    as long as the window begins inside code."""
    lo = max(TVA, va - before)
    hi = min(TVA + TSZ, va + after)
    start = lo - (lo - va) % 4
    o = TOFF + (start - TVA)
    return list(md.disasm(d[o:o + (hi - start)], start))


def show(va, before, after, indent="      "):
    """Print a window, folding adrp+add into '-> 0x<resolved>' annotations."""
    pend = {}
    lines = []
    for ins in disasm_window(va, before, after):
        mark = ""
        if ins.mnemonic == "adrp":
            try:
                pend[ins.address] = int(
                    ins.op_str.split(",")[1].strip().lstrip("#"), 16)
            except Exception:
                pass
        elif ins.mnemonic == "add" and (ins.address - 4) in pend:
            p = pend.pop(ins.address - 4)
            try:
                im = int(ins.op_str.split(",")[2].strip().lstrip("#"), 16)
                mark = "   -> 0x%x" % (p + im)
            except Exception:
                pass
        if ins.mnemonic in ("bl", "b"):
            try:
                t = int(ins.op_str.lstrip("#"), 16)
                mark = "   -> 0x%x" % t
            except Exception:
                pass
        lines.append("%s0x%08x  %-8s %-42s%s"
                     % (indent, ins.address, ins.mnemonic, ins.op_str, mark))
    return lines


for va, label in TARGETS:
    say("=" * 78)
    say("%s   @ 0x%x" % (label, va))
    say("=" * 78)
    # print from a few instructions of preamble through the first ret
    body = disasm_window(va, 0x20, 0x300)
    pend = {}
    started = False
    for ins in body:
        mark = ""
        if ins.mnemonic == "adrp":
            try:
                pend[ins.address] = int(
                    ins.op_str.split(",")[1].strip().lstrip("#"), 16)
            except Exception:
                pass
        elif ins.mnemonic == "add" and (ins.address - 4) in pend:
            p = pend.pop(ins.address - 4)
            try:
                im = int(ins.op_str.split(",")[2].strip().lstrip("#"), 16)
                mark = "   -> 0x%x" % (p + im)
            except Exception:
                pass
        if ins.mnemonic in ("bl", "b"):
            try:
                t = int(ins.op_str.lstrip("#"), 16)
                mark = "   -> 0x%x" % t
            except Exception:
                pass
        if ins.address == va:
            mark += "   <<<< ENTRY"
            started = True
        if not started:
            continue
        say("      0x%08x  %-8s %-42s%s"
            % (ins.address, ins.mnemonic, ins.op_str, mark))
        if ins.mnemonic == "ret":
            say("      <<<<")
            break
    say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
