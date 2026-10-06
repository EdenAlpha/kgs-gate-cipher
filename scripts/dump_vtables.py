"""Dump the cipher vtables so the algorithm stops being an inference.

Established (walk_cipher.txt):
    0x7b2d094(state, key, len)   memcpy key into state+0x10, len -> +0x48,
                                 iv -> +0x4c, flag -> +0x54,
                                 vtable = 0x981a620
    0x7b2d144(state, iv, 8)      stores the 8-byte prefix
    0x7b2cbb0(ctx, data, len, out)
        key = ctx+0x08 (the string we recovered)
        state = 0x7b2d094(stack, key, keylen)
        vtable[7](state, plaintext, 8)      <- w2 = #8 is the BLOCK SIZE
        vtable[5](state, ptr, len, out, &n) <- the transform
        out = state+0x4c (8 bytes) || out

So the real cipher lives behind 0x981a620.  Reading the table is cheaper and
more reliable than continuing to guess from call shapes -- and the guess so
far (56-byte max key + 8-byte blocks + 4184-byte working set = Blowfish) is
exactly the sort of thing that must be checked rather than assumed.
"""
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\vtables.txt"

VT = {
    "cipher state (0x7b2d094 sets this)": 0x981A620,
    "cipher state (set before the memcpy)": 0x981A5B0,
    "context A (key at +0x08, 56B key)": 0x981A590,
    "context B (key at +0x08, 32B key)": 0x981A4A0,
}

d = open(SO, "rb").read()
FL = len(d)


def _delta(va):
    if va >= 0x9906CC0:
        return 0xC000
    if va >= 0x8B75140:
        return 0x8000
    if va >= 0x28293C0:
        return 0x4000
    return 0x0


# --------------------------------------------------- apply dynamic relocs ----
# The vtables live in .data but read as all-zero: every entry is written by
# R_AARCH64_RELATIVE at load time.  Reading the file as-is would report a
# vtable full of nulls and quietly prove nothing.
_e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
_e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
_e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
_e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def _sec(i):
    return struct.unpack_from("<IIQQQQIIQQ", d, _e_shoff + i * _e_shentsize)


_shstr = _sec(_e_shstrndx)
_SH = {}
for _i in range(_e_shnum):
    _s = _sec(_i)
    _nm = d[_shstr[4] + _s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    _SH[_nm] = {"name": _nm, "addr": _s[3], "off": _s[4], "size": _s[5],
                "type": _s[1], "entsize": _s[9]}

R_AARCH64_RELATIVE = 1027
rel = {}
_rd = _SH.get(".rela.dyn")
if _rd:
    for _i in range(_rd["size"] // 24):
        _o, _info, _add = struct.unpack_from("<QQq", d, _rd["off"] + _i * 24)
        if (_info & 0xFFFFFFFF) == R_AARCH64_RELATIVE:
            rel[_o] = _add & 0xFFFFFFFFFFFFFFFF
print("RELATIVE relocations: %d" % len(rel))


def u64(va):
    if va in rel:
        return rel[va]
    o = va - _delta(va)
    if 0 <= o + 8 <= FL:
        return struct.unpack_from("<Q", d, o)[0]
    return None


def word(va):
    o = va - _delta(va)
    if 0 <= o + 4 <= FL:
        return struct.unpack_from("<I", d, o)[0]
    return None


# ------------------------------------------------------------- PLT names ----
e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]


def sec(i):
    return struct.unpack_from("<IIQQQQIIQQ", d, e_shoff + i * e_shentsize)


shstr = sec(e_shstrndx)
SECS = []
for i in range(e_shnum):
    s = sec(i)
    nm = d[shstr[4] + s[0]:].split(b"\x00")[0].decode("ascii", "replace")
    SECS.append({"name": nm, "addr": s[3], "off": s[4], "size": s[5],
                 "entsize": s[9]})
by = {s["name"]: s for s in SECS}
plt, rela = by[".plt"], by[".rela.plt"]
dynsym, dynstr = by[".dynsym"], by[".dynstr"]


def sym_name(i):
    off = dynsym["off"] + i * dynsym["entsize"]
    st_name = struct.unpack_from("<I", d, off)[0]
    b = dynstr["off"] + st_name
    return d[b:d.index(b"\x00", b)].decode("ascii", "replace")


reloc = {}
for i in range(rela["size"] // 24):
    _o, r_info, _ = struct.unpack_from("<QQq", d, rela["off"] + i * 24)
    reloc[i] = sym_name(r_info >> 32)


def plt_name(va):
    if va < plt["addr"] or va > plt["addr"] + plt["size"]:
        return None
    return reloc.get((va - plt["addr"] - 0x20) // 16)


md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = []


def say(s=""):
    out.append(str(s))


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
        if not p or p == 0xFFFFFFFF:
            continue
        if p < 0x28293C0:
            say("  --- slot %d : 0x%x is not in .text ---" % (i, p))
            continue
        say("  --- slot %d  vtable[+0x%02x] = 0x%x ---" % (i, 8 * i, p))
        body = d[_delta(p):_delta(p) + 0x80]
        ins = list(md.disasm(body, p))
        pend = {}
        for k, ins_ in enumerate(ins[:30]):
            mark = ""
            if ins_.mnemonic == "ret":
                mark = "    <<<<"
            say("      0x%08x  %-8s %-44s%s"
                % (ins_.address, ins_.mnemonic, ins_.op_str, mark))
            if ins_.mnemonic in ("bl", "b"):
                try:
                    tgt = int(ins_.op_str.lstrip("#"), 16)
                    nm = plt_name(tgt)
                    if nm:
                        say("             PLT: %s" % nm)
                except Exception:
                    pass
            if mark:
                break
        say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
