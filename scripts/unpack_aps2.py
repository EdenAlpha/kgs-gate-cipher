"""Decode the Android packed relocation stream and read the cipher vtables.

Why this file exists
--------------------
Everything before it read the vtables as zeros and concluded they were
unavailable.  They were never unavailable: `.rela.dyn` begins with the literal
bytes 'APS2', i.e. it is an *Android packed* relocation section
(SHT_ANDROID_RELA = 0x60000002, DT_ANDROID_RELA = 0x60000011), a delta+SLEB128
stream, not an array of 24-byte Elf64_Rela records.  Parsing it as 24-byte
records produced 169,027 entries with implausible r_offsets -- which was the
signal that the format, not the data, was wrong.

Layout (LLVM lld / bionic `linker_relocs.cpp`, confirmed by
llvm/test/tools/llvm-readobj/Inputs/elf-packed-relocs1.s):

    'APS2'
    sleb128 relocation_count
    sleb128 relocation_offset          # r_offset of the first relocation
    repeat:
      sleb128 group_size
      sleb128 group_flags
        1 RELOCATION_GROUPED_BY_INFO          -> sleb128 group_info
        2 RELOCATION_GROUPED_BY_OFFSET_DELTA  -> sleb128 group_offset_delta
        4 RELOCATION_GROUPED_BY_ADDEND        -> sleb128 group_addend
        8 RELOCATION_GROUP_HAS_ADDEND         -> addends are present
      for each of group_size:
        sleb128 r_offset_delta   (skipped when flag 2; uses group_offset_delta)
        sleb128 r_info           (skipped when flag 1; uses group_info)
        sleb128 r_addend_delta   (only when flag 8 and not flag 4)

Because the order of the three *group* fields is not fixed by the format text,
this tries every permutation and keeps the first that consumes the stream
exactly, yields the header's relocation count, and lands every r_offset inside a
loaded segment.  That is a real check, not a hopeful one.
"""
import itertools
import struct

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\aps2.txt"

d = open(SO, "rb").read()
FL = len(d)

out = []


def say(s=""):
    out.append(str(s))


# --------------------------------------------------------------- sleb128 ----
def sleb128(buf, pos):
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
        if pos >= len(buf):
            raise EOFError
    if shift < 64 and (b & 0x40):
        result -= 1 << shift
    return result, pos


# ------------------------------------------------------- program headers ----
e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
e_phentsize = struct.unpack_from("<H", d, 0x36)[0]
e_phnum = struct.unpack_from("<H", d, 0x38)[0]
phdrs = []
for i in range(e_phnum):
    p = struct.unpack_from("<IIQQQQQQ", d, e_phoff + i * e_phentsize)
    phdrs.append({"type": p[0], "off": p[2], "va": p[3], "filesz": p[5],
                  "memsz": p[6]})

SEG_LO = min(p["va"] for p in phdrs if p["type"] == 1)
SEG_HI = max(p["va"] + p["memsz"] for p in phdrs if p["type"] == 1)
say("loaded VA range: 0x%x .. 0x%x" % (SEG_LO, SEG_HI))

# writable target ranges (where a RELATIVE reloc may point)
WRITE_LO, WRITE_HI = SEG_LO, SEG_HI


def va2off(va):
    for p in phdrs:
        if p["type"] == 1 and p["va"] <= va < p["va"] + p["filesz"]:
            return p["off"] + (va - p["va"])
    return None


# --------------------------------------------------------- the stream -------
RELA_OFF, RELA_SZ = 0x2ED270, 0x3DE65A
buf = d[RELA_OFF:RELA_OFF + RELA_SZ]

say("stream at file 0x%x, %d bytes, magic=%r" % (RELA_OFF, len(buf),
                                                 buf[:4]))
assert buf[:4] == b"APS2", "not an Android packed relocation stream"

count0, pos = sleb128(buf, 4)
off0, pos = sleb128(buf, pos)
say("header: relocation_count=%d  initial r_offset=0x%x  (stream pos %d)"
    % (count0, off0, pos))

FLAG_INFO, FLAG_OFFDELTA, FLAG_ADDEND_GROUPED, FLAG_HAS_ADDEND = 1, 2, 4, 8
GROUP_FIELDS = (FLAG_INFO, FLAG_OFFDELTA, FLAG_ADDEND_GROUPED)


def decode(order):
    """order = which group field is read first (permutation of 1,2,4)."""
    p = pos
    n = 0
    r_offset = off0
    r_addend = 0
    rel = {}
    try:
        while p < len(buf):
            gsize, p = sleb128(buf, p)
            if gsize <= 0:
                return None, "non-positive group size %d at %d" % (gsize, p)
            gflags, p = sleb128(buf, p)
            if gflags & ~0xF:
                return None, "unknown flags 0x%x at %d" % (gflags, p)
            gval = {}
            for bit in order:
                if gflags & bit:
                    gval[bit], p = sleb128(buf, p)
            for _ in range(gsize):
                if gflags & FLAG_OFFDELTA:
                    delta = gval[FLAG_OFFDELTA]
                else:
                    delta, p = sleb128(buf, p)
                r_offset += delta
                if gflags & FLAG_INFO:
                    r_info = gval[FLAG_INFO]
                else:
                    r_info, p = sleb128(buf, p)
                if gflags & FLAG_HAS_ADDEND:
                    if gflags & FLAG_ADDEND_GROUPED:
                        ad = gval[FLAG_ADDEND_GROUPED]
                    else:
                        ad, p = sleb128(buf, p)
                    r_addend += ad
                rel[r_offset & 0xFFFFFFFFFFFFFFFF] = (
                    r_info & 0xFFFFFFFFFFFFFFFF,
                    r_addend & 0xFFFFFFFFFFFFFFFF,
                    r_info & 0xFFFFFFFF,
                )
                n += 1
    except (EOFError, IndexError):
        return None, "ran off the end"
    return (n, p, rel), None


say("")
say("=" * 78)
say("GROUP-FIELD ORDER SEARCH")
say("=" * 78)

best = None
for order in itertools.permutations(GROUP_FIELDS):
    res, err = decode(order)
    if res is None:
        say("  %-24s FAIL: %s" % (str(order), err))
        continue
    n, p, rel = res
    names = {1: "INFO", 2: "OFFDELTA", 4: "ADDEND"}
    label = "+".join(names[b] for b in order)
    bad = sum(1 for k in rel if not (SEG_LO <= k < SEG_HI))
    types = {}
    for k, (inf, add, t) in rel.items():
        types[t] = types.get(t, 0) + 1
    say("  %-24s count=%d (want %d)  consumed=%d/%d  out-of-range=%d  types=%s"
        % (label, n, count0, p, len(buf), bad,
           {hex(t): c for t, c in
            sorted(types.items(), key=lambda kv: -kv[1])[:5]}))
    if n == count0 and p == len(buf) and bad == 0:
        best = (order, n, p, rel)
        say("        ^^^ VALID")

say("")
if best is None:
    say("NO ORDER VALIDATED -- not guessing further; dumping header only.")
    open(OUT, "w", encoding="utf-8").write("\n".join(out))
    print("\n".join(out))
    raise SystemExit(1)

order, n, p, rel = best
say("using order %s : %d relocations, stream fully consumed" % (order, n))
say("")

# ----------------------------------------------------- the vtables ---------
VT = {
    "cipher state (0x7b2d094 final)": 0x981A620,
    "cipher state (alt)": 0x981A5B0,
    "context A (56-byte key)": 0x981A590,
    "context B (32-byte key)": 0x981A4A0,
}

say("=" * 78)
say("RESOLVED VTABLES")
say("=" * 78)
RN = {1027: "RELATIVE", 257: "ABS64", 1025: "GLOB_DAT", 1026: "JUMP_SLOT"}
for tag, va in VT.items():
    say("%s  @ 0x%x" % (tag, va))
    for i in range(12):
        k = va + 8 * i
        if k not in rel:
            say("   [%2d] 0x%08x  (no relocation)" % (i, k))
            continue
        info, add, t = rel[k]
        say("   [%2d] 0x%08x -> 0x%016x  type=%s"
            % (i, k, add, RN.get(t, hex(t))))
    say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
