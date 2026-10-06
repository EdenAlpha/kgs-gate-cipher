"""Find the code that consumes the Blowfish init tables, and inspect the
relocation region.

Two independent questions, both answerable from the file alone.

1. The Blowfish P-array + S-boxes sit in .rodata at VA 0xc8d92c
   (.rodata addr 0x725800 == file offset 0x725800, so delta is 0 in this
   range).  Whatever schedules the key must materialise that address with
   adrp+add, exactly the way the .bss globals are reached.  Finding it gives
   the real encrypt routine instead of another guessed layout.

2. The relocation table is at file 0x2ed270 (DT tag 0x60000011 there is
   DT_RELA, 0x60000012 is DT_RELASZ -- both OS-range tags whose values match
   .rela.dyn addr/size exactly).  DT_RELAENT says 24 but the size 0x3de65a is
   not a multiple of 24, and the section header says sh_entsize=1.  Those three
   facts disagree; this prints the raw first entries so the disagreement can be
   settled rather than reasoned around.
"""
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\game\libUE4.so"
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\find_bf.txt"

d = open(SO, "rb").read()
FL = len(d)

out = []


def say(s=""):
    out.append(str(s))


# ---------------------------------------------------- sections / delta -----
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
    SEC.append({"i": i, "name": nm, "type": s[1], "flags": s[2],
                "addr": s[3], "off": s[4], "size": s[5], "entsize": s[9]})

TEXT = [s for s in SEC if s["name"] == ".text"][0]
EXEC = [s for s in SEC if s["name"] in (".text", ".plt")]


def delta(va):
    for s in reversed(SEC):
        if s["addr"] and s["off"] and va >= s["addr"]:
            return s["off"] - s["addr"]
    return 0


def off(va):
    return va - delta(va)


# ---------------------------------------------------- relocation region ----
say("=" * 78)
say("RELOCATION REGION AT FILE 0x2ed270  (DT_RELA / DT_RELASZ = 0x3de65a)")
say("=" * 78)
base = 0x2ED270
for k in range(6):
    o = base + k * 24
    r_off, r_info, r_add = struct.unpack_from("<QQq", d, o)
    say("  [%d] r_offset=0x%012x  r_info=0x%016x (type=%u, sym=%u)  "
        "r_addend=0x%012x"
        % (k, r_off, r_info, r_info & 0xFFFFFFFF, r_info >> 32, r_add))
say("")
say("  is r_offset a plausible VA for .data.rel.ro 0x8b75140..0x98bd888?")
for k in range(6):
    r_off = struct.unpack_from("<Q", d, base + k * 24)[0]
    ok = 0x8B75140 <= r_off < 0x98BD888
    say("    [%d] 0x%012x  %s" % (k, r_off, "YES" if ok else "no"))
say("")
say("  scan whole region for entries whose r_offset lands in .data.rel.ro")
hits, others = 0, 0
sample = []
i = 0
while (base + i * 24) + 24 <= base + 0x3DE65A:
    o = base + i * 24
    r_off, r_info, r_add = struct.unpack_from("<QQq", d, o)
    if 0x8B75140 <= r_off < 0x98BD888:
        hits += 1
        if len(sample) < 5:
            sample.append((r_off, r_info, r_add))
    else:
        others += 1
    i += 1
say("    plausible: %d   implausible: %d   (entries tried: %d)"
    % (hits, others, i))
for r_off, r_info, r_add in sample:
    say("      off=0x%x info=0x%x type=%u addend=0x%x"
        % (r_off, r_info, r_info & 0xFFFFFFFF, r_add))
say("")

# ---------------------------------------------------- find table users -----
BLOWFISH_BASE = 0xC8D92C
BLOWFISH_END = BLOWFISH_BASE + 0x1048        # P[18] + 4*256 words
PAGE = BLOWFISH_BASE & ~0xFFF               # 0xc8d000

say("=" * 78)
say("CODE MATERIALISING THE BLOWFISH TABLE VA 0x%x..0x%x (page 0x%x)"
    % (BLOWFISH_BASE, BLOWFISH_END, PAGE))
say("=" * 78)

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# Disassembling 103 MB in one CsError-safe call is not possible -- capstone
# raises CS_ERR_MEM.  Chunk it, with a 4 KiB overlap so an adrp/add pair that
# straddles a boundary is still caught (the lookahead is only 48 instructions
# = 192 bytes).  ARM64 is fixed-width, so starting each chunk at a 4-byte
# boundary keeps it in sync with the instruction stream.
CHUNK = 0x200000
OVER = 0x1000
tva, tsz, toff = TEXT["addr"], TEXT["size"], off(TEXT["addr"])
say(".text VA 0x%x size %d" % (tva, tsz))

sites = []
pos = 0
while pos < tsz:
    n = min(CHUNK + OVER, tsz - pos)
    chunk = d[toff + pos:toff + pos + n]
    ins_iter = list(md.disasm(chunk, tva + pos))
    if ins_iter:
        last = ins_iter[-1].address
        pos = max(1, last + 4 - tva)
    else:
        pos += n
    for k, ins in enumerate(ins_iter):
        if ins.mnemonic != "adrp":
            continue
        try:
            page = int(ins.op_str.split(",")[1].strip().lstrip("#"), 16)
        except Exception:
            continue
        if page != PAGE:
            continue
        rd = ins.op_str.split(",")[0].strip()
        for j in range(k + 1, min(k + 48, len(ins_iter))):
            nxt = ins_iter[j]
            # any control transfer (or a call, which clobbers every
            # caller-saved register the adrp result could be sitting in)
            # invalidates the page
            if nxt.mnemonic in ("adrp", "ret", "b", "blr", "br", "cbz",
                                "cbnz", "tbz", "tbnz", "bl") or \
                    nxt.mnemonic.startswith("b."):
                break
            if nxt.mnemonic == "add" and nxt.op_str.startswith(rd + ","):
                try:
                    imm = int(nxt.op_str.split(",")[2].strip().lstrip("#"), 16)
                except Exception:
                    continue
                full = page + imm
                if BLOWFISH_BASE <= full < BLOWFISH_END:
                    sites.append((ins.address, nxt.address, full))
                    break
say("adrp+add sites reaching the tables: %d" % len(sites))
say("")

for va, addva, full in sites:
    say("-" * 78)
    say("  adrp 0x%x -> add 0x%x  => VA 0x%x  (table +0x%x)"
        % (va, addva, full, full - BLOWFISH_BASE))
    # small window around the hit, re-disassembled on its own
    w0 = max(tva, va - 0x100)
    w1 = min(tva + tsz, addva + 0x100)
    w = list(md.disasm(d[toff + (w0 - tva):toff + (w1 - tva)], w0))
    pend = {}
    for i2 in w:
        mark = ""
        if i2.mnemonic == "adrp":
            try:
                pend[i2.address] = int(i2.op_str.split(",")[1].strip()
                                       .lstrip("#"), 16)
            except Exception:
                pass
        elif i2.mnemonic == "add" and (i2.address - 4) in pend:
            p = pend.pop(i2.address - 4)
            try:
                im = int(i2.op_str.split(",")[2].strip().lstrip("#"), 16)
                mark = "   -> 0x%x" % (p + im)
            except Exception:
                pass
        if i2.address == va:
            mark += "   <<<< adrp HERE"
        if i2.address == addva:
            mark += "   <<<< add HERE"
        say("      0x%08x  %-8s %-44s%s"
            % (i2.address, i2.mnemonic, i2.op_str, mark))
        if i2.mnemonic in ("bl", "b"):
            try:
                t = int(i2.op_str.lstrip("#"), 16)
                say("               -> 0x%x" % t)
            except Exception:
                pass
    say("")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("\n".join(out))
print("wrote %s" % OUT)
