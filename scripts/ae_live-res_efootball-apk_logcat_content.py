"""logcat_content.py -- what does eFootball actually write to Android logcat?

libUE4.so imports __android_log_print / _write / _vprint from liblog.so.
Their PLT stubs are the only places those imports are referenced, and anyref
found 187 / 1 / 1 PC-relative callers respectively.

For every caller, walk backwards over the instruction window and harvest the
ADRP+ADD pairs that materialise a string address, then read the bytes.  That
yields the literal tag and format text the game hands to logcat.

A caller that passes no literal (register-held format) is reported as such
rather than guessed.
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

e_phoff = struct.unpack_from("<Q", d, 32)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)
ph = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, fl = struct.unpack_from("<II", d, o)
    po, pv, _, pf, _, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
    if t == 1:
        ph.append((po, pv, pf, fl))

RX = [(po, pv, pf) for po, pv, pf, fl in ph if fl & 1]
R_OFF, R_VA, R_SZ = RX[0]


def va2off(va):
    for po, pv, pf, _ in ph:
        if pv <= va < pv + pf:
            return po + (va - pv)
    return None


def read_cstr(va, limit=200):
    o = va2off(va)
    if o is None or o >= len(d):
        return None
    end = d.find(b"\x00", o, o + limit)
    if end < 0:
        return None
    b = d[o:end]
    if not b or len(b) < 3:
        return None
    if any(c < 0x20 or c > 0x7E for c in b):
        return None
    return b.decode("ascii")


def sx(x, bits):
    s = 1 << (bits - 1)
    m = (1 << bits) - 1
    v = x & m
    return (v ^ s) - s


def decode_at(off):
    """-> (pc, kind, imm) for a branch, else (pc, None, None)"""
    w = struct.unpack_from("<I", d, off)[0]
    if (w & 0xFC000000) == 0x14000000:
        return w, "B", sx(w & 0x3FFFFFF, 26) * 4
    if (w & 0xFC000000) == 0x94000000:
        return w, "BL", sx(w & 0x3FFFFFF, 26) * 4
    if (w & 0xFF000010) == 0x54000000:
        return w, "Bcond", sx((w >> 5) & 0x7FFFF, 19) * 4
    if (w & 0xFF000000) in (0x34000000, 0x35000000):
        return w, "CBZ", sx((w >> 5) & 0x7FFFF, 19) * 4
    if (w & 0xFF000000) in (0xB4000000, 0xB5000000):
        return w, "CBZ64", sx((w >> 5) & 0x7FFFF, 19) * 4
    if (w & 0xFF000000) in (0x36000000, 0x37000000, 0xB6000000, 0xB7000000):
        return w, "TBZ", sx((w >> 5) & 0x3FFFFFF, 19) * 4
    return w, None, None


# ---- find every caller of the three PLT stubs -------------------------------
STUBS = {
    0x08B356E0: "__android_log_print",
    0x08B3AF70: "__android_log_write",
    0x08B3CE90: "__android_log_vprint",
}

code = d[R_OFF:R_OFF + R_SZ]
callers = {name: [] for name in STUBS.values()}
for off in range(0, R_SZ, 4):
    w, kind, imm = decode_at(R_OFF + off)
    if kind not in ("B", "BL"):
        continue
    pc = R_VA + off
    tgt = pc + imm
    if tgt in STUBS:
        callers[STUBS[tgt]].append(pc)

for name, cs in callers.items():
    print("%-24s callers: %d" % (name, len(cs)))

# ---- harvest literals above each call ---------------------------------------
WINDOW = 40  # instructions back from the call


def harvest(call_pc, back=40):
    out = []
    adrpg = None
    start = call_pc - back * 4
    for pc in range(start, call_pc + 4, 4):
        off = va2off(pc)
        if off is None:
            continue
        w = struct.unpack_from("<I", d, off)[0]
        # ADRP
        if (w >> 24) & 0x9F == 0x90:
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = sx((immhi << 2) | immlo, 21)
            page = (pc & ~0xFFF) + (imm << 12)
            rd = w & 0x1F
            adrpg = (rd, page)
            continue
        # ADR
        if (w >> 24) & 0x9F == 0x10:
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = sx((immhi << 2) | immlo, 21)
            rd = w & 0x1F
            s = read_cstr(pc + imm)
            if s:
                out.append(s)
            continue
        # ADD (immediate, 64-bit)  sf=1 op=0 S=0 imm12
        if (w & 0xFF800000) == 0x91000000 and adrpg is not None:
            rd = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm = (w >> 10) & 0xFFF
            sh = (w >> 22) & 1
            if rn == adrpg[0]:
                addr = adrpg[1] + (imm << (12 if sh else 0))
                s = read_cstr(addr)
                if s:
                    out.append(s)
                adrpg = None
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


print()
print("=" * 78)
print("literals handed to __android_log_print  (tag + format)")
print("=" * 78)
all_lit = []
for pc in callers["__android_log_print"]:
    lits = harvest(pc)
    if lits:
        all_lit.append((pc, lits))

print("  callers with at least one readable literal: %d / %d"
      % (len(all_lit), len(callers["__android_log_print"])))
print()
for pc, lits in all_lit[:60]:
    print("  0x%08x  %s" % (pc, " | ".join(x[:70] for x in lits)))

print()
print("=" * 78)
print("score / match / result / goal / disconnect keywords in those literals")
print("=" * 78)
import re
kw = re.compile(r"score|match|result|goal|halftime|fulltime|disconnect|"
                r"watchdog|abnormal|timeout|reason", re.I)
found = []
for pc, lits in all_lit:
    for s in lits:
        if kw.search(s):
            found.append((pc, s))
print("  hits: %d" % len(found))
for pc, s in found[:60]:
    print("    0x%08x  %s" % (pc, s[:150]))

print()
print("=" * 78)
print("other two imports")
print("=" * 78)
for name in ("__android_log_write", "__android_log_vprint"):
    for pc in callers[name]:
        print("  %s @0x%08x -> %s" % (name, pc, harvest(pc)))
