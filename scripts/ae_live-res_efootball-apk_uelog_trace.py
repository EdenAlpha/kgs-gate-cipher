"""uelog_trace.py -- where do the live UE4 Java->native log bridges go?

NativeCalls.UELogLog/UELogWarning/UELogError/UELogVerbose are ordinary code
(308 bytes each), so unlike jp.konami.Logger.PrintNative they are not stubbed.
Two possible destinations:

  * __android_log_print / _write / _vprint  (PLT stubs at
    0x8b356e0 / 0x8b3af70 / 0x8b3ce90)  -> reaches Android logcat
  * the variadic emitter 0x39e5ff8 / 0x39e609c, which is gated on the .bss
    sink 0x9c14870 -> would produce nothing

Scans each bridge body for those branches and reports the strings it passes.
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

e_shoff = struct.unpack_from("<Q", d, 40)[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 58)
sho = e_shoff + e_shstrndx * e_shentsize
str_off = struct.unpack_from("<Q", d, sho + 24)[0]
str_size = struct.unpack_from("<Q", d, sho + 32)[0]
shstr = d[str_off:str_off + str_size]

secs = {}
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    nmoff = struct.unpack_from("<I", d, o)[0]
    t = struct.unpack_from("<I", d, o + 4)[0]
    off = struct.unpack_from("<Q", d, o + 24)[0]
    size = struct.unpack_from("<Q", d, o + 32)[0]
    entsz = struct.unpack_from("<Q", d, o + 56)[0]
    nm = shstr[nmoff:shstr.find(b"\x00", nmoff)].decode("ascii", "replace")
    secs[nm] = (t, off, size, entsz)

_, dso, dss, _ = secs[".dynstr"]
dynstr = d[dso:dso + dss]
_, dymo, dymz, dyesz = secs[".dynsym"]

e_phoff = struct.unpack_from("<Q", d, 32)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)
ph = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, fl = struct.unpack_from("<II", d, o)
    po, pv = struct.unpack_from("<QQ", d, o + 8)
    pf, pm = struct.unpack_from("<QQ", d, o + 32)
    ph.append((t, fl, po, pv, pf, pm))


def va2off(va):
    for t, fl, po, pv, pf, pm in ph:
        if t == 1 and pv <= va < pv + pf:
            return po + (va - pv)
    return None


def sx(x, bits):
    s = 1 << (bits - 1)
    m = (1 << bits) - 1
    v = x & m
    return (v ^ s) - s


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


LOGCAT = {0x08B356E0: "__android_log_print",
          0x08B3AF70: "__android_log_write",
          0x08B3CE90: "__android_log_vprint"}
EMITTER = {0x39E5FF8: "emitter@0x39e5ff8", 0x39E609C: "emitter@0x39e609c",
           0x39E5FDC: "SetSink@0x39e5fdc"}

want = [b"Java_com_epicgames_ue4_NativeCalls_UELogLog",
        b"Java_com_epicgames_ue4_NativeCalls_UELogWarning",
        b"Java_com_epicgames_ue4_NativeCalls_UELogError",
        b"Java_com_epicgames_ue4_NativeCalls_UELogVerbose",
        b"Java_jp_konami_Logger_PrintNative"]

print("=" * 78)
print("where each bridge branches")
print("=" * 78)
for i in range(dymz // dyesz):
    o = dymo + i * dyesz
    st_name, _, _, _ = struct.unpack_from("<IBBH", d, o)
    st_value, st_size = struct.unpack_from("<QQ", d, o + 8)
    nm = dynstr[st_name:dynstr.find(b"\x00", st_name)]
    if nm not in want:
        continue
    print()
    print("  %s   va=0x%x size=%d" % (nm.decode(), st_value, st_size))
    hits = {}
    for k in range(st_size // 4):
        a = st_value + k * 4
        off = va2off(a)
        if off is None:
            continue
        w = struct.unpack_from("<I", d, off)[0]
        if (w & 0xFC000000) in (0x14000000, 0x94000000):
            tgt = a + sx(w & 0x3FFFFFF, 26) * 4
            kind = "BL" if (w & 0xFC000000) == 0x94000000 else "B"
            label = LOGCAT.get(tgt) or EMITTER.get(tgt)
            if label:
                hits.setdefault((kind, tgt, label), []).append(a)
    if not hits:
        print("      no direct branch to logcat PLT or the gated emitter")
    for (kind, tgt, label), sites in sorted(hits.items()):
        print("      %-2s -> 0x%x %-24s at %s"
              % (kind, tgt, label, ", ".join("0x%x" % s for s in sites)))

    # strings materialised inside the body
    print("      literals:")
    for k in range(st_size // 4):
        a = st_value + k * 4
        off = va2off(a)
        if off is None:
            continue
        w = struct.unpack_from("<I", d, off)[0]
        if ((w >> 24) & 0x9F) != 0x90:
            continue
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        page = (a & ~0xFFF) + (sx((immhi << 2) | immlo, 21) << 12)
        rd = w & 0x1F
        # look ahead for ADD rd, rd, #imm
        for j in range(1, 8):
            b = a + j * 4
            o2 = va2off(b)
            if o2 is None:
                break
            w2 = struct.unpack_from("<I", d, o2)[0]
            if (w2 & 0xFF800000) == 0x91000000 and ((w2 >> 5) & 0x1F) == rd \
                    and (w2 & 0x1F) == rd:
                imm12 = (w2 >> 10) & 0xFFF
                if (w2 >> 22) & 1:
                    imm12 <<= 12
                s = read_cstr(page + imm12)
                if s:
                    print("         %s" % s[:140])
                break
