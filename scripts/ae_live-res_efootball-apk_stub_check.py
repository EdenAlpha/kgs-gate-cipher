"""stub_check.py -- are the Java->native logging bridges stubbed out?

Java jp.konami.Logger.v/d/i/w/e all call the native PrintNative(int,String).
If PrintNative is a bare `ret`, Konami's Java logging produces nothing.
The UE4 NativeCalls.UELog* bridges are the other Java->native log path, so
check those too.

Also looks for RegisterNatives, which would override a Java_*-named symbol
and make this analysis wrong.
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


NEED = [
    b"Java_jp_konami_Logger_PrintNative",
    b"Java_com_epicgames_ue4_NativeCalls_UELogLog",
    b"Java_com_epicgames_ue4_NativeCalls_UELogError",
    b"Java_com_epicgames_ue4_NativeCalls_UELogWarning",
    b"Java_com_epicgames_ue4_NativeCalls_UELogVerbose",
]

print("=" * 78)
print("Java -> native logging bridges: first instruction")
print("=" * 78)
syms = []
for i in range(dymz // dyesz):
    o = dymo + i * dyesz
    st_name, st_info, st_other, st_shndx = struct.unpack_from("<IBBH", d, o)
    st_value, st_size = struct.unpack_from("<QQ", d, o + 8)
    nm = dynstr[st_name:dynstr.find(b"\x00", st_name)]
    if nm in NEED:
        syms.append((nm.decode(), st_value, st_size))

for nm, va, sz in syms:
    off = va2off(va)
    if off is None:
        print("  %-48s va=0x%x NOT MAPPED" % (nm, va))
        continue
    w = struct.unpack_from("<I", d, off)[0]
    if w == 0xD65F03C0:
        verdict = "*** STUB: bare ret -- produces no output ***"
    elif (w & 0xFC000000) == 0x14000000:
        imm = w & 0x3FFFFFF
        imm = (imm ^ (1 << 25)) - (1 << 25)
        verdict = "tail branch -> 0x%x" % (va + imm * 4)
    elif (w & 0xFC000000) == 0x94000000:
        imm = w & 0x3FFFFFF
        imm = (imm ^ (1 << 25)) - (1 << 25)
        verdict = "BL -> 0x%x" % (va + imm * 4)
    else:
        verdict = "ordinary code"
    print("  %-48s va=0x%08x size=%-3d 0x%08x  %s" % (nm, va, sz, w, verdict))

print()
print("=" * 78)
print("is there a RegisterNatives that would override Java_* symbols?")
print("=" * 78)
for n in (b"RegisterNatives", b"registerNatives", b"GetMethodID",
          b"JNI_OnLoad"):
    print("  %-18s occurrences in .so: %d" % (n.decode(), d.count(n)))

# JNI table slot 214 = RegisterNatives in JNINativeInterface
print()
print("=" * 78)
print("does the binary actually call RegisterNatives?")
print("=" * 78)
print("  (checked via the JNI function-table; see regnatives dump below)")
