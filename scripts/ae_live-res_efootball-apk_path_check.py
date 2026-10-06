"""path_check.py -- does the watchdog fire path reach Android logcat?

The planned kill-test is
    adb logcat | grep -E "MatchOnlineWatchDog|AbnormalEnd"
which only works if the fire path emits through a LIVE channel.  Two
candidate destinations:

  LIVE   __android_log_print / _write / _vprint  (PLT 0x8b356e0,
         0x8b3af70, 0x8b3ce90)
  DEAD   the variadic emitter 0x39e5ff8 / 0x39e609c, gated on .bss sink
         0x9c14870 whose only writer is SetSink 0x39e5fdc, reachable only
         from an unreferenced thunk

Walks a list of address ranges (the watchdog fire path, the candidate logger
at 0x7dc0390, and the MatchOnlineWatchDog string references) and reports
every branch into either destination.

  path_check.py [lo hi] [lo hi] ...
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


LIVE = {0x08B356E0: "__android_log_print",
        0x08B3AF70: "__android_log_write",
        0x08B3CE90: "__android_log_vprint"}
DEAD = {0x39E5FF8: "emitter 0x39e5ff8", 0x39E609C: "emitter 0x39e609c",
        0x39E5FDC: "SetSink 0x39e5fdc"}

DEFAULT = [(0x6F90700, 0x6F90900),    # watchdog compare / fire
           (0x6F8EE00, 0x6F8EF00),    # fire action
           (0x7DC0390, 0x7DC0600)]    # candidate logger

args = sys.argv[1:]
if args:
    ranges = []
    for i in range(0, len(args), 2):
        ranges.append((int(args[i], 16), int(args[i + 1], 16)))
else:
    ranges = DEFAULT

for lo, hi in ranges:
    print("=" * 78)
    print("range 0x%x .. 0x%x" % (lo, hi))
    print("=" * 78)
    out = {}
    for va in range(lo, hi, 4):
        o = va2off(va)
        if o is None:
            continue
        w = struct.unpack_from("<I", d, o)[0]
        if (w & 0xFC000000) not in (0x14000000, 0x94000000):
            continue
        tgt = va + sx(w & 0x3FFFFFF, 26) * 4
        kind = "BL" if (w & 0xFC000000) == 0x94000000 else "B"
        if tgt in LIVE:
            out.setdefault((kind, tgt, "LIVE  " + LIVE[tgt]), []).append(va)
        elif tgt in DEAD:
            out.setdefault((kind, tgt, "DEAD  " + DEAD[tgt]), []).append(va)
    if not out:
        print("  no branch to a log destination in this range")
    for (kind, tgt, label), sites in sorted(out.items()):
        print("  %-2s -> 0x%x  %s   from %s"
              % (kind, tgt, label, ", ".join("0x%x" % s for s in sites)))
    print()
