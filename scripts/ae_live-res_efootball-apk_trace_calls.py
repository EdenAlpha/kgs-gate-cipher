"""trace_calls.py -- does the watchdog's message ever reach Android logcat?

Follows direct BL/B edges from a start address for a bounded number of hops
and reports the first path into either destination class:

  LIVE  __android_log_print / _write / _vprint   (PLT 0x8b356e0/0x8b3af70/0x8b3ce90)
  DEAD  the variadic emitter 0x39e5ff8 / 0x39e609c (gated on .bss sink 0x9c14870)

Per node it walks forward to the first `ret` (or a fixed instruction cap) and
collects the calls it finds.  That over-approximates, so any reported path is
re-dumped for confirmation; no reported path is taken as proof on its own.

  trace_calls.py <start> [depth] [nodecap]
"""
import struct
import sys
from collections import deque

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


# Authoritative PLT stubs (see plt_table.py -- earlier labels were wrong)
LIVE = {0x08B356F0: "__android_log_print",
        0x08B3AF80: "__android_log_write",
        0x08B3CEA0: "__android_log_vprint",
        0x08B3BE10: "openlog",
        0x08B3BE20: "syslog"}
DEAD = {0x39E5FF8: "emitter 0x39e5ff8", 0x39E609C: "emitter 0x39e609c"}
# possible *other* homes for a formatted message (stdout / a FILE stream)
STREAM = {0x08B38DF0: "printf", 0x08B39D40: "fprintf",
          0x08B3B110: "vfprintf"}

start = int(sys.argv[1], 16)
depth = int(sys.argv[2]) if len(sys.argv) > 2 else 6
cap = int(sys.argv[3]) if len(sys.argv) > 3 else 4000
WINDOW = 400

seen = {start}
q = deque([(start, [start])])
hits = []
visited = 0

while q and visited < cap:
    node, path = q.popleft()
    visited += 1
    o = va2off(node)
    if o is None:
        continue
    for k in range(WINDOW):
        a = node + k * 4
        off = va2off(a)
        if off is None:
            break
        w = struct.unpack_from("<I", d, off)[0]
        if w == 0xD65F03C0:          # ret -> end of this function
            break
        if (w & 0xFC000000) not in (0x14000000, 0x94000000):
            continue
        tgt = a + sx(w & 0x3FFFFFF, 26) * 4
        if tgt in LIVE:
            hits.append(("LIVE " + LIVE[tgt], path + [tgt], a))
            continue
        if tgt in STREAM:
            hits.append(("STREAM " + STREAM[tgt], path + [tgt], a))
            continue
        if tgt in DEAD:
            hits.append(("DEAD " + DEAD[tgt], path + [tgt], a))
            continue
        if len(path) < depth and tgt not in seen and va2off(tgt) is not None:
            seen.add(tgt)
            q.append((tgt, path + [tgt]))

print("start=0x%x depth=%d nodes visited=%d" % (start, depth, visited))
print("reachable log destinations: %d" % len(hits))
for label, path, site in hits[:20]:
    print()
    print("  %s   reached by BL at 0x%x" % (label, site))
    print("    path: " + " -> ".join("0x%x" % p for p in path))
if not hits:
    print("  NONE -- no path from 0x%x to a log destination within %d hops"
          % (start, depth))
