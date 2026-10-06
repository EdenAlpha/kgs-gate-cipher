"""logline_scan.py -- strings that are shaped like log output.

A printf format that ends in '\\n' is a log line, not UI text.  Collects every
such string in libUE4.so, then:
  - reports the ones mentioning score / match / result / goal / command
  - maps 'Score  HOME[%d] AWAY[%d]\\n' and every 'Success of Command' literal
    to a VA so str_xrefs.py can find the code that emits them
"""
import re
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
    t, _ = struct.unpack_from("<II", d, o)
    po, pv, _, pf, _, _ = struct.unpack_from("<QQQQQQ", d, o + 8)
    if t == 1:
        ph.append((po, pv, pf))


def off2va(off):
    for po, pv, pf in ph:
        if po <= off < po + pf:
            return pv + (off - po)
    return None


print("=" * 78)
print("1. strings that END in a newline (log-line shaped)")
print("=" * 78)
logs = [(m.start(), m.group(0)) for m in re.finditer(rb"[\x20-\x7e]{6,240}\n\x00", d)]
print("  count: %d" % len(logs))

pat = re.compile(r"score|match|result|goal|halftime|fulltime|command|reason|"
                 r"watchdog|disconnect|timeout|abnormal", re.I)
hits = [(o, s.decode("ascii", "replace")) for o, s in logs if pat.search(s.decode("latin-1"))]
print("  mentioning score/match/result/goal/command/reason/timeout: %d" % len(hits))
for o, s in hits[:70]:
    print("    0x%-9x %s" % (o2va if (o2va := off2va(o)) else 0, s.strip()[:140]))

print()
print("=" * 78)
print("2. every 'of Command' literal, with VA")
print("=" * 78)
i = 0
n = 0
while True:
    j = d.find(b"of Command", i)
    if j < 0:
        break
    a = d.rfind(b"\x00", 0, j) + 1
    b = d.find(b"\x00", j)
    s = d[a:b]
    try:
        s = s.decode("ascii")
    except Exception:
        s = repr(s)
    va = off2va(a)
    print("  VA=0x%-9x  %s" % (va or 0, s[:150]))
    n += 1
    i = j + 1
print("  total: %d" % n)

print()
print("=" * 78)
print("3. key VAs for str_xrefs.py")
print("=" * 78)
KEY = [
    b"Score  HOME[%d] AWAY[%d]\n",
    b"[%s] Success of Command : CmdSetMyclubBingoLinkPopupDisplayed\n",
    b"**GOALDEMO**%d:",
    b"Final_Result_%s",
]
for k in KEY:
    j = d.find(k)
    if j < 0:
        print("  %-64s NOT FOUND" % k[:64])
        continue
    print("  %-64s off=%d VA=0x%x" % (k[:64], j, off2va(j) or 0))
