"""rela_scan.py -- recover R_AARCH64_RELATIVE relocations by content, not by header.

`.rela.dyn`'s section header is mangled (sh_type 0x60000002, sh_entsize 1) and the
dynamic tags that should be DT_RELA / DT_RELASZ appear as 0x60000011 / 0x60000012
pointing at string data, so neither route finds the table.

A R_AARCH64_RELATIVE entry is (r_offset, r_info, r_addend) with r_info == 1027 and
symbol 0, i.e. the 8 bytes 03 04 00 00 00 00 00 00.  Scanning for that pattern and
validating the neighbouring fields recovers the table directly.

  rela_scan.py
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LIB = r"native\lib\arm64-v8a\libUE4.so"
d = open(LIB, "rb").read()

# a RELATIVE reloc writes into a writable segment, from a code/data address
WRITABLE = [(0x8B75140, 0x9902EC0), (0x9906CC0, 0x99D0E88)]
CODE = (0x28293C0, 0x8B71140)


def in_ranges(va, ranges):
    return any(lo <= va < hi for lo, hi in ranges)


PAT = struct.pack("<Q", 1027)          # r_info for R_AARCH64_RELATIVE, sym = 0

candidates = []
start = 0
while True:
    i = d.find(PAT, start)
    if i < 0:
        break
    start = i + 1
    if i < 8 or i + 16 > len(d):
        continue
    r_off, _, r_add = struct.unpack_from("<QQq", d, i - 8)
    if not in_ranges(r_off, WRITABLE):
        continue
    if not in_ranges(r_add, WRITABLE) and not (CODE[0] <= r_add < CODE[1]):
        continue
    candidates.append((i - 8, r_off, r_add))

print("R_AARCH64_RELATIVE candidates: %d" % len(candidates))
if not candidates:
    sys.exit(0)

# cluster into runs with a 24-byte stride
runs = []
cur = [candidates[0]]
for c in candidates[1:]:
    if c[0] - cur[-1][0] == 24:
        cur.append(c)
    else:
        runs.append(cur)
        cur = [c]
runs.append(cur)

runs.sort(key=len, reverse=True)
print("runs: %d   longest: %d entries" % (len(runs), len(runs[0])))
print()

RELA = {}
for run in runs[:4]:
    print("run at file off 0x%x..0x%x  (%d entries)" % (run[0][0], run[-1][0] + 24, len(run)))
    for _, r_off, r_add in run:
        RELA[r_off] = r_add
    print()

print("total addends captured: %d" % len(RELA))

# the vtables this investigation cares about
for name, base in (("command 0x97a2168", 0x97A2168),
                   ("command base 0x97a21d8", 0x97A21D8),
                   ("queue 0x9823660", 0x9823660),
                   ("handler 0x97a2888", 0x97A2888)):
    print("-" * 70)
    print(name)
    for k in range(12):
        a = base + k * 8
        v = RELA.get(a)
        if v is None:
            print("  [%2d] 0x%08x  -> (no reloc / zero)" % (k, a))
        else:
            mark = "  (code)" if CODE[0] <= v < CODE[1] else ""
            print("  [%2d] 0x%08x  -> 0x%08x%s" % (k, a, v, mark))
