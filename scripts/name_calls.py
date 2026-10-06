"""Name every function FUN_07c38a44 calls, using the Ghidra symbol dump.

The disassembly gave raw BL targets in ELF VAs. The dump's FUNCTIONS section
is  `FUNC <name> @ <dumpaddr> size=<n>`  and dumpaddr = elfva + 0x100000
(proved again by the very first entry: 029293c0 == segment-2 VA 028293c0+100000).
So the two can be joined directly, with no decompiler pass needed.
"""
import os
import re

ROOT = r"C:\Users\Administrator\AppData\Local\Temp\2"
DIS = os.path.join(ROOT, "dis_fun.txt")
DUMP = os.path.join(ROOT, "full1", "fulldump_out.txt")

DELTA = 0x100000


def read_text(path):
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    return raw.decode("utf-8", "replace")


# ---- 1. distinct BL targets from the disassembly ------------------------
targets = []
for line in read_text(DIS).splitlines():
    m = re.search(r"-> CALL va (0x[0-9a-f]+)", line)
    if m:
        va = int(m.group(1), 16)
        if va not in targets:
            targets.append(va)
print("distinct call targets: %d" % len(targets))

# ---- 2. Ghidra's function table ----------------------------------------
wanted = {va + DELTA for va in targets}
found = {}
func_rx = re.compile(r"^FUNC\s+(\S+)\s+@\s+([0-9a-f]{8})\s+size=(\d+)")
with open(DUMP, "r", errors="replace") as fh:
    for line in fh:
        m = func_rx.match(line)
        if m:
            a = int(m.group(2), 16)
            if a in wanted:
                found[a] = (m.group(1), int(m.group(3)))
        if len(found) == len(wanted):
            break
print("named: %d / %d" % (len(found), len(wanted)))
print()
print("%-11s %-11s %-9s %s" % ("CALL elfva", "dump va", "size", "symbol"))
print("-" * 78)
for va in targets:
    dv = va + DELTA
    hit = found.get(dv)
    print("%-11x %-11x %-9s %s" % (
        va, dv, (hit[1] if hit else "-"),
        hit[0] if hit else "?  (not a recognised function)"))
