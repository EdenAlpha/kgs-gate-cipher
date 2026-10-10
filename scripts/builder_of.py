#!/usr/bin/env python3
"""builder_of.py <so> <CMD_NAME> ...  -- find a request builder and list
the .rodata strings it addresses (i.e. its msgid + argument key names).

Rebuilt 2026-10-10 (original destroyed by temp cleanup).
"""

import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
from xref2 import Elf, find_xrefs                # noqa: E402
from dump_keys import strings_in_func            # noqa: E402


def find_str(e, secs, needle):
    """VA of the first NUL-terminated occurrence of `needle`."""
    b = needle.encode() + b"\0"
    for name in secs:
        if name not in e.byname:
            continue
        _, _, _, addr, off, size = e.byname[name]
        raw = e.read(off, size)
        i = raw.find(b)
        if i >= 0:
            return addr + i, name
    return None, None


def main():
    path = sys.argv[1]
    names = sys.argv[2:]
    e = Elf(path)
    secs = [".rodata", ".data.rel.ro", ".data", ".rodata.str1.1"]
    found = {}
    for n in names:
        va, sec = find_str(e, secs, n)
        print("%-34s -> %s %s" % (n, ("%#x" % va) if va else "NOT FOUND", sec))
        if va:
            found[va] = n
    if not found:
        return 1
    print()
    x = find_xrefs(path, list(found))
    for va, n in found.items():
        hits = x[va]
        print("=== %s  (%d xrefs)" % (n, len(hits)))
        for pc in hits[:3]:
            print("  xref pc=%#x" % pc)
            strings_in_func(path, pc)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
