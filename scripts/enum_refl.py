#!/usr/bin/env python3
"""enum_refl.py <so> <regex on enum NAME> [--all]

The game emits UENUM reflection strings as 'EEnumName::MEMBER'. Group
every such string by enum name and print members of the enums whose name
matches. This yields server-valid enum vocabulary straight from the
build instead of guessing."""
import re
import sys

sys.path.insert(0, r"C:\Users\Administrator\AppData\Local\Temp\2")
from xref2 import Elf            # noqa: E402


def main():
    path = sys.argv[1]
    pat = sys.argv[2] if len(sys.argv) > 2 else "."
    rx = re.compile(pat, re.I)
    e = Elf(path)
    groups = {}
    for sec in (".rodata", ".data.rel.ro", ".data"):
        if sec not in e.byname:
            continue
        _, _, _, addr, off, size = e.byname[sec]
        raw = e.read(off, size)
        for m in re.finditer(rb"[A-Za-z_][A-Za-z0-9_]*::[A-Za-z0-9_]{1,60}\x00",
                             raw):
            s = m.group()[:-1].decode("ascii")
            name, member = s.split("::", 1)
            if not name.startswith("E"):
                continue
            groups.setdefault(name, {}).setdefault(member,
                                                   addr + m.start())
    hit = sorted(n for n in groups if rx.search(n))
    if not hit:
        print("no enum name matches %r" % pat)
        return 0
    for n in hit:
        ms = groups[n]
        print("\n== %s  (%d members) ==" % (n, len(ms)))
        for k in sorted(ms, key=lambda k: ms[k]):
            print("    %-40s %#x" % (k, ms[k]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
