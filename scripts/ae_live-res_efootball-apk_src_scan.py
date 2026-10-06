#!/usr/bin/env python3
"""Extract KONAMI source-file paths (PES22HC tree) from libUE4.so.
   These name the exact translation units implementing match/netcode rules.
Output: source_paths.txt"""
import struct, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")
OUT = os.path.join(HERE, "source_paths.txt")


def parse_elf(data):
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    ph = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, o)
        p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<QQQQQQ", data, o + 8)
        if p_type == 1:
            ph.append((p_offset, p_vaddr, p_filesz, p_flags))
    return ph


def off2va(ph, off):
    for po, pv, pf, _ in ph:
        if po <= off < po + pf:
            return pv + (off - po)
    return None


def main():
    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    found = {}
    for m in re.finditer(rb"[A-Z]:\\[ -~]{5,200}?\.(cpp|cc|c|h|hpp)", data):
        s = m.start()
        while s > 0 and data[s - 1] != 0 and 0x20 <= data[s - 1] <= 0x7e:
            s -= 1
        e = m.end()
        while e < len(data) and data[e] != 0 and 0x20 <= data[e] <= 0x7e:
            e += 1
        b = data[s:e]
        if not (8 <= len(b) <= 240):
            continue
        try:
            t = b.decode("ascii")
        except Exception:
            continue
        found[t] = off2va(ph, s)

    lines = ["source paths: %d" % len(found)]
    # group: highlight Match/Online/netcode
    hot = [t for t in found if re.search(r"(Match|Online|Multiplay|Net|P2P|Stun|Turn|WatchDog|Watchdog)", t, re.I)]
    rest = [t for t in found if t not in hot]
    lines.append("\n--- RELEVANT (%d) ---" % len(hot))
    for t in sorted(hot, key=str.lower):
        lines.append("  %s" % t)
    lines.append("\n--- OTHER (%d) ---" % len(rest))
    for t in sorted(rest, key=str.lower):
        lines.append("  %s" % t)
    open(OUT, "w", encoding="utf-8", errors="replace").write("\n".join(lines))
    print("WROTE %s lines=%d relevant=%d" % (OUT, len(lines), len(hot)))


if __name__ == "__main__":
    main()
