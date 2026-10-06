#!/usr/bin/env python3
"""Print NUL-separated ASCII strings in a VA window."""
import struct, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")


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


def va2off(ph, va):
    for po, pv, pf, _ in ph:
        if pv <= va < pv + pf:
            return po + (va - pv)
    return None


def main():
    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    start = int(sys.argv[1], 16)
    end = int(sys.argv[2], 16) if len(sys.argv) > 2 else start + 0x800
    o = va2off(ph, start)
    buf = data[o:o + (end - start)]
    i = 0
    while i < len(buf):
        if 0x20 <= buf[i] <= 0x7e:
            j = i
            while j < len(buf) and 0x20 <= buf[j] <= 0x7e:
                j += 1
            if j - i >= 4:
                print("0x%08x  %s" % (start + i, buf[i:j].decode("ascii", "replace")))
            i = j + 1
        else:
            i += 1


if __name__ == "__main__":
    main()
