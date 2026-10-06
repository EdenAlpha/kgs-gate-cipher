#!/usr/bin/env python3
"""Find ALooper_pollAll / ALooper_pollOnce in the binary and report the
address of each, plus any nearby exported-name table, so we can call the
game's own engine pump between gRPC task steps.
"""
from __future__ import annotations

import re

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"
data = open(SO, "rb").read()

for needle in (b"ALooper_pollAll", b"ALooper_pollOnce", b"ALooper_prepare",
               b"ALooper_addFd", b"ALooper_wake"):
    i = 0
    hits = []
    while True:
        i = data.find(needle, i)
        if i < 0:
            break
        hits.append(i)
        i += 1
    print("%-18s %d hit(s): %s" % (needle.decode(), len(hits),
                                   [hex(h) for h in hits[:6]]))
    for h in hits[:3]:
        st = h
        while st > 0 and 32 <= data[st - 1] < 127:
            st -= 1
        print("     ctx @%#x: %r" % (st, data[st:st + 90]))

# is there a symbol table with these?
print("\n--- dynsym / symtab present? ---")
import struct
e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    name, typ, flags, addr, off, size, link, info, align, entsz = \
        struct.unpack_from("<IIQQQQIIQQ", data, o)
    secs.append((name, typ, addr, off, size, link, entsz))
shstr = secs[e_shstrndx]
shstr_data = data[shstr[3]:shstr[3] + shstr[4]]


def secname(n):
    end = shstr_data.find(b"\0", n)
    return shstr_data[n:end].decode()


for name, typ, addr, off, size, link, entsz in secs:
    nm = secname(name)
    if typ in (2, 11):      # SHT_SYMTAB / DYNSYM
        print("  %s: type=%d size=%d entsz=%d" % (nm, typ, size, entsz))
        if entsz:
            cnt = size // entsz
            found = 0
            for k in range(cnt):
                so = off + k * entsz
                st_name, st_info, st_other, st_shndx, st_value, st_size = \
                    struct.unpack_from("<IBBHQQ", data, so)
                end = shstr_data.find(b"\0", link * entsz + st_name) \
                    if False else None
            # names live in the linked strtab
            if link < len(secs):
                lname, ltyp, laddr, loff, lsize, _, _ = secs[link]
                strtab = data[loff:loff + lsize]
                for k in range(cnt):
                    so = off + k * entsz
                    st_name, st_info, st_other, st_shndx, st_value, st_size = \
                        struct.unpack_from("<IBBHQQ", data, so)
                    end = strtab.find(b"\0", st_name)
                    s = strtab[st_name:end].decode("latin1", "replace")
                    if "ALooper" in s or "pollAll" in s:
                        print("     %s = %#x" % (s, st_value))
                        found += 1
                if not found:
                    print("     (no ALooper entries)")
