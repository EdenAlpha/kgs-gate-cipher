#!/usr/bin/env python3
"""Where do the Def_* values come from?

The gRPC config loader (0x7b101f8) reads Def_Online_gRPC_server_address,
_insecure, debug_root_ca, _path, _port from a global map. If that map is
populated from a FILE we can write, then on a rooted device we can set
Def_Online_gRPC_debug_root_ca to our own CA and MITM the traffic in
cleartext -- no TLS interception guesswork needed.

So: find the file/asset the Def_ table is loaded from.
"""
from __future__ import annotations

import os
import re
import struct

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"
d = open(SO, "rb").read()


def ctx(needle: bytes, before=140, after=180, limit=3, label=""):
    print("=" * 18, label or needle.decode("latin1"))
    n, i = 0, 0
    while n < limit:
        i = d.find(needle, i)
        if i < 0:
            break
        st = max(0, i - before)
        seg = d[st:i + after]
        # print printable runs only, so it is readable
        runs = [m.decode("latin1", "replace")
                for m in re.findall(rb"[\x20-\x7e]{4,}", seg)]
        print("  @%#x  %s" % (i, " | ".join(runs))[:400])
        n += 1
        i += 1
    print()


ctx(b"0_DEF_", label="0_DEF_")
ctx(b"Def_Online_gRPC_insecure", before=200, after=200, label="gRPC_insecure ctx")
ctx(b"Def_Online_gRPC_server_address", before=200, after=200, limit=2,
    label="server_address ctx")

print("=" * 18, "candidate config file names in the binary")
pats = (rb"[\w./-]{3,60}\.(?:ini|cfg|conf|json|xml|dat|properties|csv|txt)",
        rb"[\w./-]{0,40}def[\w./-]{0,40}")
found = set()
for m in re.finditer(pats[0], d):
    s = m.group(0).decode("latin1", "replace")
    if any(k in s.lower() for k in ("def", "config", "setting", "setting",
                                   "game", "online", "option")):
        found.add(s)
for s in sorted(found)[:40]:
    print("  ", s)
print("  total candidates:", len(found))

print("=" * 18, "strings near the Def map global 0x9a9e738")
# the map global; look for adjacent string table refs
for name, va in (("map", 0x9a9e738),):
    page = va & ~0xFFF
    text_off = 0x28253C0
    text_va = 0x28293C0
    text_len = 0x630BE48
    text = d[text_off:text_off + text_len]
    pend, hits = {}, []
    for off in range(0, len(text), 4):
        w = struct.unpack_from("<I", text, off)[0]
        pc = text_va + off
        if (w & 0x9F000000) == 0x90000000:
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            v = (immhi << 2) | immlo
            if v & (1 << 20):
                v -= 1 << 21
            pend[w & 0x1F] = (pc & ~0xFFF) + (v << 12)
            continue
        if (w & 0xFF800000) == 0x91000000:
            rn = (w >> 5) & 0x1F
            rd = w & 0x1F
            imm = (w >> 10) & 0xFFF
            if w & (1 << 22):
                imm <<= 12
            if rn in pend and pend[rn] + imm == va:
                hits.append(pc)
            pend.pop(rd, None)
            continue
        pend.pop(w & 0x1F, None)
    print("  refs to %#x: %d" % (va, len(hits)))
    for pc in hits[:12]:
        st = max(0, pc - 200)
        runs = [m.decode("latin1", "replace")
                for m in re.findall(rb"[\x20-\x7e]{5,}", d[st:pc + 200])]
        print("   %#x : %s" % (pc, " | ".join(runs))[:300])
