#!/usr/bin/env python3
"""Which session/task method contains a BL to the HTTP stack?

Scan each session method's body for BL to curl_easy_setopt, the HTTP post
routine, the gateinfo sender, etc.
"""
from __future__ import annotations

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

SESS_METHODS = [
    0x7CDA184, 0x7CDA1F8, 0x7CDB974, 0x7CDB9D0,
    0x7CE1A48, 0x7CE1ACC, 0x7CDBA60, 0x7CDC3D8,
    0x7CDC414, 0x7CDC6E8, 0x7CDCA20, 0x7CDCAD4,
    0x7CDCAB4, 0x7CE1860, 0x7CE1974, 0x7CE1480,
    0x7CE157C, 0x7CE158C, 0x7CE1594, 0x7CE159C,
    0x7CE15A4, 0x7CE15AC, 0x7CDCAF4, 0x7CE1334,
    0x7CE1450, 0x7CDD7CC, 0x7CDD70C, 0x7CDD790,
    0x7CDD7AC, 0x7CDD7B4,
]

TASK_METHODS = [
    0x7DC8FBC, 0x7DC9248, 0x7DC911C, 0x7DC91C4,
    0x7DC91C8, 0x7DC91D0, 0x7B1F37C, 0x745AAEC,
]

INTERESTING = {
    0x6886498: "curl_easy_setopt",
    0x7D038C8: "http_post_routine",
    0x7D0C06C: "gateinfo_sender",
    0x7D015B0: "http_post_parent",
    0x7CE7070: "http_grandparent",
    0x7D157F8: "http_alt",
    0x7D0BDA8: "gateinfo_parent",
    0x6886548: "curl_easy_perform",
    0x6858C98: "curl_easy_init",
}


def bl_targets(text):
    """-> set of BL targets in .text"""
    out = set()
    for idx in range(len(text) // 4):
        i = struct.unpack_from("<I", text, idx * 4)[0]
        if (i & 0xFC000000) == 0x94000000:
            imm = i & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            pc = TEXT_VADDR + idx * 4
            out.add(pc + (imm << 2))
    return out


def main():
    with open(SO, "rb") as f:
        f.seek(TEXT_OFF)
        text = f.read(TEXT_SIZE)
    print("scanning .text for BL targets ...", flush=True)
    allbl = bl_targets(text)
    print(f"  {len(allbl):,} BL targets\n", flush=True)

    for label, methods in (("SESSION", SESS_METHODS),
                           ("TASK", TASK_METHODS)):
        print("=" * 74)
        print(f"{label} METHODS calling the HTTP stack")
        print("=" * 74)
        for m in methods:
            body = bl_targets_in(text, m, 0x400)
            found = [INTERESTING[a] for a in body if a in INTERESTING]
            if found:
                print(f"  {m:#x}: {', '.join(sorted(set(found)))}")
        print()
    return 0


def bl_targets_in(text, start, length):
    """BL targets from the `length` bytes at vaddr `start`."""
    off = start - 0x4000
    chunk = text[off:off + length]
    out = set()
    base = start & ~3
    for idx in range(len(chunk) // 4):
        i = struct.unpack_from("<I", chunk, idx * 4)[0]
        if (i & 0xFC000000) == 0x94000000:
            imm = i & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            pc = base + idx * 4
            out.add(pc + (imm << 2))
    return out


if __name__ == "__main__":
    sys.exit(main())
