#!/usr/bin/env python3
"""Scan .text for direct BL calls to given target addresses.

BL is a PC-relative immediate, so it survives packed relocations -- this is
the one static reference that always works.

Address model: vaddr = file offset + 0x4000 (confirmed for .text)."""
from __future__ import annotations

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48
TEXT_VA = 0x28293C0          # = TEXT_OFF + 0x4000

TARGETS = {
    "curl_easy_perform?": 0x6858D84,
    "multi_add_handle?": 0x68788C4,
    "multi_alloc?": 0x68786B8,
    "multi_thunk": 0x68788B4,
    "mp_wait?": 0x687990C,
    "mp_perform?": 0x6879928,
    "mp_info_read?": 0x687AF14,
    "mp_remove?": 0x6878E80,
    "sender": 0x7D03B68,
    "sender2": 0x7D03C68,
    "sender3": 0x7D04148,
    "http_post_routine": 0x7D038C8,
    "begin_method": 0x7D044B0,
}


def bl_target(pc, w):
    imm26 = w & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return pc + imm26 * 4


def main():
    with open(SO, "rb") as f:
        f.seek(TEXT_OFF)
        data = f.read(TEXT_SIZE)
    print(f"read {len(data):#x} bytes of .text")
    hits = {k: [] for k in TARGETS}
    for off in range(0, len(data) - 3, 4):
        w = struct.unpack_from("<I", data, off)[0]
        if (w & 0xFC000000) != 0x94000000:      # BL
            continue
        pc = TEXT_VA + off
        t = bl_target(pc, w)
        for k, tv in TARGETS.items():
            if t == tv:
                hits[k].append(pc)
    for k, v in hits.items():
        print(f"\n{k} -> {TARGETS[k]:#x}:  {len(v)} callers")
        for c in v[:60]:
            print(f"    {c:#x}")
        if len(v) > 60:
            print(f"    ... +{len(v)-60} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
