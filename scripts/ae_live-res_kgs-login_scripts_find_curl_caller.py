#!/usr/bin/env python3
"""The sub-request vtable 0x98225a0 -- scan each method for a BL to the curl
stack.  That is the last missing link."""
from __future__ import annotations

import os
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

SUBREQ_VT = 0x98225A0
CURL = 0x6886498
HTTP = {0x7D038C8: "http_post", 0x7D0C06C: "gateinfo", 0x7D015B0: "httpparent"}


def bl_set(start, length):
    """BL targets from `length` bytes at vaddr `start`."""
    off = start - 0x4000
    with open(SO, "rb") as f:
        f.seek(off)
        chunk = f.read(length)
    out = set()
    for i in range(len(chunk) // 4):
        w = struct.unpack_from("<I", chunk, i * 4)[0]
        if (w & 0xFC000000) == 0x94000000:
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            out.add((start + i * 4) + (imm << 2))
    return out


def main():
    from peerlink.online_client import OnlineCore, REGISTRARS
    sys.path.insert(0, os.path.join(HERE, "scripts"))
    sys.path.insert(0, HERE)

    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    B = core.base

    try:
        vtd = bytes(core.uc.mem_read(B + SUBREQ_VT, 16 * 8))
    except Exception as e:
        print(f"unreadable: {type(e).__name__}")
        return 1

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for i in range(16):
        v = struct.unpack_from("<Q", vtd, i * 8)[0]
        if v == 0:
            continue
        a = v - B
        # find the function extent (approx 0x400)
        tgt = bl_set(a, 0x200)
        hits = [HTTP.get(t, f"curl@{t:#x}") for t in tgt
                if t == CURL or t in HTTP]
        print(f"  [{i:2d}] {a:#x}: "
              f"{', '.join(hits) if hits else 'no direct curl/HTTP BL'}")
        if hits:
            with open(SO, "rb") as f:
                f.seek(a - 0x4000)
                code = f.read(0x200)
            print(f"       disasm of {a:#x}:")
            n = 0
            for ins in md.disasm(code, a):
                print(f"         {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
                n += 1
                if n > 25:
                    break
    return 0


if __name__ == "__main__":
    sys.exit(main())
