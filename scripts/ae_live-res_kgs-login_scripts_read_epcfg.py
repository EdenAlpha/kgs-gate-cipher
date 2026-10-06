#!/usr/bin/env python3
"""Read get_endpoint_config's data table from the RUNNING game.

0x7d6532c reads slots at 0xa4b0000..0xa4b0218.  Those are .bss (zero in the
file) filled by relocations at load, so the only way to see the values is
live, after boot.  Prints every slot as qword + resolved string (if any).
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

CREATE = 0x7CDA280


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(CREATE, timeout_s=60)
    print("[epcfg] booted  base=%#x" % core.base, flush=True)
    uc = core.uc
    for va in range(0xA4B0000, 0xA4B0240, 8):
        try:
            raw = bytes(uc.mem_read(core.base + va, 8))
        except Exception as e:
            print("  %#x  <unreadable %s>" % (va, e))
            continue
        v = int.from_bytes(raw, "little")
        if v == 0:
            continue
        s = ""
        try:
            # runtime pointer? try reading a C string there
            if 0x10000000000 <= v < 0x1000A000000:
                rb = bytes(uc.mem_read(v, 96)).split(b"\x00")[0]
                if rb and all(32 <= b < 127 for b in rb):
                    s = rb.decode()
        except Exception:
            pass
        print("  %#x -> %#014x  %r" % (va, v, s), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
