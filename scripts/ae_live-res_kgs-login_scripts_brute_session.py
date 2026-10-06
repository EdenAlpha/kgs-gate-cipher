#!/usr/bin/env python3
"""Call each session method in turn (x0 = session) and watch for the game's
own HTTP stack firing.  Decisive: whichever method makes curl_easy_setopt
call is the network entry point.
"""
from __future__ import annotations

import os
import struct
import sys
import time

from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1   # noqa: E402

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

CREATE = 0x7CDA280
CURL_SETOPT = 0x6886498
SESS = 0xA4AB6A8

SESS_METHODS = [
    (0x7CDA184, "destroy0"), (0x7CDA1F8, "destroy1"),
    (0x7CDB974, "m4"), (0x7CDB9D0, "m5"),
    (0x7CE1A48, "m6"), (0x7CE1ACC, "m7"),
    (0x7CDBA60, "m8"), (0x7CDC3D8, "m9"),
    (0x7CDC414, "m10"), (0x7CDC6E8, "m11"),
    (0x7CDCA20, "m12"), (0x7CDCAD4, "m13"),
    (0x7CDCAB4, "m14"), (0x7CE1860, "m15"),
    (0x7CE1974, "m16"), (0x7CE1480, "m17"),
    (0x7CE157C, "m18"), (0x7CE158C, "m19"),
    (0x7CE1594, "m20"), (0x7CE159C, "m21"),
    (0x7CE15A4, "m22"), (0x7CE15AC, "m23"),
    (0x7CDCAF4, "m24"), (0x7CE1334, "m25"),
    (0x7CE1450, "m26"), (0x7CDD7CC, "m27"),
    (0x7CDD70C, "m28"), (0x7CDD790, "m29"),
    (0x7CDD7AC, "m30"), (0x7CDD7B4, "m31"),
]


def main():
    print("[bf] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(CREATE, timeout_s=60)
    B = core.base
    sess = struct.unpack("<Q", bytes(core.uc.mem_read(B + SESS, 8)))[0]
    print(f"[bf] session = {sess:#x}\n", flush=True)

    for addr, name in SESS_METHODS:
        urls = []

        def on_setopt(uc, c, _u=urls):
            opt = uc.reg_read(UC_ARM64_REG_X1)
            val = uc.reg_read(UC_ARM64_REG_X2)
            if opt == 10002:
                try:
                    raw = bytes(uc.mem_read(val, 256))
                except Exception:
                    raw = b""
                z = raw.find(b"\0")
                _u.append(raw[:z if z >= 0 else 256])

        core.watch(CURL_SETOPT, on_setopt, name=f"curl_{name}")
        try:
            r = core.call(addr, sess, timeout_s=20, max_insns=4_000_000)
            res = f"x0={r.get('x0'):#x} err={r.get('error')}"
        except Exception as e:
            res = f"{type(e).__name__}"
        n = len(urls)
        flag = "   <<< HTTP!" if n else ""
        print(f"  {name:10s} {addr:#x}: {res}  urls={n}{flag}")
        for u in urls[:3]:
            print(f"        {u!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
