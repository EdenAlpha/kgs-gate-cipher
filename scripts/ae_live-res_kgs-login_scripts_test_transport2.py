#!/usr/bin/env python3
"""The SM reads a std::string as:
    ldrb w9, [x8]        ; byte at +0   (bit 0 = is_long)
    ldr  x10,[x8,#0x10]  ; data pointer at +0x10
    csinc x0, x10, x8, ne
So the layout is {flag@0, size@8, data@0x10}.  Retry the transport with
that layout.
"""
from __future__ import annotations

import os
import struct
import sys
import time

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

TRANSPORT = 0x7D017DC
CURL_SETOPT = 0x6886498
SESS = 0xA4AB6A8
URL = b"http://ntl.service.konami.net/ntl/api/GateInfo.php"


def attempt(core, layout):
    url_buf = core.alloc(256, URL + b"\0" * (256 - len(URL)), name="u")
    ctx = core.alloc(0x4000, b"\0" * 0x4000, name="c")
    if layout == "flag0_size8_data16":
        core.write_u8(ctx + 0x3968, 0x01)          # is_long
        core.write_u64(ctx + 0x3970, len(URL))     # size
        core.write_u64(ctx + 0x3978, url_buf)      # data
    elif layout == "cap0_size8_data16":
        core.write_u64(ctx + 0x3968, 0x100 | 1)     # cap | long
        core.write_u64(ctx + 0x3970, len(URL))     # size
        core.write_u64(ctx + 0x3978, url_buf)      # data
    elif layout == "data0_size8_cap16":
        core.write_u64(ctx + 0x3968, url_buf)
        core.write_u64(ctx + 0x3970, len(URL))
        core.write_u64(ctx + 0x3978, 0x100 | 1)
    return ctx


def main():
    for layout in ("flag0_size8_data16", "cap0_size8_data16",
                   "data0_size8_cap16"):
        print("\n" + "#" * 74)
        print(f"# layout = {layout}")
        print("#" * 74)
        core = OnlineCore(verbose=False)
        core.install_netsplice()
        for fn in REGISTRARS:
            try:
                core.call(fn)
            except Exception:
                pass
        core.call(0x7CDA280, timeout_s=60)
        B = core.base

        urls = []

        def hook(uc, c, _u=urls):
            from unicorn.arm64_const import UC_ARM64_REG_X1, UC_ARM64_REG_X2
            o = uc.reg_read(UC_ARM64_REG_X1)
            v = uc.reg_read(UC_ARM64_REG_X2)
            if o == 10002:
                try:
                    raw = bytes(uc.mem_read(v, 512))
                except Exception:
                    raw = b""
                z = raw.find(b"\0")
                _u.append(raw[:z if z >= 0 else 512])
                print(f"    >>> URL = {_u[-1]!r}", flush=True)
        core.watch(CURL_SETOPT, hook, name="curl")

        ctx = attempt(core, layout)
        try:
            r = core.call(TRANSPORT, ctx, timeout_s=40,
                          max_insns=15_000_000)
            print(f"  -> err={r.get('error')} x0={r.get('x0'):#x}")
        except Exception as e:
            print(f"  -> {type(e).__name__}: {str(e)[:60]}")
        print(f"  urls={len(urls)}")
        for u in urls[:3]:
            print(f"      {u!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
