#!/usr/bin/env python3
"""Call the curl sender 0x7d03b68 directly with a built sub-request.
It does: curl_global_init, curl_easy_init, CURLOPT_URL, WRITEFUNCTION,
then curl_easy_perform -- the game's own HTTP path end to end."""
from __future__ import annotations

import os
import struct
import sys
import time

from unicorn.arm64_const import (                                  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

SENDER = 0x7D03B68
SUBREQ_VT = 0x98225A0
CURL = 0x6886498
URL = b"http://ntl.service.konami.net/ntl/api/GateInfo.php"


def main():
    print("[send] booting ...", flush=True)
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

    def on_setopt(uc, c):
        o = uc.reg_read(UC_ARM64_REG_X1)
        v = uc.reg_read(UC_ARM64_REG_X2)
        if o == 10002:
            try:
                raw = bytes(uc.mem_read(v, 512))
            except Exception:
                raw = b""
            z = raw.find(b"\0")
            urls.append(raw[:z if z >= 0 else 512])
            print(f"    >>> URL = {urls[-1]!r}", flush=True)

    core.watch(CURL, on_setopt, name="curl")

    subreq = core.alloc(0x10200, b"\0" * 0x10200, name="subreq")
    core.write_u64(subreq, B + SUBREQ_VT)
    urlbuf = core.alloc(256, URL + b"\0" * (256 - len(URL)), name="url")

    print(f"[send] subreq={subreq:#x} calling 0x7d03b68 ...", flush=True)
    try:
        r = core.call(SENDER, subreq, urlbuf, 0, 0, 0, 0,
                      timeout_s=40, max_insns=15_000_000)
        print(f"  -> err={r['error']} x0={r['x0']:#x}", flush=True)
    except Exception as e:
        print(f"  -> {type(e).__name__}: {str(e)[:60]}", flush=True)

    print(f"\ncurl URLs: {len(urls)}")
    for u in urls[:6]:
        print(f"    {u!r}")

    print("\nlog (last 10):")
    for line in getattr(core, "_log", [])[-10:]:
        print("   ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
