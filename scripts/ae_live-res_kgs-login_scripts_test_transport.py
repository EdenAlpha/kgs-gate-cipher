#!/usr/bin/env python3
"""Prove the game's own HTTP stack works headlessly.

0x7d017dc is the transport wrapper:
    req = new(0x68); req->vt = 0x9822580;
    url = ctx->[0x3968];          <- a std::string
    http_post_routine(req);       <- the game's curl path

So: build a context with a real URL at +0x3968 and call it.  If
curl_easy_setopt fires, the game's own network stack is live.
"""
from __future__ import annotations

import os
import struct
import sys
import time

from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1   # noqa: E402

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

TRANSPORT = 0x7D017DC
CURL_SETOPT = 0x6886498
SESS = 0xA4AB6A8

URL = (b"http://ntl.service.konami.net/ntl/api/GateInfo.php")


def main():
    print("[xport] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    B = core.base
    sess = struct.unpack("<Q", bytes(core.uc.mem_read(B + SESS, 8)))[0]
    print(f"[xport] session = {sess:#x}", flush=True)

    urls = []
    bodies = []

    def on_setopt(uc, c):
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        if opt == 10002:                       # CURLOPT_URL
            try:
                raw = bytes(uc.mem_read(val, 512))
            except Exception:
                raw = b""
            z = raw.find(b"\0")
            urls.append(raw[:z if z >= 0 else 512])
            print(f"    >>> URL = {urls[-1]!r}", flush=True)
        elif opt == 10015:                     # CURLOPT_POSTFIELDS
            try:
                raw = bytes(uc.mem_read(val, 1024))
            except Exception:
                raw = b""
            bodies.append(raw)
            print(f"    >>> BODY ({len(raw)}B) = {raw[:200]!r}",
                  flush=True)

    core.watch(CURL_SETOPT, on_setopt, name="curl_easy_setopt")

    # ---- build the context with a URL at +0x3968 ------------------------
    url_buf = core.alloc(256, URL + b"\0" * (256 - len(URL)),
                         name="urlbuf")
    ctx = core.alloc(0x4000, b"\0" * 0x4000, name="http_ctx")

    # std::string (libc++ long): {data_ptr, size, cap|1}
    core.write_u64(ctx + 0x3968, url_buf)
    core.write_u64(ctx + 0x3970, len(URL))
    core.write_u64(ctx + 0x3978, 0x100 | 1)

    print(f"\n[xport] ctx={ctx:#x} url@ctx+0x3968", flush=True)
    print(f"[xport] calling transport 0x7d017dc ...", flush=True)

    try:
        r = core.call(TRANSPORT, ctx, timeout_s=60, max_insns=20_000_000)
        print(f"[xport] -> err={r.get('error')} x0={r.get('x0'):#x}",
              flush=True)
    except Exception as e:
        print(f"[xport] -> {type(e).__name__}: {str(e)[:80]}", flush=True)

    print("\n" + "=" * 74)
    print("RESULT")
    print("=" * 74)
    print(f"  URLs  : {len(urls)}")
    for u in urls[:5]:
        print(f"      {u!r}")
    print(f"  Bodies: {len(bodies)}")
    for b in bodies[:3]:
        print(f"      {b[:200]!r}")

    print("\nharness log (last 15):")
    for line in getattr(core, "_log", [])[-15:]:
        print("   ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
