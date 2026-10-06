#!/usr/bin/env python3
"""Run the game's OWN GateInfo routine end to end.

  0x7d0bda8  ->  0x7d0c06c(holder, config)

  0x7d0c06c does the whole thing with the game's own code:
      * snprintf  (0x7d17d24 -> __vsnprintf_chk) builds
        {"titleCode":..,"locale":..,"version":..,"extra":..,"apiLevel":..}
      * hex-encodes it and prefixes "req="
      * POSTs it with the sub-request sender 0x7d03c68
      * pumps curl_multi_perform until the completion callback fires
      * parses STATUS / API_STATUS / LOG_ACTIVE out of the reply

  We only supply configuration: URL, titleCode, locale, version, extra.
  Every byte on the wire is produced by the binary itself.
"""
from __future__ import annotations

import os
import struct
import sys
import time

from unicorn.arm64_const import (                                  # noqa: E402
    UC_ARM64_REG_X1, UC_ARM64_REG_X2)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

GATEINFO = 0x7D0C06C          # the routine under test
SUBREQ_VT = 0x98225A0
SETOPT = 0x6886498

CURLOPT_URL = 0x2712          # 10002
CURLOPT_POSTFIELDS = 0x271F   # 10015
CURLOPT_POSTFIELDSIZE = 0x3C  # 60

URL = "http://ntl.service.konami.net/ntl/api/GateInfo.php"
TITLE_CODE = "pes22"
LOCALE = "en"
VERSION = "dt270"
EXTRA = ""

OK_DONE = 0xE5000207


def main():
    print("[gate] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    B = core.base

    # ------------------------------------------------------- globals check
    api_ptr = struct.unpack("<Q", bytes(core.uc.mem_read(B + 0x98DD2A0, 8)))[0]
    api_level = None
    if api_ptr:
        api_level = struct.unpack("<i", bytes(core.uc.mem_read(api_ptr, 4)))[0]
    polls = struct.unpack("<i", bytes(core.uc.mem_read(B + 0x98DD278, 4)))[0]
    print(f"[gate] **(0x98dd2a0) = {api_ptr:#x}  apiLevel = {api_level}",
          flush=True)
    print(f"[gate] *(0x98dd278) = {polls}   (pump loop budget)", flush=True)

    # ------------------------------------------------------- request watch
    seen = {"url": None, "body": None, "size": None}

    def on_setopt(uc, c):
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        try:
            if opt == CURLOPT_URL:
                raw = bytes(uc.mem_read(val, 300)).split(b"\0")[0]
                seen["url"] = raw
                print(f"    >>> URL   {raw!r}", flush=True)
            elif opt == CURLOPT_POSTFIELDS:
                raw = bytes(uc.mem_read(val, 900)).split(b"\0")[0]
                seen["body"] = raw
                print(f"    >>> BODY  {raw[:400]!r}", flush=True)
            elif opt == CURLOPT_POSTFIELDSIZE:
                seen["size"] = val
                print(f"    >>> SIZE  {val}", flush=True)
        except Exception as e:
            print(f"    >>> setopt {opt:#x} read failed: {e}", flush=True)

    core.watch(SETOPT, on_setopt, name="setopt")

    # ------------------------------------------------------------- objects
    subreq = core.alloc(0x10200, b"\0" * 0x10200, name="subreq")
    core.write_u64(subreq, B + SUBREQ_VT)

    holder = core.alloc(0x180, b"\0" * 0x180, name="gate_holder")
    core.write_u64(holder + 0x08, subreq)       # x19+8  -> sub-request
    core.write_u32(holder + 0x10, 0)            # must be 0 to proceed
    core.write_u32(holder + 0x14, 1)            # "not finished yet"
    core.write_u32(holder + 0x18, 0)            # completion status

    cfg = core.alloc(0x180, b"\0" * 0x180, name="gate_cfg")

    core.uc.mem_write(cfg + 0x000, URL.encode() + b"\0")
    core.uc.mem_write(cfg + 0x100, TITLE_CODE.encode() + b"\0")
    core.uc.mem_write(cfg + 0x120, LOCALE.encode() + b"\0")
    core.uc.mem_write(cfg + 0x128, VERSION.encode() + b"\0")
    core.uc.mem_write(cfg + 0x148, EXTRA.encode() + b"\0")

    print(f"[gate] subreq={subreq:#x} holder={holder:#x} cfg={cfg:#x}",
          flush=True)
    print(f"[gate] calling 0x{GATEINFO:x}(holder, cfg) ...", flush=True)

    t0 = time.time()
    r = core.call(GATEINFO, w0=holder, w1=cfg, timeout_s=180,
                  max_insns=200_000_000)
    print(f"[gate] -> x0={r['x0']:#x} err={r['error']} pc={r['pc']:#x} "
          f"({time.time() - t0:.1f}s)", flush=True)

    def u32(a):
        return struct.unpack("<I", bytes(core.uc.mem_read(a, 4)))[0]

    def i32(a):
        return struct.unpack("<i", bytes(core.uc.mem_read(a, 4)))[0]

    err_flag = u32(holder + 0x14)
    status = u32(holder + 0x18)
    print(f"[gate] holder+0x14 (pending/error) = {err_flag:#x}", flush=True)
    print(f"[gate] holder+0x18 (status)        = {status:#x}  "
          f"{'OK' if status == OK_DONE else ''}", flush=True)
    print(f"[gate] holder+0x15c                = {u32(holder + 0x15C):#x}",
          flush=True)

    code = i32(subreq + 8)
    blen = i32(subreq + 0x10020)
    print(f"[gate] HTTP code  = {code}", flush=True)
    print(f"[gate] body bytes = {blen}", flush=True)

    raw = bytes(core.uc.mem_read(subreq + 0x1C, max(min(blen or 0, 0x10000), 1)))
    print("[gate] ---- body ----", flush=True)
    print(raw[:2000].decode("utf-8", "replace"), flush=True)
    print("[gate] -------------", flush=True)

    print("\n[gate] outgoing:", flush=True)
    print(f"    url  = {seen['url']!r}", flush=True)
    print(f"    size = {seen['size']}", flush=True)
    if seen["body"]:
        print(f"    body = {seen['body'][:400]!r}", flush=True)
        if seen["body"].startswith(b"req="):
            try:
                import json
                decoded = bytes.fromhex(seen["body"][4:].decode()).decode()
                print(f"    decoded = {decoded}", flush=True)
                print(f"    parsed  = {json.loads(decoded)}", flush=True)
            except Exception as e:
                print(f"    decode failed: {e}", flush=True)

    print("\n[gate] libc calls:", flush=True)
    for k in sorted(getattr(core, "import_calls", {})):
        v = core.import_calls[k]
        if v:
            print(f"    {k:22s} {v}", flush=True)
    print("\n[gate] network trace:", flush=True)
    for line in getattr(core, "_log", []):
        if line.startswith("net "):
            print("   ", line, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
