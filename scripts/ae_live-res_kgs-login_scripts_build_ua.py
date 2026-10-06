#!/usr/bin/env python3
"""Run the game's own User-Agent builder (0x7dbc430) and print the result.

    f(std::string *out, ctx)  ->  out = the User-Agent the game sends to the
                                  game host (built from its own literals)
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

UA_BUILDER = 0x7DBC430


def rd_str(core, addr) -> str | None:
    try:
        b0 = bytes(core.uc.mem_read(addr, 1))[0]
        if b0 & 1:
            size = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 8, 8)))[0]
            ptr = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 0x10, 8)))[0]
            if size > 0x400 or ptr == 0:
                return None
            return bytes(core.uc.mem_read(ptr, size)).decode("utf-8", "replace")
        n = b0 >> 1
        return bytes(core.uc.mem_read(addr + 1, n)).decode("utf-8", "replace")
    except Exception:
        return None


def main() -> int:
    print("[ua] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[ua] booted", flush=True)

    out = core.alloc(64, b"\0" * 64, name="ua_out")
    ctx = core.alloc(0x4000, b"\0" * 0x4000, name="ua_ctx")

    for label, arg in (("ctx=zeroed", ctx), ("ctx=0", 0)):
        core.uc.mem_write(out, b"\0" * 64)
        try:
            r = core.call(UA_BUILDER, w0=out, w1=arg, timeout_s=60,
                          max_insns=200_000_000)
        except Exception as e:
            print(f"[ua] {label}: EXC {e}", flush=True)
            continue
        s = rd_str(core, out)
        print(f"[ua] {label}: err={r['error']} pc={r['pc']:#x} -> {s!r}",
              flush=True)
        if s:
            open("game_user_agent.txt", "w").write(s)
            print("[ua] wrote game_user_agent.txt", flush=True)
            return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
