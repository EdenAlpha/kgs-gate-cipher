#!/usr/bin/env python3
"""Why does the game's curl_easy_init return NULL?"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

EASY_INIT = 0x6858C98
GLOBAL_INIT = 0x6858B14
GLOBAL_LOCK = 0xA40E098


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    B = core.base

    # --- the global curl init counter -----------------------------------
    def u32(a):
        return struct.unpack("<I", bytes(core.uc.mem_read(a, 4)))[0]

    print(f"[curl] global counter at {GLOBAL_LOCK:#x} = "
          f"{u32(B + GLOBAL_LOCK)}", flush=True)

    snap = dict(getattr(core, "import_calls", {}))

    print("[curl] calling curl_global_init(1) ...", flush=True)
    r = core.call(GLOBAL_INIT, w0=1, timeout_s=60, max_insns=20_000_000)
    print(f"       -> x0={r['x0']:#x} err={r['error']} "
          f"counter={u32(B + GLOBAL_LOCK)}", flush=True)

    print("[curl] calling curl_easy_init() ...", flush=True)
    r = core.call(EASY_INIT, timeout_s=60, max_insns=50_000_000)
    print(f"       -> x0={r['x0']:#x} err={r['error']} pc={r['pc']:#x}",
          flush=True)

    diff = {}
    for k, v in getattr(core, "import_calls", {}).items():
        d = v - snap.get(k, 0)
        if d:
            diff[k] = d
    print("\n[curl] imports during the two calls:", flush=True)
    for k in sorted(diff):
        print(f"    {k:28s} +{diff[k]}", flush=True)

    print("\n[curl] log tail:", flush=True)
    for line in getattr(core, "_log", [])[-14:]:
        print("   ", line, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
