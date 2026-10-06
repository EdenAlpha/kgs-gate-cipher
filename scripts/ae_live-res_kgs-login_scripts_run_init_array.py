#!/usr/bin/env python3
"""Run the game's own static initialisers (.init_array) -- the step Android's
dynamic linker normally performs and the harness has been skipping.

  INIT_ARRAY  0x98bd898   INIT_ARRAYSZ  0x171a8   ->  11,765 constructors

These are what build the game's global registries, vtables and request
tables.  Without them the request pipeline has uninitialised maps and the
gate builder cannot complete a request.
"""
from __future__ import annotations

import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

INIT_ARRAY = 0x98BD898
INIT_ARRAYSZ = 0x171A8


def main() -> int:
    limit = int(os.environ.get("INIT_LIMIT", "20000"))
    print("[init] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    print("[init] booted", flush=True)
    B = core.base

    n = INIT_ARRAYSZ // 8
    raw = bytes(core.uc.mem_read(B + INIT_ARRAY, INIT_ARRAYSZ))
    # the array now holds relocated pointers (base + addend), but core.call()
    # takes file VAs and adds the base itself -- so strip it back off.
    entries = [struct.unpack_from("<Q", raw, 8 * i)[0] - B for i in range(n)]
    live = [e for e in entries if 0x1000 <= e < 0x10000000]
    print(f"[init] {n} entries, {len(live)} look like relocated code",
          flush=True)

    ok = skipped = failed = 0
    faults = {}
    t0 = time.time()
    for i, fn in enumerate(live[:limit]):
        if not fn:
            skipped += 1
            continue
        try:
            r = core.call(fn, timeout_s=20, max_insns=5_000_000)
            if r["error"]:
                failed += 1
                key = r["error"]
                faults[key] = faults.get(key, 0) + 1
            else:
                ok += 1
        except Exception as e:
            failed += 1
            key = type(e).__name__
            faults[key] = faults.get(key, 0) + 1
        if (i + 1) % 1000 == 0:
            print(f"    {i+1}/{min(limit,len(live))}  ok={ok} fail={failed}  "
                  f"({time.time()-t0:.0f}s)", flush=True)

    print(f"\n[init] done: ok={ok} failed={failed} skipped={skipped} "
          f"({time.time()-t0:.0f}s)", flush=True)
    print("[init] fault kinds:", faults, flush=True)

    print("\n[init] now the online registrars ...", flush=True)
    for fn in REGISTRARS:
        try:
            r = core.call(fn, timeout_s=30, max_insns=20_000_000)
            print(f"    {fn:#x} -> {r['error']}", flush=True)
        except Exception as e:
            print(f"    {fn:#x} -> EXC {type(e).__name__}", flush=True)

    print("\n[init] session create 0x7cda280 ...", flush=True)
    r = core.call(0x7CDA280, timeout_s=60, max_insns=50_000_000)
    print(f"    -> {r['error']} x0={r['x0']:#x}", flush=True)

    print("\n[init] log tail:", flush=True)
    for line in getattr(core, "_log", [])[-10:]:
        print("   ", line, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
