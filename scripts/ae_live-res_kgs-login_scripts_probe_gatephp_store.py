#!/usr/bin/env python3
"""Does 0x7a2fc64 WRITE the gate.php URL into its `this` object?

Earlier we concluded it returns void and the value dies on the stack.  That
conclusion assumed x0 was not a `this`.  Give it a real object and diff it.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

FN = 0x7A2FC64


def main() -> int:
    print("[store] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[store] booted", flush=True)

    obj = core.alloc(0x2000, b"\0" * 0x2000, name="composer_this")
    print(f"[store] this={obj:#x}", flush=True)

    hits = []
    for probe in (obj, 0):
        for off in range(0, 0x2000, 8):
            core.write_u64(obj + off, 0)
        r = core.call(FN, x0=probe, timeout_s=60, max_insns=40_000_000)
        print(f"[store] run x0={probe:#x} -> err={r['error']} "
              f"pc={r['pc']:#x}", flush=True)
        blob = bytes(core.uc.mem_read(obj, 0x2000))
        for i in range(0, len(blob)):
            if blob[i:i + 4] == b"http":
                end = blob.find(b"\0", i)
                print(f"       FOUND at +{i:#x}: "
                      f"{blob[i:end]!r}", flush=True)
                hits.append(i)
            elif blob[i:i + 8] == b"pes22-ga":
                end = blob.find(b"\0", i)
                print(f"       HOST at +{i:#x}: {blob[i:end]!r}", flush=True)
                hits.append(i)
        if probe:
            nonzero = [(i, b) for i, b in enumerate(blob) if b]
            print(f"       written bytes: {len(nonzero)}", flush=True)
            for i, b in nonzero[:40]:
                print(f"           +{i:#x} = {b:#04x}", flush=True)
    print(f"[store] done hits={hits}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
