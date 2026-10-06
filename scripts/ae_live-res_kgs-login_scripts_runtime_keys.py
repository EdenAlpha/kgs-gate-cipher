#!/usr/bin/env python3
"""Read the per-command MessagePack key tables from the RUNNING game.

They live in .bss (all-zero in the file) and are filled when the game's
constructors run, so the only way to see them is inside the harness after
`REGISTRARS` + CREATE.  Image addresses map at runtime as core.base + VA.

Prints, for each room command's key-table region, every 8-byte slot read both
as the game's own SSO string (the layout drive_cmd_wire's rd_str understands)
and as a plain C string.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "scripts"))

from unicorn.arm64_const import UC_ARM64_REG_X0  # noqa: E402

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402
from drive_cmd_wire import rd_str, u64  # noqa: E402

CREATE = 0x7CDA280

REGIONS = [
    ("CMD_CREATEJOIN_ROOM", 0x97E3B00, 0x97E3C80, 0x97E2F00, 0x97E3180),
    ("CMD_SEND_RECRUIT_CODE", 0x97D7550, 0x97D7700, 0x97D6F00, 0x97D7180),
    ("CMD_GET_SESSION_ID", 0x98260A0, 0x9826180, 0x9825F00, 0x9826100),
]

# per-command body writers (the function that appends real fields to the base
# map).  CMD_LOGIN's is 0x76b1b28; the room ones sit next to their ctors.
WRITERS = [
    ("CMD_CREATEJOIN_ROOM", 0x77B7414),
    ("CMD_SEND_RECRUIT_CODE", 0x76C5C74),
    ("CMD_GET_SESSION_ID", 0x7DA8AA8),
]


def show_region(core, label, lo, hi):
    base = core.base
    print("\n--- %s  runtime %#x..%#x ---"
          % (label, base + lo, base + hi), flush=True)
    for va in range(lo & ~7, hi, 8):
        try:
            v = u64(core, base + va)
        except Exception:
            continue
        if v == 0:
            continue
        sso = rd_str(core, v) if v > 0x1000 else ""
        try:
            raw = bytes(core.uc.mem_read(v, 48)).split(b"\x00")[0]
            cstr = raw.decode("latin1") if raw and all(
                32 <= b < 127 for b in raw) else ""
        except Exception:
            cstr = ""
        print("  %#x -> %#014x  sso=%-24r cstr=%r"
              % (va, v, (sso or "")[:24], cstr), flush=True)


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(CREATE, timeout_s=60)
    print("[keys] booted  base=%#x" % core.base, flush=True)

    for label, a1, b1, a2, b2 in REGIONS:
        show_region(core, label + " tableA", a1, b1)
        show_region(core, label + " tableB", a2, b2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
