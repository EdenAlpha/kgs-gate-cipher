#!/usr/bin/env python3
"""Trace the game's task step to find why it stops at state=4 with no write.

Progress so far (all real game code running under Unicorn):
  creds 0xa40b038 built  -> args builder returns non-null
  state 0 -> 4, x0 = 1
so the channel path is live. The task's own jump table at 0xc6303c selects a
case by (this+0xc - 1); every case ends by building a request and calling
0x6778200 / 0x6777aec to START the stream, storing the handle at this+0x38.

Trace: log every direct call the task makes, and every field it reads/writes
in the task object, so we can see which case ran and what it found missing.
"""
from __future__ import annotations

import collections
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM  # noqa: E402
from unicorn import UC_HOOK_CODE  # noqa: E402

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

B = 0x10000000000
LO, HI = 0x67FF000, 0x6801000
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def put_str(core, addr, text, name="s"):
    raw = text.encode()
    if len(raw) <= 22:
        core.uc.mem_write(addr, bytes([len(raw) << 1]) + raw +
                          b"\0" * (32 - 1 - len(raw)))
    else:
        p = core.alloc(len(raw) + 1, raw + b"\0", name=name + "_h")
        core.uc.mem_write(addr, b"\x01" + b"\0" * 7)
        core.write_u64(addr + 8, len(raw))
        core.write_u64(addr + 0x10, p)


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    core.call(0x677716C, timeout_s=180, max_insns=500_000_000)
    print("[t] creds = %#x" % u64(core, B + 0xA40B038), flush=True)

    this = core.alloc(0x100, b"\0" * 0x100, name="task")
    put_str(core, this + 0x18,
            "/command_service.CommandService/CommandStream", "m")

    calls = []
    ring = collections.deque(maxlen=400)

    def on_code(uc, addr, size, ud):
        w = struct.unpack("<I", bytes(uc.mem_read(addr, 4)))[0]
        if (w & 0xFC000000) == 0x94000000:
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            tgt = addr + imm * 4
            if B + LO <= tgt < B + HI:
                calls.append((addr, tgt))
        ring.append(addr)

    core.uc.hook_add(UC_HOOK_CODE, on_code, begin=B + LO, end=B + HI)

    r = core.call(0x67FFCBC, w0=this, timeout_s=180, max_insns=400_000_000)
    print("[t] step: err=%s x0=%#x" % (r["error"], r["x0"]), flush=True)
    print("[t] task object dump:", flush=True)
    for off in range(0, 0x60, 8):
        print("   +0x%02x = %#018x" % (off, u64(core, this + off)), flush=True)
    print("\n[t] calls made (first 40):", flush=True)
    seen = set()
    for a, t in calls:
        if t in seen:
            continue
        seen.add(t)
        print("   %#012x -> %#012x" % (a, t), flush=True)
        if len(seen) > 40:
            break
    print("\n[t] last 25 pcs:", flush=True)
    for a in list(ring)[-25:]:
        try:
            w = struct.unpack("<I", bytes(core.uc.mem_read(a, 4)))[0]
            txt = next(md.disasm(struct.pack("<I", w), a))
            print("   %#012x: %s %s" % (a, txt.mnemonic, txt.op_str),
                  flush=True)
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
