#!/usr/bin/env python3
"""See the URL the GAME builds, once and for all.

The composer's callers pass `a` = std::string at obj+0x70.  We have never
read that field off a real object.  So:

  1. build the two real object types the game makes
       cmdobj = 0x767eaf0()          the command object
       task   = 0x7dc91d8(name)      the factory task
  2. dump EVERY 8-byte slot of each, decoded as a libc++ std::string
  3. drive the game's own gate-request builder 0x7afd364 with the composer
     hooked, so we see the exact URL it produces

Nothing is guessed: `a` comes from the object, the URL from the composer.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn.arm64_const import (                      # noqa: E402
    UC_ARM64_REG_X1, UC_ARM64_REG_X2,
)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

CTOR = 0x767EAF0
FACTORY = 0x7DC91D8
COMPOSER = 0x7B099D0
GATEBUILD = 0x7AFD364       # (self, task, state) -> composes gate URL
CREATE = 0x7CDA280


def u64(core, a):
    try:
        return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]
    except Exception:
        return 0


def rd_str(core, addr):
    """libc++ std::string: byte0 bit0 set -> long (size@8 ptr@0x10),
    else short (size = byte0>>1, chars at +1).  Returns None if implausible."""
    try:
        b0 = bytes(core.uc.mem_read(addr, 1))[0]
    except Exception:
        return None
    try:
        if b0 & 1:
            n = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 8, 8)))[0]
            p = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 0x10, 8)))[0]
            if not (0 < n <= 256) or not p:
                return None
            raw = bytes(core.uc.mem_read(p, n))
        else:
            n = b0 >> 1
            if n == 0 or n > 22:
                return None
            raw = bytes(core.uc.mem_read(addr + 1, n))
        if not all(32 <= c < 127 for c in raw):
            return None
        return raw.decode("ascii")
    except Exception:
        return None


def dump(core, base: int, nwords: int, label: str):
    print(f"\n=== {label} @ {base:#x} ({nwords} slots) ===", flush=True)
    hits = []
    for i in range(nwords):
        s = rd_str(core, base + 8 * i)
        if s:
            print(f"    +{8*i:#06x}  STR {s!r}", flush=True)
            hits.append((8 * i, s))
    if not hits:
        print("    (no decodable strings)", flush=True)
    return hits


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(CREATE, timeout_s=60)
    B = core.base

    # ---- the command object the game's own ctor builds -------------------
    cmdobj = core.alloc(0x4000, b"\0" * 0x4000, name="cmd")
    r = core.call(CTOR, w0=cmdobj, timeout_s=180, max_insns=400_000_000)
    print(f"[a] ctor -> obj={cmdobj:#x} err={r['error']}", flush=True)
    h1 = dump(core, cmdobj, 80, "command object")

    # ---- the factory task ------------------------------------------------
    name = core.alloc(64, b"CmdGetServerEnv\0", name="tn")
    r = core.call(FACTORY, name, 0, 0, 0, 0, timeout_s=60,
                  max_insns=20_000_000)
    task = r.get("x0")
    print(f"\n[a] factory task={task and hex(task)}", flush=True)
    h2 = dump(core, task, 200, "factory task") if task else []

    # ---- drive the gate builder with the composer hooked -----------------
    composed = []

    def on_composer(uc, c):
        sa = rd_str(core, uc.reg_read(UC_ARM64_REG_X1))
        sb = rd_str(core, uc.reg_read(UC_ARM64_REG_X2))
        print(f"\n[a] *** COMPOSER a={sa!r}  b={sb!r}", flush=True)
        composed.append((sa, sb))

    core.watch(COMPOSER, on_composer, name="composer")

    for obj, tag in ((cmdobj, "cmdobj"), (task, "task")):
        if not obj:
            continue
        self_obj = core.alloc(0x4000, b"\0" * 0x4000, name="self_" + tag)
        state = core.alloc(8, b"\0" * 8, name="st_" + tag)
        # the builder reads obj+0x70 as `a`; give the object a valid empty
        # std::string there if it has none, then let the game fill it
        try:
            r = core.call(GATEBUILD, w0=self_obj, w1=obj, x2=state,
                          timeout_s=120, max_insns=120_000_000)
            print(f"[a] gate builder({tag}) -> err={r['error']} x0={r['x0']:#x}",
                  flush=True)
        except Exception as e:
            print(f"[a] gate builder({tag}) -> {type(e).__name__}: "
                  f"{str(e)[:60]}", flush=True)

    print("\n[a] ==== URLs the game composed ====", flush=True)
    for sa, sb in composed:
        print(f"    a={sa!r} b={sb!r}", flush=True)
    if not composed:
        print("    (composer was never called)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
