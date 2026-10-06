#!/usr/bin/env python3
"""Follow the indirection to `a`.

The gate builder (0x7afd364) passes `a` = arg1 + 0x70, and in the sibling
caller (0x7b06850) that object is loaded as  x21 = *(task + 0x178).

We have read +0x70 directly off the task and the command object -- both
empty -- because `a` lives one pointer deeper.  Follow it.
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

FACTORY = 0x7DC91D8
COMPOSER = 0x7B099D0
CREATE = 0x7CDA280


def u64(core, a):
    try:
        return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]
    except Exception:
        return 0


def rd_str(core, addr):
    """Strict libc++ std::string decode; None if implausible."""
    try:
        b0 = bytes(core.uc.mem_read(addr, 1))[0]
        if b0 & 1:
            n = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 8, 8)))[0]
            p = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 0x10, 8)))[0]
            if not (0 < n <= 512) or not p:
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

    for tname in (b"CmdLogin", b"CmdGetServerEnv",
                  b"CmdGetKgsGuestLoginToken", b"CmdCreatejoinRoom"):
        name = core.alloc(64, tname + b"\0", name="tn")
        r = core.call(FACTORY, name, 0, 0, 0, 0, timeout_s=60,
                      max_insns=20_000_000)
        task = r.get("x0")
        print(f"\n=== task {tname!r} = {task and hex(task)} ===", flush=True)
        if not task:
            continue

        # follow every pointer-looking slot one level deep
        for off in (0x70, 0x178, 0x180, 0x48, 0x50, 0x68, 0x78, 0x168,
                    0x170, 0x188, 0x190):
            v = u64(core, task + off)
            s_here = rd_str(core, task + off)
            tag = f"task+{off:#x}"
            if s_here is not None:
                print(f"  {tag:12s} STR  {s_here!r}", flush=True)
                continue
            if not (0x1000000000 <= v < 0x200000000000):
                continue
            print(f"  {tag:12s} PTR  {v:#x}", flush=True)
            s2 = rd_str(core, v + 0x70)
            if s2 is not None:
                print(f"      -> +0x70  STR  {s2!r}     <<<<<< this is `a`",
                      flush=True)
                # build the URL from it
                out = core.alloc(64, b"\0" * 64, name="out")
                buf = bytearray(32)
                t = s2.encode()
                buf[0] = min(len(t), 22) << 1
                buf[1:1 + len(t)] = t[:22]
                sa = core.alloc(32, bytes(buf), name="strA")
                sb = core.alloc(32, bytes([0]), name="strB")
                try:
                    rr = core.call(COMPOSER, w0=out, x1=sa, x2=sb,
                                   timeout_s=60, max_insns=200_000_000)
                    print(f"      -> URL   {rd_str(core, out)!r}", flush=True)
                except Exception as e:
                    print(f"      -> composer ERR {e}", flush=True)
            for sub in (0x0, 0x10, 0x68, 0x70, 0x78, 0x80, 0x138, 0x170):
                s3 = rd_str(core, v + sub)
                if s3 is not None:
                    print(f"      -> +{sub:#05x} STR  {s3!r}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
