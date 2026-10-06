#!/usr/bin/env python3
"""Dump the CmdGetServerEnv task's parameter fields (+0x400..+0x460) and
disassemble vtable[8] (0x7dc911c) which builds strings from them."""
from __future__ import annotations

import os
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")


def cstr(core, addr, n=128):
    if not addr:
        return None
    try:
        b = bytes(core.uc.mem_read(addr, n))
    except Exception:
        return None
    i = b.find(b"\0")
    return b[:i if i >= 0 else n]


def main():
    from peerlink.online_client import OnlineCore, REGISTRARS
    sys.path.insert(0, os.path.join(HERE, "scripts"))
    sys.path.insert(0, HERE)

    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    B = core.base
    name = core.alloc(64, b"CmdGetServerEnv\0", name="cmdname")
    r = core.call(0x7DC91D8, name, 0, 0, 0, 0, timeout_s=60,
                  max_insns=20_000_000)
    task = r.get("x0")
    print(f"task = {task:#x}\n", flush=True)

    print("task parameter fields (+0x400..+0x460):")
    for off in range(0x400, 0x460, 8):
        try:
            v = struct.unpack("<Q", bytes(core.uc.mem_read(task + off, 8)))[0]
        except Exception:
            break
        if v == 0:
            continue
        s = cstr(core, v, 64)
        extra = ""
        if s and len(s) >= 2 and all(32 <= c < 127 for c in s):
            extra = f'  -> "{s.decode()}"'
        elif v > 0x1000:
            extra = f"  (ptr {v:#x})"
        print(f"    +{off:#04x}: {v:#018x}{extra}")

    # ---- vtable[8] ------------------------------------------------------
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    with open(SO, "rb") as f:
        f.seek(0x7DC911C - 0x4000)
        code = f.read(0x200)
    print("\n" + "=" * 74)
    print("vtable[8] = 0x7dc911c  (builds strings from task fields)")
    print("=" * 74)
    n = 0
    for ins in md.disasm(code, 0x7DC911C):
        print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
        n += 1
        if n > 45:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
