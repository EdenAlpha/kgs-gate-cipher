#!/usr/bin/env python3
"""Find the vtable SLOT the login path dereferences, then its target.

The CMD_GET_SERVER_ENV class installs vtable 0x97a2600, which is a shared
base -- 700+ constructors install it.  So its slots are not "this class's
methods"; they are inherited defaults, and the derived class's own vtable
(0x97d4448 for the concrete command) extends it.

The failure we must fix is a `blr` through a null slot.  So instead of
guessing class layout, trace the actual faulting call in the emulator: find
the `blr` whose target register came from [vtable, #slot], and recover that
one slot's value by seeing which function *should* be there.

Practical route: for the concrete object, watch the emulator. When it does
    ldr xN,[xM]        (vtable)
    ldr xF,[xN,#slot]
    blr xF
log the slot.  Then find every function in the binary that is never called
directly but is a plausible override, and patch just that slot.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_X0,
                                 UC_ARM64_REG_X1, UC_ARM64_REG_X2)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

CTOR = 0x767EAF0
ENVELOPE = 0x74E3374


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
    obj = core.alloc(0x4000, b"\0" * 0x4000, name="cmd")
    core.call(CTOR, w0=obj, timeout_s=120, max_insns=400_000_000)
    print("obj vtable =", hex(struct.unpack(
        "<Q", bytes(core.uc.mem_read(obj, 8)))[0]))

    # log the last instructions before a blr to address 0
    hist = []

    def h(uc, addr, size, user):
        if B <= addr < B + 0x7000000:
            hist.append((addr - B, uc.reg_read(UC_ARM64_REG_X0),
                         uc.reg_read(UC_ARM64_REG_X1),
                         uc.reg_read(UC_ARM64_REG_X2)))
            del hist[:-12]

    core.uc.hook_add(UC_HOOK_CODE, h)

    try:
        core.call(ENVELOPE, w0=obj, timeout_s=60, max_insns=100_000_000)
    except Exception as e:
        print("envelope stopped:", type(e).__name__)
    print("\nlast instructions before the stop:")
    for a, x0, x1, x2 in hist:
        print(f"   {a:#x}  x0={x0:#x} x1={x1:#x} x2={x2:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
