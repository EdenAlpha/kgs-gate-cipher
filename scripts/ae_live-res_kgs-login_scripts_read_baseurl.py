#!/usr/bin/env python3
"""Read the game's own CmdGetServerEnv base URL straight out of emulated
memory. The builder (0x767eaf0) does:

    adrp x10, #0xa00000 ; add x10, x10, #0x26e   -> "CmdGetServerEnv.php"
    adrp x10, #0x97d4000; add x10, x10, #0x448   -> the BASE (a static)
    ...
    ldr  x10, [0xb42c54]                          -> the HOST (env note)

So base + path + host are all just memory. No protocol to reverse.
"""
from __future__ import annotations

import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "scripts"))
sys.path.insert(0, HERE)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

BASE_OBJ = 0x97D4448
BASE_ALT = 0x97A2600
HOST_PTR = 0xB42C54


def cstr(core, addr, n=256):
    if not addr:
        return None
    try:
        b = bytes(core.uc.mem_read(addr, n))
    except Exception:
        return None
    i = b.find(b"\0")
    return b[:i if i >= 0 else n]


def dump_region(core, label, center, before=0x80, after=0x180):
    print(f"\n--- {label} around {center:#x} ---")
    lo = center - before
    try:
        raw = bytes(core.uc.mem_read(lo, before + after))
    except Exception as e:
        print(f"    unreadable: {type(e).__name__}")
        return
    # print qwords, annotating strings
    for off in range(0, len(raw), 8):
        at = lo + off
        v = struct.unpack_from("<Q", raw, off)[0]
        sel = " >>" if at == center else "   "
        # try to interpret as a string pointer
        tag = ""
        if core.base <= v < core.base + 0x100000000:
            off2 = v - core.base
            s = cstr(core, v, 64)
            if s and len(s) >= 4 and all(31 <= c < 127 for c in s):
                tag = f"  -> str {s.decode('latin1')!r}"
            elif 0x9000000 <= off2 < 0xA000000 or 0xB00000 <= off2 < 0xC00000:
                tag = f"  -> data+{off2:#x}"
            else:
                tag = f"  -> {off2:#x}"
        elif v == 0:
            tag = "  (null)"
        else:
            tag = f"  ({v:#x})"
        print(f"  {sel} {at:#x}: {v:#018x}{tag}")


def main():
    t0 = time.time()
    print("[url] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    print(f"[url] up in {time.time()-t0:.1f}s base={core.base:#x}", flush=True)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    print("[url] registrars done", flush=True)

    B = core.base

    print("\n" + "=" * 74)
    print("THE GAME'S OWN CmdGetServerEnv BASE URL")
    print("=" * 74)

    for label, addr in (("BASE_OBJ 0x97d4448", BASE_OBJ),
                        ("BASE_ALT 0x97a2600", BASE_ALT)):
        s = cstr(core, B + addr)
        print(f"\n  {label} as C-string: {s!r}")

    # walk the object's fields as strings
    print(f"\n  fields of BASE_OBJ (0x97d4448) as strings:")
    for off in range(0, 0x100, 8):
        a = BASE_OBJ + off
        s = cstr(core, B + a, 64)
        if s and len(s) >= 3 and all(31 <= c < 127 for c in s):
            print(f"      +{off:#04x}: {s.decode('latin1')!r}")

    print("\n" + "=" * 74)
    print("HOST POINTER @ 0xb42c54")
    print("=" * 74)
    try:
        v = struct.unpack("<Q", bytes(core.uc.mem_read(B + HOST_PTR, 8)))[0]
        print(f"  *(0xb42c54) = {v:#x}")
        if B <= v < B + 0x100000000:
            s = cstr(core, v)
            print(f"  as string: {s!r}")
        dump_region(core, "HOST_PTR", B + HOST_PTR, 0x40, 0x80)
    except Exception as e:
        print(f"  unreadable: {e}")

    # env table again
    print("\n" + "=" * 74)
    print("ENV TABLE 0xa4cff68 (re-check)")
    print("=" * 74)
    for i in range(4):
        e = 0xA4CFF68 + i * 0x40
        try:
            raw = bytes(core.uc.mem_read(B + e, 0x40))
        except Exception as ex:
            print(f"  [{i}] unreadable {type(ex).__name__}")
            continue
        sp = struct.unpack_from("<Q", raw, 0x30)[0]
        s = cstr(core, sp) if sp else None
        nz = sum(1 for b in raw if b)
        print(f"  [{i}] nonzero={nz:2d} flag={raw[0x2C]:#04x} "
              f"str@{sp:#x}={s!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
