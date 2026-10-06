#!/usr/bin/env python3
"""After the registrars run, is the env table (0xa4cff68) populated?
And what does the command dispatcher 0x767cecc actually do?
"""
from __future__ import annotations

import os
import struct
import sys
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "scripts"))
sys.path.insert(0, HERE)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

ENV_TABLE = 0xA4CFF68
ENV_ESZ = 0x40            # entry size: flag @+0x2C, std::string @+0x30
CFG_BLOCK = 0xA4B0188


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
    t0 = time.time()
    print("[env] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    print(f"[env] up in {time.time()-t0:.1f}s", flush=True)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    print("[env] registrars done\n", flush=True)

    B = core.base

    # ---- env table -----------------------------------------------------
    print("=" * 74)
    print(f"ENV TABLE @ {ENV_TABLE:#x}  (4 entries x {ENV_ESZ:#x} bytes)")
    print("=" * 74)
    for i in range(4):
        e = ENV_TABLE + i * ENV_ESZ
        try:
            raw = bytes(core.uc.mem_read(B + e, ENV_ESZ))
        except Exception as ex:
            print(f"  [{i}] UNREADABLE at {e:#x}: {type(ex).__name__}")
            continue
        print(f"  [{i}] len={len(raw)}")
        if len(raw) < 32:
            print(f"       SHORT: {raw.hex(' ')}")
            continue
        flag = raw[0x2C]
        sptr = struct.unpack_from("<Q", raw, 0x30)[0]
        s = cstr(core, sptr) if sptr else None
        print(f"  [{i}] flag={flag:#04x} str@{sptr:#x} = {s!r}")
        print(f"       raw: {raw.hex(' ')}")

    # ---- config block --------------------------------------------------
    print("\n" + "=" * 74)
    print(f"CONFIG BLOCK @ {CFG_BLOCK:#x}")
    print("=" * 74)
    data = bytes(core.uc.mem_read(B + CFG_BLOCK, 0x400))
    off = 0
    while off < len(data) - 24:
        b = data[off]
        if 0 < b <= 44 and b % 2 == 0:
            ln = b >> 1
            s = data[off + 1:off + 1 + ln]
            try:
                t = s.decode("utf8")
                if all(31 < ord(c) < 127 for c in t):
                    print(f"  cfg+{off:#06x}: {t!r}")
            except Exception:
                pass
        off += 8

    # ---- disassemble the dispatcher + builder --------------------------
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for label, vaddr, n in (("DISPATCHER 0x767cecc", 0x767CECC, 0x58),
                             ("BUILDER 0x767eaf0", 0x767EAF0, 0x170)):
        print("\n" + "=" * 74)
        print(label)
        print("=" * 74)
        with open(os.path.join(HERE, "apk_lab", "libUE4.so"), "rb") as f:
            f.seek(vaddr - 0x4000)
            code = f.read(n)
        for ins in md.disasm(code, vaddr):
            print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
