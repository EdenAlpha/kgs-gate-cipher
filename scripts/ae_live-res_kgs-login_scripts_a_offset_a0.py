#!/usr/bin/env python3
"""`a` = std::string at obj+0xa0  (proven from the call chain):

    0x7afe42c(a0=self, x1=obj)
        x9 = x1 + 0x30
        0x7afd364(self, x1=x9, x2=obj+0x3e4)
            0x7afd454  x1 = arg1 + 0x70      ->  obj + 0x30 + 0x70
            0x7afd468  bl 0x7b099d0          ->  compose gate URL

So `a` is the string at obj+0xa0.  Read it off every real object and build
the URL with the game's own composer.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

CTOR = 0x767EAF0
FACTORY = 0x7DC91D8
COMPOSER = 0x7B099D0
CREATE = 0x7CDA280


def u64(core, a):
    try:
        return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]
    except Exception:
        return 0


def rd_str(core, addr):
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


def mk_str(core, t: bytes) -> int:
    buf = bytearray(32)
    if len(t) <= 22:
        buf[0] = len(t) << 1
        buf[1:1 + len(t)] = t
    else:
        buf[0] = 1
        struct.pack_into("<Q", buf, 8, len(t))
        ptr = core.alloc(len(t) + 1, t + b"\0", name="cstr")
        struct.pack_into("<Q", buf, 0x10, ptr)
    return core.alloc(32, bytes(buf), name="str")


def build_url(core, a: str) -> str | None:
    out = core.alloc(64, b"\0" * 64, name="out")
    try:
        core.call(COMPOSER, w0=out, x1=mk_str(core, a.encode()),
                  x2=mk_str(core, b""), timeout_s=60,
                  max_insns=200_000_000)
    except Exception:
        return None
    return rd_str(core, out)


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(CREATE, timeout_s=60)

    obj = core.alloc(0x4000, b"\0" * 0x4000, name="cmd")
    r = core.call(CTOR, w0=obj, timeout_s=180, max_insns=400_000_000)
    print(f"[a] cmd object = {obj:#x} err={r['error']}", flush=True)
    for off in (0x30, 0x70, 0xA0, 0x138, 0x170, 0x3E4, 0x414):
        print(f"    +{off:#06x} = {rd_str(core, obj + off)!r}", flush=True)

    print("\n[a] === `a` is obj+0xa0 ===", flush=True)
    for label, o in (("cmdobj", obj),):
        a = rd_str(core, o + 0xA0)
        print(f"  {label}+0xa0 = {a!r}", flush=True)
        if a:
            print(f"     -> URL {build_url(core, a)!r}", flush=True)

    # now every command name the game can run, through its own composer
    print("\n[a] === URLs for every command name the binary contains ===",
          flush=True)
    data = open(r"C:\Users\Administrator\Documents\Default Project"
                r"\peerlink-efootball-disconnects\efootball-apk\native\lib"
                r"\arm64-v8a\libUE4.so", "rb").read()
    import re
    names = sorted({m.group(0).decode()
                    for m in re.finditer(rb"CMD_[A-Z][A-Z0-9_]{2,60}", data)})
    for n in ("CMD_LOGIN", "CMD_GET_SERVER_ENV", "CMD_GET_KGS_GUEST_LOGIN_TOKEN",
              "CMD_CREATEJOIN_ROOM", "CMD_GET_GAME_ID"):
        url = build_url(core, n)
        print(f"  a={n:36s} -> {url}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
