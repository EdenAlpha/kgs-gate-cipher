#!/usr/bin/env python3
"""Construct the game's own CmdGetServerEnv command object and list its
methods.

  0x767f6e4  ctor: builds the object, stamps it with
             "CMD_GET_SERVER_ENV" (0xaf6dad) and "CmdGetServerEnv.php"
             (0xa0026e), and points obj+0 at *(0x98dea98)+0x10 -- the
             runtime vtable the loader fills in.

Reading that vtable back out tells us which routine actually builds and
sends the command, the same way 0x7d0c06c did for GateInfo.
"""
from __future__ import annotations

import bisect
import os
import re
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

CTOR = 0x767F6E4
CTOR_SMALL = 0x767EAF0

_FDE = []
_FDE_START = []


def load_fde():
    global _FDE, _FDE_START
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "funcs_eh.txt"), encoding="utf-8") as f:
        for line in f:
            p = line.split()
            if len(p) >= 2:
                _FDE.append((int(p[0], 16), int(p[1], 16)))
    _FDE_START = [a for a, _ in _FDE]


def fn_of(addr):
    if not _FDE:
        load_fde()
    i = bisect.bisect_right(_FDE_START, addr) - 1
    if i >= 0 and _FDE[i][0] <= addr < _FDE[i][1]:
        return _FDE[i][0]
    return None


def dump_vtable(core, vt, tag, slots=48):
    print(f"\n  --- {tag}: vtable @ {vt:#x} ---", flush=True)
    for i in range(slots):
        p = struct.unpack("<Q", bytes(core.uc.mem_read(vt + i * 8, 8)))[0]
        if p == 0:
            continue
        if core.base <= p < core.base + 0x10000000:
            off = p - core.base
            f = fn_of(off)
            tag2 = f"fn {f:#x}" if f else f"off {off:#x}"
        else:
            tag2 = f"raw {p:#x}"
        print(f"    [{i:2d}] {p:#x}   {tag2}", flush=True)


def show_str(core, addr, n=64):
    try:
        b = bytes(core.uc.mem_read(addr, n))
        return b.split(b"\0")[0]
    except Exception:
        return b"<unreadable>"


def main():
    print("[cmd] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    B = core.base

    g = struct.unpack("<Q", bytes(core.uc.mem_read(B + 0x98DEA98, 8)))[0]
    print(f"[cmd] *(0x98dea98) = {g:#x}   -> vtable {g + 0x10:#x}" if g
          else "[cmd] *(0x98dea98) = 0  (not populated)", flush=True)

    obj = core.alloc(0x1000, b"\0" * 0x1000, name="cmdenv")
    print(f"[cmd] calling ctor 0x{CTOR:x}(obj={obj:#x}) ...", flush=True)
    r = core.call(CTOR, w0=obj, timeout_s=60, max_insns=100_000_000)
    print(f"[cmd]   -> x0={r['x0']:#x} err={r['error']} pc={r['pc']:#x}",
          flush=True)
    if r["error"]:
        print("[cmd] ctor faulted -- stop", flush=True)
        return 1

    vt = struct.unpack("<Q", bytes(core.uc.mem_read(obj, 8)))[0]
    print(f"[cmd] obj+0 (vptr) = {vt:#x}", flush=True)
    print(f"[cmd] obj+0x108    = {show_str(core, obj + 0x100, 48)!r}",
          flush=True)
    print(f"[cmd] obj+0x138    = {show_str(core, obj + 0x138, 48)!r}",
          flush=True)
    print(f"[cmd] obj+0x170    = {show_str(core, obj + 0x170, 48)!r}",
          flush=True)
    print(f"[cmd] obj+0x991    = {show_str(core, obj + 0x991, 48)!r}",
          flush=True)

    if vt:
        dump_vtable(core, vt, "dynamic vptr from obj+0")

    # the ctor also stores the static table 0x97a2600 before overwriting it
    dump_vtable(core, B + 0x97A2600, "static table 0x97a2600")

    if g:
        dump_vtable(core, g + 0x10, "*(0x98dea98)+0x10")

    # small sibling
    obj2 = core.alloc(0x400, b"\0" * 0x400, name="cmdenv_small")
    r2 = core.call(CTOR_SMALL, w0=obj2, timeout_s=60,
                   max_insns=100_000_000)
    print(f"\n[cmd] small ctor 0x{CTOR_SMALL:x} -> err={r2['error']}",
          flush=True)
    if not r2["error"]:
        vt2 = struct.unpack("<Q", bytes(core.uc.mem_read(obj2, 8)))[0]
        print(f"[cmd] small obj+0 = {vt2:#x}", flush=True)
        print(f"[cmd] small +0x138 = {show_str(core, obj2 + 0x138, 48)!r}",
              flush=True)
        if vt2:
            dump_vtable(core, vt2, "small vptr")
    return 0


if __name__ == "__main__":
    sys.exit(main())
