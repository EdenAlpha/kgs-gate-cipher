#!/usr/bin/env python3
"""Read the REAL `a` (the gate service name) straight off a task object the
game itself constructed, then run the game's own composer on it.

No guessing: the task comes from the game's factory, `a` comes from the
object, the URL comes from the composer.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

FACTORY = 0x7DC91D8
COMPOSER = 0x7B099D0
CTOR_ENV = 0x767EAF0


def mk_str(core, text: bytes) -> int:
    buf = bytearray(32)
    if len(text) <= 22:
        buf[0] = len(text) << 1
        buf[1:1 + len(text)] = text
    else:
        buf[0] = 1
        struct.pack_into("<Q", buf, 8, len(text))
        ptr = core.alloc(len(text) + 1, text + b"\0", name="cstr")
        struct.pack_into("<Q", buf, 0x10, ptr)
    return core.alloc(32, bytes(buf), name="str")


def rd_str(core, addr) -> str | None:
    """Read a libc++ std::string at addr; return None if it doesn't look one."""
    try:
        b0 = bytes(core.uc.mem_read(addr, 1))[0]
    except Exception:
        return None
    try:
        if b0 & 1:
            size = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 8, 8)))[0]
            ptr = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 0x10, 8)))[0]
            if size > 0x2000 or ptr == 0:
                return None
            return bytes(core.uc.mem_read(ptr, size)).decode("utf-8", "replace")
        n = b0 >> 1
        return bytes(core.uc.mem_read(addr + 1, n)).decode("utf-8", "replace")
    except Exception:
        return None


def u64(core, a):
    try:
        return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]
    except Exception:
        return 0


def main() -> int:
    print("[a] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[a] booted", flush=True)

    B = core.base

    # ---- 1. what lives in the ApiManager-type globals? ---------------
    print("\n[a] scanning static string fields named in the +0x70 writer:",
          flush=True)
    for g in (0xA4A8240, 0xA4A8000, 0xA4B0140, 0xA4B0218):
        v = u64(core, B + g)
        print(f"    *(base+{g:#x}) = {v:#x}", flush=True)

    # ---- 2. a real task from the game's own factory -------------------
    name = core.alloc(64, b"CmdGetServerEnv\0", name="taskname")
    r = core.call(FACTORY, name, 0, 0, 0, 0, timeout_s=60,
                  max_insns=20_000_000)
    task = r.get("x0")
    print(f"\n[a] factory task={task and hex(task)} err={r.get('error')}",
          flush=True)

    candidates = []
    if task:
        print("[a] ---- string-ish fields on the task ----", flush=True)
        for off in range(0, 0x400, 8):
            s = rd_str(core, task + off)
            if s:
                print(f"    task+{off:#06x} = {s!r}", flush=True)
                candidates.append((f"task+{off:#x}", s))
        # indirect: many callers read *(obj+0x178) then take +0x70
        for off in (0x170, 0x178, 0x180, 0x48, 0x68):
            p = u64(core, task + off)
            if not p:
                continue
            print(f"\n[a] *(task+{off:#x}) = {p:#x}", flush=True)
            s = rd_str(core, p + 0x70)
            if s:
                print(f"      -> obj+0x70 = {s!r}", flush=True)
                candidates.append((f"*(task+{off:#x})+0x70", s))
            for sub in (0x0, 0x8, 0x10, 0x68, 0x70, 0x78):
                s2 = rd_str(core, p + sub)
                if s2:
                    print(f"      -> obj+{sub:#x} = {s2!r}", flush=True)
                    candidates.append((f"*(task+{off:#x})+{sub:#x}", s2))

    # ---- 3. also build a raw command object via its ctor ---------------
    obj = core.alloc(0x4000, b"\0" * 0x4000, name="cmdobj")
    r2 = core.call(CTOR_ENV, w0=obj, timeout_s=60,
                   max_insns=400_000_000)
    print(f"\n[a] ctor object obj={obj:#x} err={r2.get('error')}", flush=True)
    for off in (0x70, 0x170, 0x178, 0x180):
        s = rd_str(core, obj + off)
        if s:
            print(f"    obj+{off:#x} = {s!r}", flush=True)
            candidates.append((f"obj+{off:#x}", s))
    p = u64(core, obj + 0x178)
    if p:
        s = rd_str(core, p + 0x70)
        print(f"    *(obj+0x178)={p:#x} +0x70 = {s!r}", flush=True)
        if s:
            candidates.append(("*(obj+0x178)+0x70", s))

    # ---- 4. run the game's composer on every real candidate ------------
    seen = set()
    print("\n[a] ---- composer output for each REAL value of a ----",
          flush=True)
    for src, val in candidates:
        if val in seen:
            continue
        seen.add(val)
        out = core.alloc(64, b"\0" * 64, name="out")
        sa = mk_str(core, val.encode())
        sb = mk_str(core, b"")
        try:
            rr = core.call(COMPOSER, w0=out, x1=sa, x2=sb,
                           timeout_s=60, max_insns=200_000_000)
        except Exception as e:
            print(f"    {src}: {val!r} -> EXC {e}", flush=True)
            continue
        if rr["error"]:
            print(f"    {src}: {val!r} -> err {rr['error']}", flush=True)
            continue
        print(f"    {src}: {val!r}", flush=True)
        print(f"        -> {rd_str(core, out)!r}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
