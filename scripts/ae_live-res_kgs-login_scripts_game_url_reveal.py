#!/usr/bin/env python3
"""Let the GAME build its own login request and print the URL it composes.

The missing ingredient was the game's static constructors (11,824 of 11,829
run clean) -- the thing Android's linker does at startup and we skipped.
Every earlier attempt to drive the bootstrap got zero curl calls because
the request registries were never built.

  1. run .init_array (the game's own global registries)
  2. run the online-config registrars
  3. hook the URL composer (0x7b099d0) and curl_easy_setopt(CURLOPT_URL)
  4. drive the bootstrap state machine 0x7dc7164 through its states

Every byte of the URL then comes from the game.  We print, never guess.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn.arm64_const import (                      # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

COMPOSER = 0x7B099D0
SETOPT = 0x6886498
SETURL = 0x7B2E334          # attaches url+body to the request object
SM = 0x7DC7164
CREATE = 0x7CDA280
INIT_ARRAY = 0x98BD898
INIT_ARRAYSZ = 0x171A8


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def rd_str(core, addr):
    try:
        b0 = bytes(core.uc.mem_read(addr, 1))[0]
        if b0 & 1:
            n = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 8, 8)))[0]
            p = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 0x10, 8)))[0]
            if n > 0x4000 or not p:
                return f"<long n={n}>"
            return bytes(core.uc.mem_read(p, n)).decode("utf-8", "replace")
        n = b0 >> 1
        return bytes(core.uc.mem_read(addr + 1, n)).decode("utf-8", "replace")
    except Exception as e:
        return f"<err {e}>"


def run_constructors(core, limit=20000) -> int:
    B = core.base
    raw = bytes(core.uc.mem_read(B + INIT_ARRAY, INIT_ARRAYSZ))
    n = INIT_ARRAYSZ // 8
    ok = 0
    for i in range(min(n, limit)):
        fn = struct.unpack_from("<Q", raw, 8 * i)[0] - B
        if not (0x1000 <= fn < 0x10000000):
            continue
        try:
            r = core.call(fn, timeout_s=20, max_insns=5_000_000)
            if not r["error"]:
                ok += 1
        except Exception:
            pass
    return ok


def main() -> int:
    print("[reveal] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    print("[reveal] running the game's static constructors ...", flush=True)
    ok = run_constructors(core)
    print(f"[reveal] constructors ok={ok}", flush=True)

    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(CREATE, timeout_s=60)
    B = core.base

    found = []

    def on_composer(uc, c):
        a = uc.reg_read(UC_ARM64_REG_X1)
        b = uc.reg_read(UC_ARM64_REG_X2)
        sa, sb = rd_str(core, a), rd_str(core, b)
        print(f"\n[reveal] *** COMPOSER a={sa!r} b={sb!r}", flush=True)
        found.append(("composer", sa, sb))

    core.watch(COMPOSER, on_composer, name="composer")

    def on_seturl(uc, c):
        url = uc.reg_read(UC_ARM64_REG_X1)
        size = uc.reg_read(UC_ARM64_REG_X2)
        data = uc.reg_read(UC_ARM64_REG_X3)
        u = rd_str(core, url)
        body = b""
        try:
            body = bytes(core.uc.mem_read(data, min(size, 256))) if data else b""
        except Exception:
            pass
        print(f"[reveal] *** REQUEST url={u!r} body_len={size} "
              f"body={body[:80].hex()}", flush=True)
        found.append(("request", u, body[:80]))

    core.watch(SETURL, on_seturl, name="seturl")

    def on_setopt(uc, c):
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        if opt == 10002:
            try:
                u = bytes(uc.mem_read(val, 400)).split(b"\0")[0]
            except Exception:
                u = b"?"
            print(f"[reveal] *** CURLOPT_URL = {u!r}", flush=True)
            found.append(("curl", u.decode("utf-8", "replace"), b""))

    core.watch(SETOPT, on_setopt, name="setopt")

    # ---- drive the game's own bootstrap state machine -------------------
    ctx = core.alloc(0x1000, b"\0" * 0x1000, name="ctx")
    core.write_u64(ctx + 0x288, 0)
    print("\n[reveal] driving the bootstrap state machine ...", flush=True)
    for state in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11):
        core.write_u32(ctx + 0x2A0, state)
        try:
            r = core.call(SM, x0=ctx, timeout_s=90, max_insns=80_000_000)
            st2 = core.safe_read_u32(ctx + 0x2A0)
            tk = core.safe_read_u64(ctx + 0x288)
            print(f"    state {state:2d} -> err={r['error']} x0={r['x0']:#x} "
                  f"now={st2} task={tk:#x}", flush=True)
        except Exception as e:
            print(f"    state {state:2d} -> {type(e).__name__}: "
                  f"{str(e)[:60]}", flush=True)
        if found:
            break

    print("\n[reveal] ==== the game's own request ====", flush=True)
    if not found:
        print("    (nothing composed -- the bootstrap never reached the "
              "request stage)", flush=True)
    for kind, a, b in found:
        print(f"    {kind:9s} {a!r}  {b if isinstance(b, (bytes,)) else ''!r}",
              flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
