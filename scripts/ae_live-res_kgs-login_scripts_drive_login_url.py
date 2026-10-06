#!/usr/bin/env python3
"""THE decisive experiment: make the game build its own request and print
the URL it composes.

We have never actually seen the URL the app uses -- we inferred it.  Hook the
game's own URL composer (0x7b099d0) and curl_easy_setopt(CURLOPT_URL) and
drive the game's own task machinery, so `a` comes from the game, not us.

Also runs the game's 11,829 static constructors first (.init_array), which
is what Android's linker does and what we were skipping.
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
FACTORY = 0x7DC91D8
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
    ok = fail = 0
    for i in range(min(n, limit)):
        fn = struct.unpack_from("<Q", raw, 8 * i)[0] - B
        if not (0x1000 <= fn < 0x10000000):
            continue
        try:
            r = core.call(fn, timeout_s=20, max_insns=5_000_000)
            if r["error"]:
                fail += 1
            else:
                ok += 1
        except Exception:
            fail += 1
    return ok


def main() -> int:
    print("[url] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    print("[url] running static constructors (the missing startup step) ...",
          flush=True)
    ok = run_constructors(core)
    print(f"[url] constructors ok={ok}", flush=True)

    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(CREATE, timeout_s=60)
    B = core.base

    # ---- watch the composer and curl's URL setting ----------------------
    def on_composer(uc, c):
        a = uc.reg_read(UC_ARM64_REG_X1)
        b = uc.reg_read(UC_ARM64_REG_X2)
        print(f"\n[url] *** COMPOSER called with a={rd_str(core, a)!r} "
              f"b={rd_str(core, b)!r}", flush=True)

    core.watch(COMPOSER, on_composer, name="composer")

    def on_setopt(uc, c):
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        if opt == 10002:
            try:
                u = bytes(uc.mem_read(val, 400)).split(b"\0")[0]
            except Exception:
                u = b"?"
            print(f"[url] *** CURLOPT_URL = {u!r}", flush=True)

    core.watch(SETOPT, on_setopt, name="setopt")

    # ---- drive the game's own task machinery ----------------------------
    for taskname in (b"CmdLogin", b"CmdGetServerEnv", b"CmdGetKgsGuestLoginToken"):
        name = core.alloc(64, taskname + b"\0", name="tn")
        r = core.call(FACTORY, name, 0, 0, 0, 0, timeout_s=60,
                      max_insns=20_000_000)
        task = r.get("x0")
        print(f"\n[url] ---- task {taskname!r} = {task and hex(task)} "
              f"err={r.get('error')}", flush=True)
        if not task:
            continue
        print(f"      task+0x70  (candidate `a`) = {rd_str(core, task + 0x70)!r}",
              flush=True)
        print(f"      task+0x138 (msgid)         = {rd_str(core, task + 0x138)!r}",
              flush=True)
        print(f"      task+0x170 (script)        = {rd_str(core, task + 0x170)!r}",
              flush=True)

        core.write_u8(task + 0xF8, 1)          # mark ready
        ctx = core.alloc(0x1000, b"\0" * 0x1000, name="ctx")
        core.write_u64(ctx + 0x288, task)
        core.write_u32(ctx + 0x2A0, 10)
        try:
            r = core.call(SM, x0=ctx, timeout_s=120, max_insns=60_000_000)
            print(f"      SM -> err={r['error']} x0={r['x0']:#x}", flush=True)
        except Exception as e:
            print(f"      SM -> {type(e).__name__}: {str(e)[:60]}", flush=True)

    print("\n[url] done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
