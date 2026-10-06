#!/usr/bin/env python3
"""Drive the login/bootstrap SM at state 10 with a fabricated task object.

State 10 (0x7dc7860) does:
    x0 = ctx->[0x288];  if (!x0) -> exit
    x8 = x0->vtable;  blr x8[0x38]        (vtable[7])
    if (ret & 1) { ... x0->[0x88] ... blr x8[0x38] again ... 0x7b1cf34(x0) }

So: fabricate ctx + a task whose vtable[7] is a stub returning 1, set
ctx->state = 10, and call the SM.  Watch curl_easy_setopt and the stub.
"""
from __future__ import annotations

import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "scripts"))
sys.path.insert(0, HERE)

from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1   # noqa: E402

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

SM = 0x7DC7164
CURL_SETOPT = 0x6886498

MOV_W0_1_RET = struct.pack("<II", 0x52800002, 0xD65F03C0)


def main():
    t0 = time.time()
    print("[drive] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    print(f"[drive] up in {time.time()-t0:.1f}s", flush=True)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    print("[drive] registrars done", flush=True)

    # ---- watch curl ----------------------------------------------------
    seen = []

    def on_setopt(uc, c):
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        if opt == 10002:                       # CURLOPT_URL
            try:
                raw = bytes(uc.mem_read(val, 256))
            except Exception:
                raw = b""
            z = raw.find(b"\0")
            seen.append(raw[:z if z >= 0 else 256])
            print(f"    >>> CURLOPT_URL = {seen[-1]!r}", flush=True)
        else:
            seen.append((opt, val))

    core.watch(CURL_SETOPT, on_setopt, name="curl_easy_setopt")

    # ---- fabricate -----------------------------------------------------
    # executable arena for guest stubs (same trick as matchmain_run)
    EXEC_BASE = 0xA4000000000
    try:
        core.uc.mem_map(EXEC_BASE, 0x100000, 7)      # UC_PROT_ALL
    except Exception:
        pass
    stub = EXEC_BASE
    core.uc.mem_write(stub, MOV_W0_1_RET * 8)
    print(f"[drive] stub (mov w0,#1; ret) at {stub:#x}", flush=True)

    task_vt = core.alloc(0x100, b"\0" * 0x100, name="task_vt")
    task = core.alloc(0x200, b"\0" * 0x200, name="task")
    ctx = core.alloc(0x800, b"\0" * 0x800, name="login_ctx")

    core.write_u64(task_vt + 0x38, stub)          # vtable[7]
    core.write_u64(task, task_vt)                  # task->vtable
    core.write_u64(ctx + 0x288, task)              # ctx->task
    core.write_u32(ctx + 0x2a0, 10)                # ctx->state = 10

    print(f"[drive] ctx={ctx:#x} task={task:#x} vt={task_vt:#x}", flush=True)

    # ---- call the SM ---------------------------------------------------
    print("[drive] calling bootstrap_SM at state 10 ...", flush=True)
    try:
        r = core.call(SM, x0=ctx, timeout_s=60, max_insns=20_000_000)
        print(f"[drive] returned: {r}", flush=True)
    except Exception as e:
        print(f"[drive] exception: {type(e).__name__}: {e}", flush=True)

    print("\n" + "=" * 74)
    print("RESULT")
    print("=" * 74)
    print(f"  curl_easy_setopt calls: {len(seen)}")
    for s in seen[:12]:
        print(f"      {s!r}")

    print("\n  ctx after:")
    for off in (0x288, 0x2a0, 0x2a4, 0x2a8, 0x2aa, 0x2ab, 0x2ac,
                0x2ad, 0x2ae, 0x280):
        try:
            if off in (0x2a0, 0x2a4):
                v = core.safe_read_u32(ctx + off)
            else:
                v = core.safe_read(ctx + off, 1)[0]
            print(f"      ctx+{off:#06x} = {v}")
        except Exception:
            pass

    print("\n  harness log (last 20):")
    for line in getattr(core, "_log", [])[-20:]:
        print("   ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
