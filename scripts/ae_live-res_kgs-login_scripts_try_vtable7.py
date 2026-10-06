#!/usr/bin/env python3
"""Try each candidate game function as the task's vtable[7] and see which one
makes the game's own HTTP stack fire (curl_easy_setopt).

The SM calls task->vtable[7](task) and continues only if (ret & 1).
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
EXEC_BASE = 0xA4000000000

CANDIDATES = {
    "http_post_routine 0x7d038c8": 0x7D038C8,
    "gateinfo_sender   0x7d0c06c": 0x7D0C06C,
    "http_post_parent  0x7d015b0": 0x7D015B0,
    "http_grandparent  0x7ce7070": 0x7CE7070,
    "http_alt          0x7d157f8": 0x7D157F8,
    "gateinfo_parent   0x7d0bda8": 0x7D0BDA8,
}


def main():
    for label, fn in CANDIDATES.items():
        print("\n" + "#" * 74)
        print(f"# vtable[7] = {label}")
        print("#" * 74)
        core = OnlineCore(verbose=False)
        core.install_netsplice()
        for r in REGISTRARS:
            try:
                core.call(r)
            except Exception:
                pass

        urls = []

        def on_setopt(uc, c):
            opt = uc.reg_read(UC_ARM64_REG_X1)
            val = uc.reg_read(UC_ARM64_REG_X2)
            if opt == 10002:
                try:
                    raw = bytes(uc.mem_read(val, 256))
                except Exception:
                    raw = b""
                z = raw.find(b"\0")
                urls.append(raw[:z if z >= 0 else 256])

        core.watch(CURL_SETOPT, on_setopt, name="curl_easy_setopt")

        try:
            core.uc.mem_map(EXEC_BASE, 0x100000, 7)
        except Exception:
            pass

        task_vt = core.alloc(0x100, b"\0" * 0x100, name="task_vt")
        task = core.alloc(0x200, b"\0" * 0x200, name="task")
        ctx = core.alloc(0x800, b"\0" * 0x800, name="ctx")
        core.write_u64(task_vt + 0x38, core.base + fn)
        core.write_u64(task, task_vt)
        core.write_u64(ctx + 0x288, task)
        core.write_u32(ctx + 0x2a0, 10)

        try:
            r = core.call(SM, x0=ctx, timeout_s=30, max_insns=10_000_000)
            res = f"err={r['error']} x0={r['x0']:#x}"
        except Exception as e:
            res = f"EXC {type(e).__name__}: {str(e)[:60]}"

        print(f"  SM result : {res}")
        print(f"  curl URLs : {len(urls)}")
        for u in urls[:4]:
            print(f"      {u!r}")
        if not urls:
            # did it at least reach the task?  check ctx->[0x288]
            try:
                t = core.safe_read_u64(ctx + 0x288)
                st = core.safe_read_u32(ctx + 0x2a0)
                print(f"  ctx->task={t:#x} ctx->state={st}")
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
