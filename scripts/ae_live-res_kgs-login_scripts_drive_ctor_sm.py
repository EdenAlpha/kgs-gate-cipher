#!/usr/bin/env python3
"""Construct a REAL command task with the game's own per-command ctor, run the
game's own state machine, and record the exact request curl is given.

Previously (drive_login_url) the task came back from FACTORY with empty
fields, so the state machine had nothing to do.  dump_cmdenv proved the
per-command ctor fills them:

    0x767f6e4  -> msgid "CMD_GET_SERVER_ENV", script "CmdGetServerEnv.php"
    0x76b12f8  -> CMD_LOGIN
    0x7db2404  -> CMD_CONNECT_GRPC  ("CmdConnectGrpc.php")

Hooks (observation only, nothing assembled by hand):
    CURLOPT_URL / POSTFIELDS / POSTFIELDSIZE / HTTPHEADER / method
    WRITEFUNCTION 0x7d04570        -> the server's response
"""
from __future__ import annotations

import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn.arm64_const import (                      # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

SETOPT = 0x6886498
WRITE_CB = 0x7D04570
POSTER = 0x7D04148
GETTER = 0x7D03B68
COMPOSER = 0x7B099D0
SM = 0x7DC7164
CREATE = 0x7CDA280
INIT_ARRAY = 0x98BD898
INIT_ARRAYSZ = 0x171A8

CURLOPT_URL, CURLOPT_POSTFIELDS, CURLOPT_POSTFIELDSIZE = 10002, 10015, 60
CURLOPT_HTTPHEADER, CURLOPT_POST, CURLOPT_HTTPGET = 10023, 47, 80
CURLOPT_CUSTOMREQUEST, CURLOPT_VERBOSE = 36, 41

CMDS = [
    ("CmdGetServerEnv", 0x767F6E4),
    ("CmdLogin", 0x76B12F8),
    ("CmdConnectGrpc", 0x7DB2404),
    ("CmdGetKgsGuestLoginToken", 0x7639388),
]

seen = {}


def reset():
    seen.clear()
    seen.update(url=None, body=None, hdrs=None, method=None,
                resp=bytearray(), events=[])


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def rd_str(core, addr):
    """read a libc++ short/long string (first byte = size<<1, LSB=1 -> long)"""
    try:
        b0 = bytes(core.uc.mem_read(addr, 1))[0]
        if b0 & 1:
            n = u64(core, addr + 8)
            p = u64(core, addr + 0x10)
            if n > 0x10000 or not p:
                return f"<long n={n}>"
            return bytes(core.uc.mem_read(p, n)).decode("utf-8", "replace")
        n = b0 >> 1
        return bytes(core.uc.mem_read(addr + 1, n)).decode("utf-8", "replace")
    except Exception as e:
        return f"<err {e}>"


def slist(core, head):
    out, p = [], head
    for _ in range(60):
        if not p:
            break
        try:
            data, nxt = u64(core, p), u64(core, p + 8)
        except Exception:
            break
        if not data:
            break
        out.append(bytes(core.uc.mem_read(data, 900)).split(b"\0")[0]
                   .decode("latin1", "replace"))
        p = nxt
    return out


def run_constructors(core):
    raw = bytes(core.uc.mem_read(core.base + INIT_ARRAY, INIT_ARRAYSZ))
    ok = 0
    for i in range(INIT_ARRAYSZ // 8):
        fn = struct.unpack_from("<Q", raw, 8 * i)[0] - core.base
        if not (0x1000 <= fn < 0x10000000):
            continue
        try:
            if not core.call(fn, timeout_s=20, max_insns=5_000_000)["error"]:
                ok += 1
        except Exception:
            pass
    return ok


def install_hooks(core):
    def on_setopt(uc, c):
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        try:
            if opt == CURLOPT_URL:
                seen["url"] = bytes(uc.mem_read(val, 600)).split(b"\0")[0] \
                    .decode("latin1", "replace")
                seen["events"].append("URL " + seen["url"])
                print("   [curl] URL    = %s" % seen["url"], flush=True)
            elif opt == CURLOPT_POSTFIELDS:
                seen["body"] = bytes(uc.mem_read(val, 300000))
                seen["events"].append("POSTFIELDS")
                print("   [curl] BODY   = %d bytes  peek=%r"
                      % (len(seen["body"]), seen["body"][:120]), flush=True)
            elif opt == CURLOPT_POSTFIELDSIZE:
                seen["events"].append("SIZE %s" % val)
                print("   [curl] SIZE   = %s" % val, flush=True)
            elif opt == CURLOPT_HTTPHEADER:
                seen["hdrs"] = slist(core, val)
                seen["events"].append("HEADERS")
                print("   [curl] HDRS   = %s" % seen["hdrs"], flush=True)
            elif opt == CURLOPT_POST:
                seen["method"] = "POST"
            elif opt == CURLOPT_HTTPGET:
                seen["method"] = "GET"
            elif opt == CURLOPT_CUSTOMREQUEST:
                seen["method"] = bytes(uc.mem_read(val, 32)).split(b"\0")[0] \
                    .decode("latin1", "replace")
            elif opt == CURLOPT_VERBOSE:
                uc.reg_write(UC_ARM64_REG_X2, 1)
        except Exception as e:
            print("   [curl] hook err %s" % e, flush=True)

    core.watch(SETOPT, on_setopt, name="setopt")

    def on_write(uc, c):
        p = uc.reg_read(UC_ARM64_REG_X0)
        sz = uc.reg_read(UC_ARM64_REG_X1)
        nm = uc.reg_read(UC_ARM64_REG_X2)
        n = sz * nm
        if 0 < n < 2_000_000:
            try:
                seen["resp"] += uc.mem_read(p, n)
            except Exception:
                pass

    core.watch(WRITE_CB, on_write, name="write")

    def tag(name):
        def f(uc, c):
            seen["events"].append(name)
            print("   [game] %s entered" % name, flush=True)
        return f

    core.watch(POSTER, tag("POST sender"), name="poster")
    core.watch(GETTER, tag("GET sender"), name="getter")
    core.watch(COMPOSER, tag("composer"), name="composer")


def dump(tag):
    print("\n   ===== %s =====" % tag, flush=True)
    print("     method = %s" % seen.get("method"), flush=True)
    print("     url    = %s" % seen.get("url"), flush=True)
    print("     hdrs   = %s" % (seen.get("hdrs") or []), flush=True)
    b = seen.get("body")
    print("     body   = %s bytes" % (len(b) if b else None), flush=True)
    if b:
        print("       raw  = %r" % b[:800], flush=True)
        try:
            print("       text = %s" % b.decode("utf-8")[:800], flush=True)
        except Exception:
            pass
    r = bytes(seen.get("resp") or b"")
    print("     resp   = %d bytes %r" % (len(r), r[:600]), flush=True)
    print("     events = %s" % seen.get("events"), flush=True)


def main() -> int:
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    print("[drv] constructors ok=%d" % run_constructors(core), flush=True)
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(CREATE, timeout_s=60)
    install_hooks(core)

    only = sys.argv[1] if len(sys.argv) > 1 else None
    for name, ctor in CMDS:
        if only and only not in name:
            continue
        reset()
        obj = core.alloc(0x1000, b"\0" * 0x1000, name="cmd")
        try:
            r = core.call(ctor, w0=obj, timeout_s=60,
                          max_insns=100_000_000)
        except Exception as e:
            print("\n[drv] %s ctor CALL %s" % (name, type(e).__name__),
                  flush=True)
            continue
        if r["error"]:
            print("\n[drv] %s ctor fault %s pc=%#x"
                  % (name, r["error"], r["pc"]), flush=True)
            continue
        msgid = rd_str(core, obj + 0x138)
        script = rd_str(core, obj + 0x170)
        print("\n[drv] %s: msgid=%r script=%r vt=%#x"
              % (name, msgid, script, u64(core, obj)), flush=True)
        n0 = len(getattr(core, "_log", []))

        core.write_u8(obj + 0xF8, 1)
        ctx = core.alloc(0x1000, b"\0" * 0x1000, name="ctx")
        core.write_u64(ctx + 0x288, obj)
        core.write_u32(ctx + 0x2A0, 10)
        t0 = time.time()
        try:
            rr = core.call(SM, x0=ctx, timeout_s=240,
                           max_insns=200_000_000)
            if rr["error"]:
                try:
                    from unicorn.arm64_const import UC_ARM64_REG_LR
                    lr = core.uc.reg_read(UC_ARM64_REG_LR)
                except Exception:
                    lr = 0
                print("[drv]   SM -> err=%s pc=%#x lr=%#x x0=%#x (%.1fs)"
                      % (rr["error"], rr["pc"], lr, rr["x0"],
                         time.time() - t0), flush=True)
            else:
                print("[drv]   SM -> ok x0=%#x (%.1fs)"
                      % (rr["x0"], time.time() - t0), flush=True)
            for line in getattr(core, "_log", [])[n0:]:
                print("       %s" % line[:200], flush=True)
        except Exception as e:
            print("[drv]   SM -> %s %s" % (type(e).__name__, str(e)[:80]),
                  flush=True)
        dump(name)
    print("\n[drv] done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
