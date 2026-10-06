#!/usr/bin/env python3
"""Send the game's own body through the game's own HTTP stack.

We have:
  * the body  — produced earlier by the game's own serializer
                (0x767edbc, confirmed as vtable slot [4] after LIEF recovered
                1.33M Android packed relocations)
  * the URL   — produced by the game's own composer (0x7b099d0)
  * the send  — the game's own POST sender (subreq vtable[3], 0x7d03c68)

Every byte on the wire comes from the game's own code.
We watch curl_easy_setopt + WRITEFUNCTION to see exactly what the game does.
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
    UC_ARM64_REG_X1, UC_ARM64_REG_X2,
)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402
from peerlink.game_http import GameHttp                  # noqa: E402

COMPOSER = 0x7B099D0
SETOPT = 0x6886498

OPT_NAME = {3: "PORT", 41: "VERBOSE", 60: "POSTFIELDSIZE",
            10001: "WRITEDATA", 10002: "URL", 10015: "POSTFIELDS",
            10023: "HTTPHEADER", 20011: "WRITEFUNCTION",
            20094: "HEADERFUNCTION", 0x271A: "ERRORBUFFER"}


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def i32(core, a):
    return struct.unpack("<i", bytes(core.uc.mem_read(a, 4)))[0]


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


def rd_str(core, addr):
    try:
        b0 = bytes(core.uc.mem_read(addr, 1))[0]
        if b0 & 1:
            size = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 8, 8)))[0]
            ptr = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 0x10, 8)))[0]
            if size > 0x4000 or ptr == 0:
                return "<long>"
            return bytes(core.uc.mem_read(ptr, size)).decode("utf-8", "replace")
        return bytes(core.uc.mem_read(addr + 1, b0 >> 1)).decode("utf-8",
                                                                 "replace")
    except Exception as e:
        return "<err %s>" % e


def walk_slist(core, ptr, limit=24):
    out = []
    for _ in range(limit):
        if not ptr:
            break
        try:
            data, nxt = struct.unpack("<QQ", bytes(core.uc.mem_read(ptr, 16)))
        except Exception:
            break
        if data:
            try:
                out.append(bytes(core.uc.mem_read(data, 200)).split(b"\0")[0]
                           .decode("utf-8", "replace"))
            except Exception:
                pass
        ptr = nxt
    return out


def send_one(core, body: bytes, msgid: str) -> int:
    """Compose URL and POST through the game's own stack."""
    B = core.base

    # --- 1. URL from the game's composer --------------------------------
    out = core.alloc(64, b"\0" * 64, name="url")
    r = core.call(COMPOSER, w0=out, x1=mk_str(core, msgid.encode()),
                  x2=mk_str(core, b""), timeout_s=60, max_insns=200_000_000)
    if r["error"]:
        print("[send] composer err=%s" % r["error"], flush=True)
        return 1
    url = rd_str(core, out)
    print(f"[send] URL = {url}", flush=True)

    # --- 2. watch every curl option the game sets -------------------------
    wire = {}

    def on_setopt(uc, c):
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        name = OPT_NAME.get(opt, str(opt))
        if opt in (10002, 10015, 10173, 10036, 10062):
            try:
                wire[name] = bytes(uc.mem_read(val, 500)).split(b"\0")[0]
            except Exception:
                wire[name] = val
        elif opt == 10023:
            wire[name] = walk_slist(uc, val)
        else:
            wire[name] = val

    core.watch(SETOPT, on_setopt, name="setopt")

    # --- 3. the game's own PLAIN POST sender (subreq vtable[3]) -----------
    # signature (read off the disassembly at 0x7d03c68):
    #   (subreq, url, body, body_len, out_body, out_len, cb, cb_arg)
    # it sets CURLOPT_URL / WRITEDATA / WRITEFUNCTION / POSTFIELDS /
    # POSTFIELDSIZE / HEADERFUNCTION / VERBOSE -- and NO Content-Type, so
    # libcurl emits its own default form-urlencoded, exactly like the capture.
    subreq = core.alloc(0x10200, b"\0" * 0x10200, name="subreq")
    core.write_u64(subreq, core.base + 0x98225A0)   # subreq vtable
    urlbuf = core.alloc(256, url.encode() + b"\0" * (256 - len(url)),
                        name="urlbuf")
    bodybuf = core.alloc(len(body), body, name="bodybuf")
    ob = core.alloc(8, b"\0" * 8, name="ob")
    ol = core.alloc(8, b"\0" * 8, name="ol")
    exec_base = 0xA4000000000
    try:
        core.uc.mem_map(exec_base, 0x100000, 7)
        core.uc.mem_write(exec_base, struct.pack("<I", 0xD65F03C0))  # ret
    except Exception:
        pass

    print("[send] game's own PLAIN POST sender 0x7d03c68 ...", flush=True)
    # the sender re-maps its x4..x7 into init's (out_body, out_len, cb, arg),
    # so x6 is the completion callback and x7 its argument.  A plain `ret`
    # stub at exec_base is a valid no-op completion callback.
    r = core.call(0x7D03C68, w0=subreq, w1=urlbuf, x2=bodybuf,
                  x3=len(body), w4=ob, w5=ol, x6=exec_base, x7=0,
                  timeout_s=120, max_insns=200_000_000)
    print("[send] sender err=%s x0=%#x" % (r["error"], r["x0"]), flush=True)
    if r["error"]:
        for line in getattr(core, "_log", [])[-6:]:
            print("        ", line, flush=True)
        return 1

    print("\n[send] ==== what the GAME's curl was told ====", flush=True)
    for k, v in wire.items():
        print("    %-14s = %r" % (k, v), flush=True)

    # --- 4. the game's own pump ------------------------------------------
    responses = []

    def on_write(uc, c):
        p, sz, nm = (uc.reg_read(UC_ARM64_REG_X1),
                     uc.reg_read(UC_ARM64_REG_X2),
                     uc.reg_read(UC_ARM64_REG_X3))
        try:
            blob = bytes(uc.mem_read(p, min(sz * nm, 4096))) if p else b""
        except Exception:
            blob = b"<unreadable>"
        responses.append(blob)
        print(f"[send]   <<< RESPONSE %dB %r" % (len(blob), blob[:400]),
              flush=True)

    core.watch(0x7D04570, on_write, name="writefn")

    errbuf = core.alloc(256, b"\0" * 256, name="errbuf")
    easy = u64(core, subreq + 0x10060)
    multi = u64(core, subreq + 0x10068)
    print(f"[send] easy={easy:#x} multi={multi:#x}", flush=True)
    if easy:
        core.call(SETOPT, w0=easy, w1=0x271A, x2=errbuf, timeout_s=10)

    t0 = time.time()
    status = None
    while time.time() - t0 < 120:
        r = core.call(0x7D04350, w0=subreq, timeout_s=60, max_insns=200_000_000)
        if r["error"]:
            print("[send] pump fault %s pc=%#x" % (r["error"], r["pc"]),
                  flush=True)
            break
        status = r["x0"] & 0xFFFFFFFFFFFFFFFF
        if status:
            break
        if multi:
            core.call(0x687990C, w0=multi, w1=0, x2=0, x3=400, s0=0.0, w4=0,
                      timeout_s=5, max_insns=5_000_000)
        else:
            time.sleep(0.05)

    code = i32(core, subreq + 8)
    reason = bytes(core.uc.mem_read(errbuf, 256)).split(b"\0")[0]
    blen = i32(core, subreq + 0x10020)
    print(f"\n[send] pump status = {status or 0:#x}   HTTP = {code}   "
          f"len = {blen}", flush=True)
    print(f"[send] curl reason = {reason!r}", flush=True)
    print(f"[send] response body = {b''.join(responses)[:800]!r}", flush=True)

    print("\n[send] network trace:", flush=True)
    for line in getattr(core, "_log", []):
        if line.startswith("net "):
            print("   ", line, flush=True)
    return 0


def main() -> int:
    body = open("getserverenv_body.bin", "rb").read()
    print(f"[main] body from game's own serializer: {len(body)} bytes",
          flush=True)
    print(f"[main] hex: {body[:64].hex()}", flush=True)

    print("[main] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[main] booted", flush=True)

    return send_one(core, body, "CMD_GET_SERVER_ENV")


if __name__ == "__main__":
    sys.exit(main())
