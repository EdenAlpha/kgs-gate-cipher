#!/usr/bin/env python3
"""Build the gate body with the REAL field values and send it.

The earlier body carried "NotImplement" placeholders because 0x767ec60 (the
field binder) never completed.  The capture gives the true values the app
sends to Konami (from its GateInfo POST, visible in plaintext):

      locale "US"   version "6.0.1"   apiLevel 4   lang "en"   platform "PES"

Supplying configuration is legitimate (photocopier rule); every byte of the
request is still produced by the game's own serializer and sent by the
game's own HTTP stack.
"""
from __future__ import annotations

import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

CTOR = 0x767EAF0
BIND = 0x767EC60
SERIAL = 0x767EDBC
COMPOSER = 0x7B099D0
POST = 0x7D03C68
PUMP = 0x7D04350
SETOPT = 0x6886498
WRITE_CB = 0x7D04570

LANG, REGION, PLATFORM, VERSION = b"en", b"US", b"PES", b"6.0.1"


def mk_sso(text: bytes) -> bytes:
    """libc++ short-string object: byte0 = len<<1, then the chars."""
    assert len(text) <= 22
    return bytes([len(text) << 1]) + text + b"\0" * (23 - len(text))


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def mk_str(core, text: bytes) -> int:
    buf = bytearray(32)
    buf[0] = len(text) << 1
    buf[1:1 + len(text)] = text
    return core.alloc(32, bytes(buf), name="s")


def rd_str(core, addr):
    b0 = bytes(core.uc.mem_read(addr, 1))[0]
    if b0 & 1:
        n = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 8, 8)))[0]
        p = struct.unpack("<Q", bytes(core.uc.mem_read(addr + 0x10, 8)))[0]
        return bytes(core.uc.mem_read(p, n)).decode("utf-8", "replace")
    return bytes(core.uc.mem_read(addr + 1, b0 >> 1)).decode("utf-8", "replace")


def main() -> int:
    msgid = os.environ.get("MSGID", "CMD_GET_SERVER_ENV")
    print(f"[req] msgid={msgid}", flush=True)
    print(f"[req] lang={LANG!r} region={REGION!r} platform={PLATFORM!r} "
          f"version={VERSION!r}", flush=True)

    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    B = core.base

    obj = core.alloc(0x4000, b"\0" * 0x4000, name="cmd")
    r = core.call(CTOR, w0=obj, timeout_s=180, max_insns=400_000_000)
    print(f"[req] ctor err={r['error']} msgid={rd_str(core, obj + 0x138)!r}",
          flush=True)
    if r["error"]:
        return 1

    core.write_u32(obj + 0x150, 1)          # rqid
    # real values instead of the ctor's "NotImplement" defaults
    for off, val in ((0x1E8, LANG), (0x200, REGION),
                     (0x218, PLATFORM), (0x230, VERSION)):
        core.uc.mem_write(obj + off, mk_sso(val))
        print(f"[req]   obj+{off:#x} = {val!r}", flush=True)

    for fn, label in ((BIND, "bind"), (SERIAL, "serial")):
        r = core.call(fn, w0=obj, timeout_s=180, max_insns=400_000_000)
        size = u64(core, obj + 0x118)
        print(f"[req] {label:7s} err={r['error']} size={size}", flush=True)
        if r["error"]:
            return 1

    size, ptr = u64(core, obj + 0x118), u64(core, obj + 0x120)
    body = bytes(core.uc.mem_read(ptr, size))
    open("real_body.bin", "wb").write(body)
    print(f"[req] body {size}B -> real_body.bin", flush=True)
    print(f"[req] hex: {body.hex()}", flush=True)
    try:
        import re
        print(f"[req] readable: "
              f"{[m.decode() for m in re.findall(rb'[ -~]{3,}', body)]}",
              flush=True)
    except Exception:
        pass

    out = core.alloc(64, b"\0" * 64, name="url")
    core.call(COMPOSER, w0=out, x1=mk_str(core, msgid.encode()),
              x2=mk_str(core, b""), timeout_s=60, max_insns=200_000_000)
    url = rd_str(core, out)
    print(f"[req] URL = {url}\n", flush=True)

    wire = {}

    def on_setopt(uc, c):
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        names = {10002: "URL", 10015: "POSTFIELDS", 60: "POSTFIELDSIZE",
                 10023: "HTTPHEADER", 10001: "WRITEDATA",
                 20011: "WRITEFUNCTION", 20094: "HEADERFUNCTION"}
        if opt in (10002, 10015, 10173, 10036, 10062):
            try:
                wire[names.get(opt, str(opt))] = \
                    bytes(uc.mem_read(val, 500)).split(b"\0")[0]
            except Exception:
                pass
        else:
            wire[names.get(opt, str(opt))] = val

    core.watch(SETOPT, on_setopt, name="setopt")
    responses = []

    def on_write(uc, c):
        p, sz, nm = (uc.reg_read(UC_ARM64_REG_X1), uc.reg_read(UC_ARM64_REG_X2),
                     uc.reg_read(UC_ARM64_REG_X3))
        try:
            blob = bytes(uc.mem_read(p, min(sz * nm, 4096))) if p else b""
        except Exception:
            blob = b"<unreadable>"
        responses.append(blob)
        print(f"[req]   <<< RESPONSE %dB %r" % (len(blob), blob[:400]),
              flush=True)

    core.watch(WRITE_CB, on_write, name="writefn")

    subreq = core.alloc(0x10200, b"\0" * 0x10200, name="sr")
    core.write_u64(subreq, B + 0x98225A0)
    urlbuf = core.alloc(256, url.encode() + b"\0" * (256 - len(url)))
    bodybuf = core.alloc(len(body), body)
    ob, ol = core.alloc(8, b"\0" * 8), core.alloc(8, b"\0" * 8)
    ex = 0xA4000000000
    try:
        core.uc.mem_map(ex, 0x100000, 7)
        core.uc.mem_write(ex, struct.pack("<I", 0xD65F03C0))
    except Exception:
        pass

    r = core.call(POST, w0=subreq, w1=urlbuf, x2=bodybuf, x3=len(body),
                  w4=ob, w5=ol, x6=ex, x7=0,
                  timeout_s=120, max_insns=200_000_000)
    print(f"[req] sender err={r['error']}", flush=True)

    print("\n[req] what the GAME's curl was told:", flush=True)
    for k, v in wire.items():
        print(f"    {k:14s} = {v!r}", flush=True)

    t0 = time.time()
    status = None
    while time.time() - t0 < 120:
        r = core.call(PUMP, w0=subreq, timeout_s=60, max_insns=200_000_000)
        if r["error"]:
            print(f"[req] pump fault {r['error']} pc={r['pc']:#x}", flush=True)
            break
        status = r["x0"] & 0xFFFFFFFFFFFFFFFF
        if status:
            break
        multi = u64(core, subreq + 0x10068)
        if multi:
            core.call(0x687990C, w0=multi, w1=0, x2=0, x3=400, s0=0.0, w4=0,
                      timeout_s=5, max_insns=5_000_000)
        else:
            time.sleep(0.05)

    code = struct.unpack("<i", bytes(core.uc.mem_read(subreq + 8, 4)))[0]
    blen = struct.unpack("<i", bytes(core.uc.mem_read(subreq + 0x10020, 4)))[0]
    print(f"\n[req] status={status or 0:#x} HTTP={code} len={blen}", flush=True)
    print(f"[req] response = {b''.join(responses)[:800]!r}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
