#!/usr/bin/env python3
"""Let the GAME's own stack build and send a gate request, then read back
every byte curl is given.

Nothing here is hand-assembled:
  * URL      <- the game's composer            0x7b099d0
  * body     <- the game's serializer          0x767eaf0 / 0x767edbc
  * headers  <- whatever the game's curl code sets
  * the send <- the game's own POST sender    0x7d03c68 (subreq vtable[3])
  * the pump <- the game's own pump            0x7d04350 (vtable[11])

We watch curl_easy_setopt and the WRITE callback, so the output is precisely
what the game would have put on the wire.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn.arm64_const import (                      # noqa: E402
    UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

CTOR = 0x767EAF0
BIND = 0x767EC60
SERIAL = 0x767EDBC
COMPOSER = 0x7B099D0
POST = 0x7D03C68          # vtable[3] -- plain POST, no custom headers
PUMP = 0x7D04350          # vtable[11]
INIT = 0x7D04444          # vtable[12]
CLEANUP = 0x7D042F0       # vtable[10]
SETOPT = 0x6886498        # curl_easy_setopt
WRITE_CB = 0x7D04570      # WRITEFUNCTION the senders install
SUBREQ_VT = 0x98225A0
MULTI_WAIT = 0x687990C

OPT_NAME = {
    3: "PORT", 41: "VERBOSE", 60: "POSTFIELDSIZE", 99: "OPTIONAL",
    10002: "URL", 10001: "WRITEDATA", 10015: "POSTFIELDS", 10023: "HTTPHEADER",
    10004: "PROXY", 10009: "READDATA", 10173: "CUSTOMREQUEST",
    20011: "WRITEFUNCTION", 20094: "HEADERFUNCTION", 0x271A: "ERRORBUFFER",
    0x4e2b: "WRITEFUNCTION", 0x4e7e: "HEADERFUNCTION", 0x2774: "TCP_KEEPALIVE",
}


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


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
    """curl_slist: {char *data; curl_slist *next;}"""
    out = []
    for _ in range(limit):
        if not ptr:
            break
        try:
            data = struct.unpack("<Q", bytes(core.uc.mem_read(ptr, 8)))[0]
            nxt = struct.unpack("<Q", bytes(core.uc.mem_read(ptr + 8, 8)))[0]
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


def main() -> int:
    print("[gate] booting the game's own core ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[gate] booted", flush=True)

    # ---------------- 1. body, from the game's own serializer ----------
    obj = core.alloc(0x4000, b"\0" * 0x4000, name="cmd")
    for fn, label in ((CTOR, "ctor"), (BIND, "bind"), (SERIAL, "serial")):
        r = core.call(fn, w0=obj, timeout_s=180, max_insns=400_000_000)
        if r["error"]:
            print("[gate] %s FAILED: %s" % (label, r["error"]), flush=True)
            return 1
    size = u64(core, obj + 0x118)
    ptr = u64(core, obj + 0x120)
    body = bytes(core.uc.mem_read(ptr, size))
    msgid = rd_str(core, obj + 0x138)
    print(f"[gate] msgid  = {msgid!r}", flush=True)
    print(f"[gate] body   = {size} bytes  {body[:64].hex()}", flush=True)

    # ---------------- 2. URL, from the game's own composer -------------
    out = core.alloc(64, b"\0" * 64, name="url")
    sa = mk_str(core, msgid.encode())
    sb = mk_str(core, b"")
    r = core.call(COMPOSER, w0=out, x1=sa, x2=sb, timeout_s=60,
                  max_insns=200_000_000)
    if r["error"]:
        print("[gate] composer failed: %s" % r["error"], flush=True)
        return 1
    url = rd_str(core, out)
    print(f"[gate] URL    = {url!r}\n", flush=True)

    # ---------------- 3. watch every curl option -----------------------
    wire = {}

    def on_setopt(uc, c):
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        name = OPT_NAME.get(opt, str(opt))
        if opt in (10002, 10173, 10004, 10036, 10062, 10009):
            try:
                wire[name] = bytes(uc.mem_read(val, 400)).split(b"\0")[0]
            except Exception:
                wire[name] = val
        elif opt == 10015:
            try:
                wire["POSTFIELDS"] = bytes(uc.mem_read(val, 300))[:300]
            except Exception:
                wire["POSTFIELDS"] = val
        elif opt == 10023:
            wire["HTTPHEADER"] = walk_slist(uc, val)
        else:
            wire[name] = val

    core.watch(SETOPT, on_setopt, name="setopt")
    headers_seen = []

    def on_hdr(uc, c):
        p = uc.reg_read(UC_ARM64_REG_X1)
        sz = uc.reg_read(UC_ARM64_REG_X2)
        nm = uc.reg_read(UC_ARM64_REG_X3)
        try:
            blob = bytes(uc.mem_read(p, min(sz * nm, 2048)))
        except Exception:
            blob = b""
        headers_seen.append(blob)
        print(f"    <<< RESPONSE HEADER {blob[:200]!r}", flush=True)

    core.watch(0x7D04594, on_hdr, name="hdrfn")
    body_seen = []

    def on_write(uc, c):
        p = uc.reg_read(UC_ARM64_REG_X1)
        sz = uc.reg_read(UC_ARM64_REG_X2)
        nm = uc.reg_read(UC_ARM64_REG_X3)
        try:
            blob = bytes(uc.mem_read(p, min(sz * nm, 4096))) if p else b""
        except Exception:
            blob = b"<unreadable>"
        body_seen.append(blob)
        print(f"    <<< RESPONSE BODY {len(blob)}B {blob[:400]!r}", flush=True)

    core.watch(WRITE_CB, on_write, name="writefn")

    # ---------------- 4. the game's own send + pump --------------------
    subreq = core.alloc(0x10200, b"\0" * 0x10200, name="subreq")
    core.write_u64(subreq, core.base + SUBREQ_VT)
    urlbuf = core.alloc(256, url.encode() + b"\0" * (256 - len(url)),
                        name="urlbuf")
    bodybuf = core.alloc(len(body), body, name="bodybuf")
    out_body = core.alloc(8, b"\0" * 8, name="out_body")
    out_len = core.alloc(8, b"\0" * 8, name="out_len")

    print("[gate] calling the game's POST sender 0x7d03c68 ...", flush=True)
    r = core.call(POST, w0=subreq, w1=urlbuf, x2=bodybuf, x3=len(body),
                  x4=out_body, x5=out_len, timeout_s=120,
                  max_insns=200_000_000)
    print("[gate] sender -> err=%s x0=%#x" % (r["error"], r["x0"]), flush=True)
    if r["error"]:
        print("[gate] sender faulted; stopping", flush=True)
        return 1

    print("\n[gate] ==== what the GAME's curl was told ====", flush=True)
    for k, v in wire.items():
        if isinstance(v, bytes):
            print(f"    {k:16s} = {v[:200]!r}", flush=True)
        elif isinstance(v, list):
            print(f"    {k:16s} = {v}", flush=True)
        else:
            print(f"    {k:16s} = {v}", flush=True)

    easy = u64(core, subreq + 0x10060)
    multi = u64(core, subreq + 0x10068)
    errbuf = core.alloc(256, b"\0" * 256, name="errbuf")
    if easy:
        core.call(SETOPT, w0=easy, w1=0x271A, x2=errbuf, timeout_s=10)

    import time
    t0 = time.time()
    status = None
    while time.time() - t0 < 180:
        r = core.call(PUMP, w0=subreq, timeout_s=120, max_insns=200_000_000)
        if r["error"]:
            print("[gate] pump fault: %s pc=%#x" % (r["error"], r["pc"]),
                  flush=True)
            break
        status = r["x0"] & 0xFFFFFFFFFFFFFFFF
        if status:
            break
        if multi:
            core.call(MULTI_WAIT, w0=multi, w1=0, x2=0, w3=400, s0=0.0,
                      w4=0, timeout_s=5, max_insns=5_000_000)
        else:
            time.sleep(0.05)

    code = struct.unpack("<i", bytes(core.uc.mem_read(subreq + 8, 4)))[0]
    reason = bytes(core.uc.mem_read(errbuf, 256)).split(b"\0")[0]
    blen = struct.unpack("<i", bytes(core.uc.mem_read(subreq + 0x10020, 4)))[0]
    print("\n[gate] pump status  = %#x" % (status or 0), flush=True)
    print("[gate] HTTP code    = %s" % code, flush=True)
    print("[gate] curl reason  = %r" % reason, flush=True)
    print("[gate] body length  = %s" % blen, flush=True)
    if body_seen:
        print("[gate] response     = %r" % b"".join(body_seen)[:600], flush=True)

    print("\n[gate] network trace:", flush=True)
    for line in getattr(core, "_log", []):
        if line.startswith("net "):
            print("   ", line, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
