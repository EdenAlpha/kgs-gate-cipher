#!/usr/bin/env python3
"""Run a REAL gate command through the game's own stack and report exactly
what went on the wire and what came back.

Recipe proven for GateInfo by drive_gate_own.py / gate_out.txt:
    body     <- ctor + bind + serial   (0x767eaf0 / 0x767ec60 / 0x767edbc)
    URL      <- composer 0x7b099d0(msgid, "")
    send     <- plain POST sender 0x7d03c68 (subreq vtable[3])
    pump     <- 0x7d04350, then HTTP code at subreq+8, body at +0x1c

Change: build the command with ITS OWN ctor first so msgid/script are real
(0x767f6e4 CMD_GET_SERVER_ENV, 0x76b12f8 CMD_LOGIN, 0x7639388 guest token).

Every hand-made attempt at these URLs returns a blank 500 in 0.06s.
If the GAME's own request also gets 500, the backend is broken.
If it gets 200, the difference is in the headers we cannot see.
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
    UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
)

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

GEN_CTOR = 0x767EAF0
BIND = 0x767EC60
SERIAL = 0x767EDBC
COMPOSER = 0x7B099D0
POST_PLAIN = 0x7D03C68          # vtable[3]  (self,url,body,len,out,outlen)
POST_HDR = 0x7D04148            # vtable[8]  (+ a4,a5,a6 header builder)
PUMP = 0x7D04350
CLEANUP = 0x7D042F0
SETOPT = 0x6886498
WRITE_CB = 0x7D04570
HDR_CB = 0x7D04594
SUBREQ_VT = 0x98225A0
MULTI_WAIT = 0x687990C

CMDS = [
    ("CMD_GET_SERVER_ENV", 0x767F6E4),
    ("CMD_LOGIN", 0x76B12F8),
    ("CMD_GET_KGS_GUEST_LOGIN_TOKEN", 0x7639388),
    ("CMD_CONNECT_GRPC", 0x7DB2404),
    ("CMD_CREATEJOIN_ROOM", 0x77B1830),
    ("CMD_GET_SESSION_ID", 0x7DA8794),
    ("CMD_SEND_RECRUIT_CODE", 0x76C5C74),
]

OPT_NAME = {
    3: "PORT", 41: "VERBOSE", 60: "POSTFIELDSIZE", 99: "OPTIONAL",
    10002: "URL", 10001: "WRITEDATA", 10015: "POSTFIELDS",
    10023: "HTTPHEADER", 10004: "PROXY", 10009: "READDATA",
    10173: "CUSTOMREQUEST", 20011: "WRITEFUNCTION", 20094: "HEADERFUNCTION",
    0x271A: "ERRORBUFFER", 0x4e2b: "WRITEFUNCTION", 0x4e7e: "HEADERFUNCTION",
    0x2774: "TCP_KEEPALIVE", 47: "POST", 80: "HTTPGET", 81: "NOBODY",
    10036: "HTTP_VERSION", 10022: "USERAGENT", 10018: "REFERER",
    10024: "COOKIE", 10062: "HTTPHEADER2", 10036 + 1: "x",
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
            size = u64(core, addr + 8)
            ptr = u64(core, addr + 0x10)
            if size > 0x10000 or ptr == 0:
                return "<long>"
            return bytes(core.uc.mem_read(ptr, size)).decode("utf-8", "replace")
        return bytes(core.uc.mem_read(addr + 1, b0 >> 1)).decode("utf-8",
                                                                 "replace")
    except Exception as e:
        return "<err %s>" % e


def walk_slist(core, ptr, limit=30):
    out = []
    for _ in range(limit):
        if not ptr:
            break
        try:
            data = u64(core, ptr)
            nxt = u64(core, ptr + 8)
        except Exception:
            break
        if data:
            out.append(bytes(core.uc.mem_read(data, 300)).split(b"\0")[0]
                       .decode("latin1", "replace"))
        ptr = nxt
    return out


def main() -> int:
    only = sys.argv[1] if len(sys.argv) > 1 else None
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[wire] booted", flush=True)

    wire = {}
    resp_body = bytearray()
    resp_hdr = bytearray()

    def on_setopt(uc, c):
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        name = OPT_NAME.get(opt, str(opt))
        try:
            if opt in (10002, 10173, 10004, 10009, 10018, 10022, 10024):
                wire[name] = bytes(uc.mem_read(val, 500)).split(b"\0")[0]
            elif opt == 10015:
                wire["POSTFIELDS"] = bytes(uc.mem_read(val, 4000))
            elif opt == 10023:
                wire["HTTPHEADER"] = walk_slist(uc, val)
            else:
                wire[name] = val
        except Exception as e:
            wire[name] = "<err %s>" % e

    core.watch(SETOPT, on_setopt, name="setopt")

    def on_write(uc, c):
        # C++ member write(this, ptr, size, nmemb) -> x1, x2, x3
        p = uc.reg_read(UC_ARM64_REG_X1)
        sz = uc.reg_read(UC_ARM64_REG_X2)
        nm = uc.reg_read(UC_ARM64_REG_X3)
        try:
            resp_body += uc.mem_read(p, min(sz * nm, 65536))
        except Exception:
            pass

    try:
        core.watch(WRITE_CB, on_write, name="write")
    except Exception:
        pass

    def on_hdr(uc, c):
        p = uc.reg_read(UC_ARM64_REG_X1)
        sz = uc.reg_read(UC_ARM64_REG_X2)
        nm = uc.reg_read(UC_ARM64_REG_X3)
        try:
            resp_hdr += uc.mem_read(p, min(sz * nm, 4096))
        except Exception:
            pass

    try:
        core.watch(HDR_CB, on_hdr, name="hdr")
    except Exception:
        pass

    for msgid, ctor in CMDS:
        if only and only not in msgid:
            continue
        for k in list(wire):
            del wire[k]
        resp_body.clear()
        resp_hdr.clear()

        obj = core.alloc(0x4000, b"\0" * 0x4000, name="cmd")
        # generic ctor first (allocates the serializer's buffers), THEN the
        # per-command ctor (stamps msgid + script + its own vtable), then
        # bind/serial so the body is built from the right msgid.
        r = core.call(GEN_CTOR, w0=obj, timeout_s=120, max_insns=200_000_000)
        if r["error"]:
            print("[wire] %s gen ctor FAILED %s" % (msgid, r["error"]),
                  flush=True)
            continue
        r = core.call(ctor, w0=obj, timeout_s=120, max_insns=200_000_000)
        if r["error"]:
            print("[wire] %s ctor FAILED %s" % (msgid, r["error"]), flush=True)
            continue
        print("\n[wire] ===== %s (ctor ok) msgid=%r script=%r"
              % (msgid, rd_str(core, obj + 0x138), rd_str(core, obj + 0x170)),
              flush=True)

        for fn, label in ((BIND, "bind"), (SERIAL, "serial")):
            r = core.call(fn, w0=obj, timeout_s=180, max_insns=400_000_000)
            if r["error"]:
                print("[wire]   %s FAILED: %s" % (label, r["error"]), flush=True)
                break
        else:
            size = u64(core, obj + 0x118)
            ptr = u64(core, obj + 0x120)
            body = bytes(core.uc.mem_read(ptr, size)) if ptr and size else b""
            m2 = rd_str(core, obj + 0x138)
            print("[wire]   msgid after serial = %r" % m2, flush=True)
            print("[wire]   body = %d bytes  %r" % (len(body), body[:160]),
                  flush=True)

            out = core.alloc(64, b"\0" * 64, name="url")
            sa = mk_str(core, m2.encode())
            sb = mk_str(core, b"")
            r = core.call(COMPOSER, w0=out, x1=sa, x2=sb, timeout_s=60,
                          max_insns=200_000_000)
            if r["error"]:
                print("[wire]   composer FAILED %s" % r["error"], flush=True)
                continue
            url = rd_str(core, out)
            print("[wire]   URL  = %s" % url, flush=True)

            subreq = core.alloc(0x10200, b"\0" * 0x10200, name="subreq")
            core.write_u64(subreq, core.base + SUBREQ_VT)
            urlbuf = core.alloc(300, url.encode() + b"\0" * 300, name="urlbuf")
            bodybuf = core.alloc(max(len(body), 1), body or b"\0",
                                 name="bodybuf")
            ob = core.alloc(8, b"\0" * 8, name="out_body")
            ol = core.alloc(8, b"\0" * 8, name="out_len")
            errbuf = core.alloc(256, b"\0" * 256, name="errbuf")

            t0 = time.time()
            r = core.call(POST_PLAIN, w0=subreq, w1=urlbuf, x2=bodybuf,
                          x3=len(body), w4=ob, w5=ol, timeout_s=120,
                          max_insns=300_000_000)
            print("[wire]   sender -> err=%s x0=%#x (%.1fs)"
                  % (r["error"], r["x0"], time.time() - t0), flush=True)
            if r["error"]:
                print("[wire]   sender fault pc=%#x" % r["pc"], flush=True)
                continue

            easy = u64(core, subreq + 0x10060)
            multi = u64(core, subreq + 0x10068)
            if easy:
                core.call(SETOPT, w0=easy, w1=0x271A, x2=errbuf, timeout_s=10)

            n0 = len(getattr(core, "_log", []))
            status = None
            t0 = time.time()
            while time.time() - t0 < 120:
                rr = core.call(PUMP, w0=subreq, timeout_s=120,
                               max_insns=300_000_000)
                if rr["error"]:
                    print("[wire]   pump fault %s pc=%#x"
                          % (rr["error"], rr["pc"]), flush=True)
                    break
                status = rr["x0"] & 0xFFFFFFFFFFFFFFFF
                if status:
                    break
                if multi:
                    core.call(MULTI_WAIT, w0=multi, w1=0, x2=0, x3=400,
                              w4=0, timeout_s=5, max_insns=5_000_000)
                else:
                    time.sleep(0.05)

            code = struct.unpack("<i", bytes(core.uc.mem_read(subreq + 8, 4)))[0]
            blen = struct.unpack("<i",
                                 bytes(core.uc.mem_read(subreq + 0x10020, 4)))[0]
            reason = bytes(core.uc.mem_read(errbuf, 256)).split(b"\0")[0]
            print("[wire]   ---- what curl was given ----", flush=True)
            for k, v in wire.items():
                if isinstance(v, bytes):
                    print("     %-14s = %r" % (k, v[:400]), flush=True)
                else:
                    print("     %-14s = %s" % (k, v), flush=True)
            print("[wire]   pump=%#x  HTTP=%s  bodylen=%s  err=%r"
                  % (status or 0, code, blen, reason), flush=True)
            print("[wire]   ---- stubs touched during the send ----", flush=True)
            for line in getattr(core, "_log", [])[n0:]:
                print("       %s" % line[:200], flush=True)
            if resp_hdr:
                print("[wire]   resp headers: %r" % bytes(resp_hdr)[:400],
                      flush=True)
            if resp_body:
                print("[wire]   resp body: %r" % bytes(resp_body)[:600],
                      flush=True)
            elif blen > 0:
                raw = bytes(core.uc.mem_read(subreq + 0x1C, min(blen, 4096)))
                print("[wire]   resp body(subreq): %r" % raw[:600], flush=True)
            try:
                core.call(CLEANUP, w0=subreq, timeout_s=30)
            except Exception:
                pass

    print("\n[wire] net trace:", flush=True)
    for line in getattr(core, "_log", []):
        if line.startswith("net "):
            print("   ", line, flush=True)
    print("\n[wire] harness log (imports that returned 0 / stubs):", flush=True)
    seen_imp = set()
    for line in getattr(core, "_log", []):
        if line.startswith("net "):
            continue
        if line in seen_imp:
            continue
        seen_imp.add(line)
        print("   ", line[:200], flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
