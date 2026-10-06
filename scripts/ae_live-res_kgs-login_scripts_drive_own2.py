#!/usr/bin/env python3
"""Drive the game's own CMD_GET_SERVER_ENV request end to end.

Repairs made this session so the harness runs at all:
  * uc_loader / uc_loader2 point at the repo copy of libUE4.so
  * STUB_SIZE raised to 4 MB (15,345 PLT imports > the old 8,192 stubs)
  * packed_relocs.npz + plt_map.json rebuilt from the ELF
  * 0x74e3374 (envelope writer) dereferences a global settings pointer that
    full app startup normally fills; we hand it a minimal one built from the
    game's own conventions.
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
ENVELOPE = 0x74E3374        # writes msgid/rqid from the object
BIND = 0x767EC60            # copies lang/region/platform/client_version
SERIAL = 0x767EDBC          # writes the MessagePack body
COMPOSER = 0x7B099D0        # builds the URL
POST = 0x7D03C68            # subreq vtable[3]
PUMP = 0x7D04350            # vtable[11]
CLEANUP = 0x7D042F0         # vtable[10]
SETOPT = 0x6886498
WRITE_CB = 0x7D04570
SUBREQ_VT = 0x98225A0
MULTI_WAIT = 0x687990C

OPT_NAME = {3: "PORT", 41: "VERBOSE", 60: "POSTFIELDSIZE",
            10001: "WRITEDATA", 10002: "URL", 10015: "POSTFIELDS",
            10023: "HTTPHEADER", 20011: "WRITEFUNCTION",
            20094: "HEADERFUNCTION", 0x271A: "ERRORBUFFER"}


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
    out = []
    for _ in range(limit):
        if not ptr:
            break
        try:
            data, nxt = struct.unpack(
                "<QQ", bytes(core.uc.mem_read(ptr, 16)))
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
    B = core.base
    print("[gate] booted", flush=True)

    # ---- the settings object the envelope writer expects ---------------
    # 0x74e3374 -> ... -> 0x421e884 walks
    #     g = *(base+0x98d5148);  if g: v = g[0];  fn = v[0x18]
    # so give it a two-level object with one vtable slot, pointing at a stub
    # that simply returns 0 (an empty string).
    settings = core.alloc(0x200, b"\0" * 0x200, name="settings")
    vt = core.alloc(0x80, b"\0" * 0x80, name="settings_vt")
    core.write_u64(vt + 0x18, 0)          # NULL -> helper returns 0
    core.write_u64(settings, core.base + vt - B)   # placeholder, fixed below
    core.uc.mem_write(settings, struct.pack("<Q", core.base + vt))
    core.write_u64(B + 0x98D5148, settings)
    print("[gate] settings global 0x98d5148 wired", flush=True)

    # ---- 1. the game builds the command object itself ------------------
    obj = core.alloc(0x4000, b"\0" * 0x4000, name="cmd")
    r = core.call(CTOR, w0=obj, timeout_s=180, max_insns=400_000_000)
    print("[gate] ctor      err=%s  msgid=%r  script=%r" % (
        r["error"], rd_str(core, obj + 0x138), rd_str(core, obj + 0x170)),
        flush=True)
    if r["error"]:
        return 1
    core.write_u32(obj + 0x150, 1)        # rqid
    for off, val in ((0x1E8, b"en"), (0x200, b"US"),
                     (0x218, b"PES"), (0x230, b"dt270")):
        core.uc.mem_write(obj + off, bytes([len(val) << 1]) + val + b"\0" * 22)

    # ---- 2. envelope + field binding ----------------------------------
    for fn, label in ((ENVELOPE, "envelope"), (BIND, "bind"),
                      (SERIAL, "serial")):
        r = core.call(fn, w0=obj, timeout_s=180, max_insns=400_000_000)
        size = u64(core, obj + 0x118)
        print("[gate] %-9s err=%-28s size=%d" % (label, r["error"], size),
              flush=True)
        if r["error"]:
            for line in getattr(core, "_log", [])[-4:]:
                print("        ", line, flush=True)
            return 1

    size, ptr = u64(core, obj + 0x118), u64(core, obj + 0x120)
    body = bytes(core.uc.mem_read(ptr, size))
    print("[gate] body = %d bytes: %s" % (size, body[:80].hex()), flush=True)

    # ---- 3. the game composes the URL itself ---------------------------
    out = core.alloc(64, b"\0" * 64, name="url")
    r = core.call(COMPOSER, w0=out, x1=mk_str(core, b"CMD_GET_SERVER_ENV"),
                  x2=mk_str(core, b""), timeout_s=60, max_insns=200_000_000)
    if r["error"]:
        print("[gate] composer err=%s" % r["error"], flush=True)
        return 1
    url = rd_str(core, out)
    print("[gate] URL  = %s\n" % url, flush=True)

    # ---- 4. the game's own curl, watched -------------------------------
    wire = {}
    seen = []

    def on_setopt(uc, c):
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        name = OPT_NAME.get(opt, str(opt))
        if opt in (10002, 10015, 10173, 10036, 10062):
            try:
                wire[name] = bytes(uc.mem_read(val, 400)).split(b"\0")[0]
            except Exception:
                wire[name] = val
        elif opt == 10023:
            wire[name] = walk_slist(uc, val)
        else:
            wire[name] = val
        seen.append((name, val))

    core.watch(SETOPT, on_setopt, name="setopt")

    def on_write(uc, c):
        p, sz, nm = (uc.reg_read(UC_ARM64_REG_X1), uc.reg_read(UC_ARM64_REG_X2),
                     uc.reg_read(UC_ARM64_REG_X3))
        try:
            blob = bytes(uc.mem_read(p, min(sz * nm, 4096))) if p else b""
        except Exception:
            blob = b"<unreadable>"
        print("[gate]   <<< RESPONSE %dB %r" % (len(blob), blob[:400]),
              flush=True)

    core.watch(WRITE_CB, on_write, name="writefn")

    subreq = core.alloc(0x10200, b"\0" * 0x10200, name="subreq")
    core.write_u64(subreq, B + SUBREQ_VT)
    urlbuf = core.alloc(256, url.encode() + b"\0" * (256 - len(url)),
                        name="urlbuf")
    bodybuf = core.alloc(len(body), body, name="bodybuf")
    ob, ol = core.alloc(8, b"\0" * 8, name="ob"), core.alloc(8, b"\0" * 8,
                                                              name="ol")

    print("[gate] the game's own POST sender ...", flush=True)
    r = core.call(POST, w0=subreq, w1=urlbuf, x2=bodybuf, x3=len(body),
                  x4=ob, x5=ol, timeout_s=120, max_insns=200_000_000)
    print("[gate] sender err=%s" % r["error"], flush=True)
    if r["error"]:
        for line in getattr(core, "_log", [])[-6:]:
            print("        ", line, flush=True)
        return 1

    print("\n[gate] ==== what the GAME's curl was told ====", flush=True)
    for k, v in wire.items():
        print("    %-14s = %r" % (k, v), flush=True)

    easy, multi = u64(core, subreq + 0x10060), u64(core, subreq + 0x10068)
    errbuf = core.alloc(256, b"\0" * 256, name="errbuf")
    if easy:
        core.call(SETOPT, w0=easy, w1=0x271A, x2=errbuf, timeout_s=10)

    import time
    t0 = time.time()
    status = None
    while time.time() - t0 < 180:
        r = core.call(PUMP, w0=subreq, timeout_s=120, max_insns=200_000_000)
        if r["error"]:
            print("[gate] pump fault %s pc=%#x" % (r["error"], r["pc"]),
                  flush=True)
            break
        status = r["x0"] & 0xFFFFFFFFFFFFFFFF
        if status:
            break
        if multi:
            core.call(MULTI_WAIT, w0=multi, w1=0, x2=0, w3=400, s0=0.0, w4=0,
                      timeout_s=5, max_insns=5_000_000)
        else:
            time.sleep(0.05)

    code = struct.unpack("<i", bytes(core.uc.mem_read(subreq + 8, 4)))[0]
    reason = bytes(core.uc.mem_read(errbuf, 256)).split(b"\0")[0]
    blen = struct.unpack("<i", bytes(core.uc.mem_read(subreq + 0x10020, 4)))[0]
    print("\n[gate] pump status = %#x   HTTP = %s   len = %s" % (
        status or 0, code, blen), flush=True)
    print("[gate] curl reason = %r" % reason, flush=True)

    print("\n[gate] network trace:", flush=True)
    for line in getattr(core, "_log", []):
        if line.startswith("net "):
            print("   ", line, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
