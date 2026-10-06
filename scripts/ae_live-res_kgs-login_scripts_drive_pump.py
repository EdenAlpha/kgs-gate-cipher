#!/usr/bin/env python3
"""Drive the game's own HTTP transport end to end.

  0x7d03b68  sender   : curl_global_init / easy_init / CURLOPT_URL / multi_add
  0x7d04350  pump     : curl_multi_perform until done -> body + length
  0x7d04444  init     : out-slots, completion callback, response buffer

The body lands in subreq+0x1c, the length at subreq+0x10020, and
curl_easy_getinfo(CURLINFO_RESPONSE_CODE) at subreq+8.
"""
from __future__ import annotations

import os
import struct
import sys
import time

from unicorn.arm64_const import (                                  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

EXEC_BASE = 0xA4000000000

SENDER = 0x7D03B68      # vtable[2]
PUMP = 0x7D04350        # vtable[11]
SUBREQ_VT = 0x98225A0
SETOPT = 0x6886498
MULTI_WAIT = 0x687990C  # curl_multi_wait(multi, NULL, 0, ms, NULL)

URL = b"http://ntl.service.konami.net/ntl/api/GateInfo.php"

OK_DONE = 0xE5000207
OK_ERR = 0xE5000208
OK_AGAIN = 0xE5000209


def main():
    print("[pump] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    B = core.base

    core.uc.mem_map(EXEC_BASE, 0x100000, 7)
    core.uc.mem_write(EXEC_BASE, struct.pack("<I", 0xD65F03C0))   # ret

    seen_urls = []

    def on_setopt(uc, c):
        o = uc.reg_read(UC_ARM64_REG_X1)
        v = uc.reg_read(UC_ARM64_REG_X2)
        if o == 10002:
            try:
                raw = bytes(uc.mem_read(v, 512))
            except Exception:
                raw = b""
            z = raw.find(b"\0")
            u = raw[:z if z >= 0 else 512]
            seen_urls.append(u)
            print(f"    >>> URL = {u!r}", flush=True)

    core.watch(SETOPT, on_setopt, name="setopt")

    URLSET = 0x6891F80

    def on_urlset(uc, c):
        h = uc.reg_read(UC_ARM64_REG_X0)
        part = uc.reg_read(UC_ARM64_REG_X1)
        p = uc.reg_read(UC_ARM64_REG_X2)
        fl = uc.reg_read(UC_ARM64_REG_X3)
        try:
            s = bytes(uc.mem_read(p, 160)).split(b"\0")[0]
        except Exception:
            s = b"<unreadable>"
        print(f"    >>> curl_url_set(h={h:#x} part={part} flags={fl:#x}) "
              f"url={s!r}", flush=True)
        core._last_urlset = (h, part, p, fl)

    core.watch(URLSET, on_urlset, name="urlset")

    def on_sa(uc, c):
        p = uc.reg_read(UC_ARM64_REG_X0)
        dst = uc.reg_read(UC_ARM64_REG_X2)
        try:
            raw = bytes(uc.mem_read(p, 32))
            fam = struct.unpack("<H", raw[:2])[0]
        except Exception:
            raw, fam = b"", -1
        print(f"    >>> sa_ntop(sa={p:#x} dst={dst:#x}) family={fam} "
              f"raw={raw.hex()}", flush=True)

    core.watch(0x685DA04, on_sa, name="sa_ntop")

    WRITE_CB = 0x7D04570

    def on_write(uc, c):
        p = uc.reg_read(UC_ARM64_REG_X1)
        sz = uc.reg_read(UC_ARM64_REG_X2)
        nm = uc.reg_read(UC_ARM64_REG_X3)
        n = min(sz * nm, 4096)
        try:
            blob = bytes(uc.mem_read(p, n)) if p and n else b""
        except Exception:
            blob = b"<unreadable>"
        print(f"    <<< WRITE {sz}x{nm} = {blob[:600]!r}", flush=True)

    core.watch(WRITE_CB, on_write, name="writecb")

    subreq = core.alloc(0x10200, b"\0" * 0x10200, name="subreq")
    core.write_u64(subreq, B + SUBREQ_VT)
    urlbuf = core.alloc(256, URL + b"\0" * (256 - len(URL)), name="url")
    out_body = core.alloc(8, b"\0" * 8, name="out_body")
    out_len = core.alloc(8, b"\0" * 8, name="out_len")

    # ------------------------------------------------------------- sender
    print(f"[pump] sender 0x{SENDER:x}(subreq={subreq:#x}) ...", flush=True)
    t0 = time.time()
    r = core.call(SENDER, w0=subreq, w1=urlbuf, x2=out_body, x3=out_len,
                  s0=0.0, w4=EXEC_BASE, w5=0, timeout_s=60,
                  max_insns=40_000_000)
    print(f"       -> x0={r['x0']:#x} err={r['error']} "
          f"({time.time() - t0:.1f}s)", flush=True)
    if r["error"]:
        print("       SENDER FAULTED -- stop", flush=True)
        return 1

    easy = struct.unpack("<Q", bytes(core.uc.mem_read(subreq + 0x10060, 8)))[0]
    multi = struct.unpack("<Q", bytes(core.uc.mem_read(subreq + 0x10068, 8)))[0]
    print(f"       easy={easy:#x} multi={multi:#x}", flush=True)
    snap = dict(getattr(core, "import_calls", {}))
    errbuf = core.alloc(256, b"\0" * 256, name="errbuf")
    # CURLOPT_ERRORBUFFER = 0x271a -> curl writes its own reason here
    core.call(SETOPT, w0=easy, w1=0x271A, x2=errbuf, timeout_s=10)

    def scan_strings(base, n, tag):
        print(f"  --- {tag} ---", flush=True)
        try:
            raw = bytes(core.uc.mem_read(base, n))
        except Exception as e:
            print(f"    unreadable: {e}", flush=True)
            return
        for off in range(0, n - 7, 8):
            p = struct.unpack_from("<Q", raw, off)[0]
            if not (0x1000000000 <= p < 0x100000000000):
                continue
            try:
                s = bytes(core.uc.mem_read(p, 96)).split(b"\0")[0]
            except Exception:
                continue
            if len(s) > 3 and all(32 <= c < 127 for c in s):
                print(f"    +{off:#x} -> {p:#x} {s[:76]!r}", flush=True)

    scan_strings(easy, 0x1400, "easy handle string ptrs (after sender)")
    print(f"    urlbuf bytes = "
          f"{bytes(core.uc.mem_read(urlbuf, 64))[:64]!r}", flush=True)

    # -------------------------------------------------------------- pump
    deadline = time.time() + float(os.environ.get("PUMP_SECS", "420"))
    last = None
    iters = 0
    while time.time() < deadline:
        iters += 1
        r = core.call(PUMP, w0=subreq, timeout_s=120, max_insns=40_000_000)
        v = r["x0"] & 0xFFFFFFFFFFFFFFFF
        if r["error"]:
            print(f"  pump#{iters}: FAULT {r['error']} pc={r['pc']:#x}",
                  flush=True)
            break
        if v != last:
            print(f"  pump#{iters}: x0={v:#x} "
                  f"({time.time() - t0:.0f}s)", flush=True)
            last = v
        if v == 0:
            # still running -> let curl wait on its own sockets
            if multi:
                core.call(MULTI_WAIT, w0=multi, w1=0, x2=0, x3=500,
                          s0=0.0, w4=0, timeout_s=5, max_insns=5_000_000)
            else:
                time.sleep(0.01)
            continue
        last = v
        break
    print(f"  loop ended after {iters} iterations "
          f"({time.time() - t0:.0f}s)", flush=True)

    # curl's own verdict: CURLMsg from curl_multi_info_read
    INFO_READ = 0x687AF14
    msgs = core.alloc(4, b"\0" * 4, name="msgs")
    ir = core.call(INFO_READ, w0=multi, w1=msgs, timeout_s=10)
    mp = ir["x0"] & 0xFFFFFFFFFFFFFFFF
    if mp:
        raw = bytes(core.uc.mem_read(mp, 32))
        print(f"\n  CURLMsg @ {mp:#x}: {raw.hex()}", flush=True)
        print(f"    msg={struct.unpack_from('<i', raw, 0)[0]} "
              f"easy={struct.unpack_from('<Q', raw, 8)[0]:#x} "
              f"result={struct.unpack_from('<i', raw, 16)[0]} "
              f"result@24={struct.unpack_from('<i', raw, 24)[0]}",
              flush=True)
    else:
        print("\n  curl_multi_info_read -> NULL (no message)", flush=True)

    diff = {}
    for k, v2 in getattr(core, "import_calls", {}).items():
        d = v2 - snap.get(k, 0)
        if d:
            diff[k] = d
    print("\n  imports during pump:", flush=True)
    for k in sorted(diff):
        print(f"    {k:20s} +{diff[k]}", flush=True)

    code = core.read_u32(subreq + 8) & 0xFFFFFFFF
    errmsg = bytes(core.uc.mem_read(errbuf, 256)).split(b"\0")[0]
    print(f"  curl reason     : {errmsg!r}", flush=True)
    print(f"    easy+0xe90 ptr = "
          f"{struct.unpack('<Q', bytes(core.uc.mem_read(easy + 0xE90, 8)))[0]:#x}",
          flush=True)
    if getattr(core, "_last_urlset", None):
        h, part, p, fl = core._last_urlset
        for tag, pp, ff in (("flags=0 same ptr", p, 0),
                            ("flags=0 urlbuf", urlbuf, 0),
                            ("orig flags urlbuf", urlbuf, fl)):
            rr = core.call(URLSET, w0=h, w1=0, x2=pp, x3=ff, timeout_s=10)
            print(f"    curl_url_set retry [{tag}] -> x0={rr['x0']:#x} "
                  f"{rr['error']}", flush=True)
    length = struct.unpack("<i", bytes(core.uc.mem_read(subreq + 0x10020, 4)))[0]
    body_ptr = struct.unpack("<Q", bytes(core.uc.mem_read(out_body, 8)))[0]
    body_len = struct.unpack("<q", bytes(core.uc.mem_read(out_len, 8)))[0]
    buf = bytes(core.uc.mem_read(subreq + 0x1c, 0x10000))
    end = buf.find(b"\0")
    got = buf[:end if end >= 0 else 0x10000]

    print(f"\n  iterations     : {iters}", flush=True)
    print(f"  final status   : {last:#x}" if last is not None else "", flush=True)
    print(f"  HTTP code [x0] : {code}", flush=True)
    print(f"  body len field : {length}", flush=True)
    print(f"  out_body       : {body_ptr:#x}  out_len={body_len}", flush=True)
    print(f"  body bytes      : {len(got)}", flush=True)
    if got:
        print("  ---- body ----", flush=True)
        print(got[:1200].decode("utf-8", "replace"), flush=True)
        print("  --------------", flush=True)

    print("\n  import calls:", flush=True)
    for k in sorted(getattr(core, "import_calls", {})):
        print(f"    {k:18s} {core.import_calls[k]}", flush=True)
    noisy = ("__cxa_atexit", "fopen", "pthread_", "malloc", "free",
             "calloc", "realloc", "memcpy", "strlen", "strcmp")
    print("\n  network trace:", flush=True)
    for line in getattr(core, "_log", []):
        if line.startswith("net ") or (
                "unhandled import" in line
                and not any(n in line for n in noisy)):
            print("   ", line, flush=True)
    print("\n  log (last 12):", flush=True)
    for line in getattr(core, "_log", [])[-12:]:
        print("   ", line, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
