"""Login watch: hook curl_easy_setopt (vaddr 0x6886498) inside the headless
game and print every URL / POST body the game hands to its own HTTP stack.

Key point: CURLOPT_URL is set BEFORE connect, so the production base URL is
observable even if the TLS handshake never completes.

Stages (each fault-tolerant; we always reach the report):
  1. boot headless core
  2. netsplice (real sockets behind the game's imports)
  3. install curl_easy_setopt watcher
  4. run the game's online-config registrars
  5. drive the GateInfo sender (0x7d0c06c)
  6. drive the bootstrap state machine (0x7dc7164)
"""
from __future__ import annotations

import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "scripts"))
sys.path.insert(0, HERE)

from unicorn.arm64_const import (                       # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
)

CURL_SETOPT = 0x6886498

# interesting CURLOPT values (OBJECTPOINT = 10000+, LONG = plain ints)
OPT_NAME = {
    3:    "CURLOPT_PORT",
    41:   "CURLOPT_VERBOSE",
    60:   "CURLOPT_POSTFIELDSIZE",
    10001: "CURLOPT_WRITEDATA",
    10002: "CURLOPT_URL",
    10004: "CURLOPT_PROXY",
    10006: "CURLOPT_USERPWD",
    10009: "CURLOPT_READDATA",
    10015: "CURLOPT_POSTFIELDS",
    10018: "CURLOPT_HTTPAUTH",
    10023: "CURLOPT_HTTPHEADER",
    10036: "CURLOPT_REFERER",
    10062: "CURLOPT_COOKIE",
    10173: "CURLOPT_CUSTOMREQUEST",
    20011: "CURLOPT_WRITEFUNCTION",
    20079: "CURLOPT_XFERINFOFUNCTION",
    30120: "CURLOPT_POSTFIELDSIZE_LARGE",
}

WATCHED = {10002, 10015, 10004, 10006, 10036, 10173, 3, 60, 30120}


class CurlWatcher:
    def __init__(self, core):
        self.core = core
        self.opt_count = 0
        self.urls = []          # ordered, unique-ish log of everything seen
        self.postsize = {}      # handle -> declared POSTFIELDSIZE
        self.handles = set()

    # ------------------------------------------------- emulated memory reads
    def _cstr(self, addr, maxn=2048):
        if not addr:
            return None
        try:
            b = bytes(self.core.uc.mem_read(addr, maxn))
        except Exception:
            return None
        i = b.find(b"\0")
        if i < 0:
            i = maxn
        return b[:i]

    def _bytes(self, addr, n):
        if not addr or n <= 0:
            return None
        try:
            return bytes(self.core.uc.mem_read(addr, min(n, 8192)))
        except Exception:
            return None

    # ------------------------------------------------------------ the hook
    def on_setopt(self, uc, core):
        self.opt_count += 1
        handle = uc.reg_read(UC_ARM64_REG_X0)
        opt = uc.reg_read(UC_ARM64_REG_X1)
        val = uc.reg_read(UC_ARM64_REG_X2)
        self.handles.add(handle)

        if opt not in WATCHED:
            return

        name = OPT_NAME.get(opt, f"opt{opt}")

        if opt == 60 or opt == 30120:                    # declared body size
            self.postsize[handle] = val & 0xFFFFFFFF
            return

        if opt == 10002:                                 # ---- the URL
            raw = self._cstr(val)
            if raw is None:
                return
            try:
                s = raw.decode("utf-8", "replace")
            except Exception:
                s = repr(raw)
            self.urls.append(("URL", s))
            print(f"    >>> CURLOPT_URL = {s}", flush=True)
            return

        if opt == 10015:                                 # ---- POST body
            n = self.postsize.get(handle) or 4096
            raw = self._bytes(val, n)
            if raw is None:
                return
            self.urls.append(("BODY", raw))
            try:
                txt = raw.decode("utf-8", "replace")
                printable = sum(1 for c in txt if 31 < ord(c) < 127)
                shown = (txt if printable > len(txt) * 0.7
                         else raw.hex())
            except Exception:
                shown = raw.hex()
            print(f"    >>> CURLOPT_POSTFIELDS ({len(raw)}B) = "
                  f"{shown[:300]}", flush=True)
            return

        self.urls.append((name, val))
        print(f"    >>> {name} = {val:#x}", flush=True)


def stage(label, fn):
    print(f"\n--- {label} ---", flush=True)
    try:
        r = fn()
        print(f"    ok: {r}", flush=True)
        return r
    except Exception as e:
        print(f"    FAILED: {type(e).__name__}: {str(e)[:300]}", flush=True)
        return None


def main():
    t0 = time.time()
    print("[login_watch] booting headless game core...", flush=True)
    from peerlink.online_client import OnlineCore, REGISTRARS  # noqa

    core = OnlineCore(verbose=False)
    print(f"[login_watch] core up in {time.time() - t0:.1f}s "
          f"(base {core.base:#x})", flush=True)

    stage("netsplice", lambda: f"{len(core.install_netsplice())} imports wired")

    w = CurlWatcher(core)
    stage("hook curl_easy_setopt", lambda: core.watch(
        CURL_SETOPT, w.on_setopt, name="curl_easy_setopt"))
    print(f"    watching vaddr {CURL_SETOPT:#x}", flush=True)

    stage("online-config registrars",
          lambda: _run_registrars(core, REGISTRARS))

    stage("GateInfo sender 0x7d0c06c", lambda: core.call(0x7d0c06c))

    stage("bootstrap state machine 0x7dc7164",
          lambda: core.call(0x7dc7164, timeout_s=25))

    # ---- report -------------------------------------------------------
    print("\n" + "=" * 70)
    print("WHAT THE GAME TRIED TO FETCH")
    print("=" * 70)
    print(f"  curl_easy_setopt calls observed : {w.opt_count}")
    print(f"  distinct handles                : {len(w.handles)}")
    urls = [s for k, s in w.urls if k == "URL"]
    bodies = [s for k, s in w.urls if k == "BODY"]
    print(f"  CURLOPT_URL values              : {len(urls)}")
    seen = []
    for u in urls:
        if u not in seen:
            seen.append(u)
    for u in seen:
        print(f"      {u}")
    if bodies:
        print(f"  POST bodies                     : {len(bodies)}")
        for b in bodies[:6]:
            print(f"      {b[:200]!r}")
    if not seen:
        print("  (no URL was set — the request path never reached curl)")
    print("=" * 70)

    # any harness fault log
    if getattr(core, "_log", None):
        print("\nharness log (last 25):")
        for line in core._log[-25:]:
            print("   ", line)

    return 0


def _run_registrars(core, registrars):
    ok = 0
    for fn in registrars:
        try:
            core.call(fn)
            ok += 1
        except Exception as e:
            print(f"    registrar {fn:#x}: {type(e).__name__} "
                  f"{str(e)[:80]}", flush=True)
    return f"{ok}/{len(registrars)} registrars ran"


if __name__ == "__main__":
    sys.exit(main())
