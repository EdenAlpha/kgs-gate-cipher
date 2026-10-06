#!/usr/bin/env python3
"""Probe the command endpoint the game itself composes, using the game's own
HTTP stack.

The endpoint was read out of a running instance (dump_endpoint.py):

    scheme https, host pes22-game.cs.konami.net, path /pes22
    -> https://pes22-game.cs.konami.net/pes22/gate.php

We hand these URLs to the game's sub-request sender and report exactly what
comes back. Nothing is assembled by hand.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402
from peerlink.game_http import GameHttp  # noqa: E402

BASES = [
    "https://pes22-game.cs.konami.net/pes22",
    "http://pes22-game.cs.konami.net/pes22",
]
PATHS = [
    "/gate.php",
    "/CmdGetServerEnv.php",
    "/nosuchscript.php",
    "/",
]


def main():
    print("[probe] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[probe] booted", flush=True)

    http = GameHttp(core, log=lambda m: print("    " + m, flush=True),
                    verbose=True)

    for base in BASES:
        for path in PATHS:
            url = base + path
            print(f"\n[probe] GET {url}", flush=True)
            try:
                r = http.get(url, timeout=45)
            except Exception as e:
                print(f"    exception: {e}", flush=True)
                continue
            body = r.body[:400].decode("utf-8", "replace") if r.body else ""
            print(f"    status={r.status} code={r.code} "
                  f"bytes={len(r.body) if r.body else 0} "
                  f"err={r.error} curl={r.curl_result}", flush=True)
            if body:
                print(f"    body: {body!r}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
