#!/usr/bin/env python3
"""Sweep every path-shaped string in the binary against the live server.

The unlock: `path` is a URL path, and `path = "/"` returns a real
`CommandResponse`:

    {'id': 'CMD_END_CONNECTION', 'packMode': 0, 'res': '{"result":"NOERR"}'}

Two things follow. `res` is JSON under `packMode = 0`, and the response's `id`
is the **resolved command name** rather than an echo of what we sent — so the
server names the command it dispatched, which makes this a clean oracle: any
path that comes back is a real route and tells us what it is.

Candidate paths are every `/`-prefixed string in libUE4.so, filtered to
plausible route shapes and de-duplicated.
"""
from __future__ import annotations

import collections
import os
import re
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, command_response  # noqa: E402

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"


def candidates():
    d = open(SO, "rb").read()
    out = set()
    for m in re.finditer(rb"/[A-Za-z][A-Za-z0-9_.{}$-]{1,40}(?:/[A-Za-z0-9_.{}$-]{1,40}){0,5}",
                         d):
        s = m.group(0).decode("latin1")
        if not (2 <= len(s) <= 60):
            continue
        # skip source/build paths and anything that is clearly not a route
        if s.startswith(("/usr/", "/proc/", "/sys/", "/system/", "/vendor/",
                         "/dev/", "/basic/", "/google/", "/android/",
                         "/codegen/", "/common/", "/data/", "/lib/")):
            continue
        if "\\" in s or ".." in s or s.count("/") > 5:
            continue
        out.add(s)
    return sorted(out)


def probe(path):
    try:
        r = call(path, "{}", 0, str(uuid.uuid4()), settle=2.5)
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e), b""
    st, gm = "-", ""
    for _f, h in r["headers"]:
        if "grpc-status" in h:
            st = h["grpc-status"]
            gm = unquote_plus(h.get("grpc-message", ""))
    return st, gm, r["data"]


def main() -> int:
    cands = candidates()
    print("%d path-shaped candidates in the binary\n" % len(cands))
    seen_cmd = collections.Counter()
    hits = []
    n = 0
    for p in cands:
        st, gm, data = probe(p)
        n += 1
        if st in (None, "14"):
            continue
        cmd = None
        res = ""
        if len(data) >= 5:
            mlen = int.from_bytes(data[1:5], "big")
            dec = command_response(data[5:5 + mlen])
            cmd = dec.get("id")
            res = dec.get("res") or ""
        seen_cmd[cmd] += 1
        hits.append((p, st, cmd, res))
        print("  %-46s -> grpc=%-4s cmd=%-26s %s"
              % (p[:46], st, cmd, res[:60]), flush=True)
        if n % 100 == 0:
            print("     ...%d/%d" % (n, len(cands)), flush=True)
    print("\nswept %d, %d resolved" % (n, len(hits)))
    print("\ncommands reached:")
    for c, k in seen_cmd.most_common():
        print("  %-30s %d path(s)" % (c, k))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
