#!/usr/bin/env python3
"""Map the router by probing its first path segment exhaustively.

Guessing words has failed: ~8000 candidate paths across the binary, the assets,
the packs and the payload all returned the default route or `14`. But `/`
resolves to `CMD_END_CONNECTION`, so there IS a route table, and a table can be
mapped structurally rather than by vocabulary.

If the router dispatches on path segments, then probing every possible *first*
segment -- all letters in both cases, digits, and a few separators -- will
either find a live branch or prove the table is keyed on something other than a
readable first segment. Either answer is progress, and unlike a wordlist it does
not depend on guessing the game's vocabulary.

Every candidate is sampled 3 times and classified by its modal outcome, because
the endpoint returns the transient `502/14` about 0.7% of the time and a single
sample has already produced two false conclusions in this investigation.
"""
from __future__ import annotations

import collections
import json
import os
import string
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, command_response  # noqa: E402

SAMPLES = 3


def one(path, payload="{}"):
    """-> (grpc_status, command_id, res) for one request."""
    try:
        r = call(path, payload, 0, str(uuid.uuid4()), settle=2.0)
    except Exception as e:
        return ("ERR", type(e).__name__, "")
    st = None
    for _f, h in r["headers"]:
        if "grpc-status" in h:
            st = h["grpc-status"]
    d = r["data"]
    if len(d) >= 5:
        mlen = int.from_bytes(d[1:5], "big")
        dec = command_response(d[5:5 + mlen])
        return (st, dec.get("id") or "", (dec.get("res") or "")[:60])
    return (st, "", "")


def modal(path, payload="{}"):
    seen = collections.Counter()
    detail = {}
    for _ in range(SAMPLES):
        st, cmd, res = one(path, payload)
        key = (st, cmd)
        seen[key] += 1
        detail[key] = res
    (st, cmd), n = seen.most_common(1)[0]
    return st, cmd, detail[(st, cmd)], seen


def classify(st, cmd):
    if cmd and cmd != "CMD_END_CONNECTION":
        return "REAL"
    if st == "14":
        return "rejected"
    if st is None and cmd == "CMD_END_CONNECTION":
        return "default"
    if st is None:
        return "silent"
    return "other(%s)" % st


def main() -> int:
    seg1 = (list(string.ascii_lowercase) + list(string.ascii_uppercase)
            + list(string.digits))
    print("A. every single-character first segment, %d samples each\n" % SAMPLES)
    print("%-8s %-26s %s" % ("path", "modal outcome", "verdict"))
    live = []
    for c in seg1:
        p = "/" + c
        st, cmd, res, seen = modal(p)
        v = classify(st, cmd)
        if v != "default":
            spread = ", ".join("%s/%s x%d" % (k[0], k[1] or "-", n)
                               for k, n in seen.most_common())
            print("  %-6s %-26s %s" % (p, spread, v), flush=True)
            live.append((p, v, cmd, res))
    print("\n  non-default single segments: %d of %d"
          % (len(live), len(seg1)))
    if not live:
        print("  -> no single-character first segment routes anywhere")

    print("\nB. the same, with a second segment, over the letters\n")
    live2 = []
    for a in string.ascii_lowercase:
        p = "/%s/x" % a
        st, cmd, res, seen = modal(p)
        v = classify(st, cmd)
        if v != "default":
            print("  %-6s %-26s %s" % (p, seen.most_common(1)[0], v), flush=True)
            live2.append((p, v, cmd, res))
    print("  non-default two-segment paths: %d" % len(live2))

    print("\nC. deeper shapes under '/', in case the table nests\n")
    shapes = ["/x", "/x/y", "/x/y/z", "/a/b/c/d", "/_", "/-", "/.", "/..",
              "/v1", "/v2", "/api", "/api/v1", "/g", "/grpc", "/cmd",
              "/command", "/cmds", "/r", "/rpc", "/c", "/s", "/p"]
    for p in shapes:
        st, cmd, res, seen = modal(p)
        v = classify(st, cmd)
        print("  %-14s %-26s %s" % (p, seen.most_common(1)[0], v), flush=True)
        if v == "REAL":
            live.append((p, v, cmd, res))

    print("\n=== anything that routed ===")
    for p, v, cmd, res in live + live2:
        print("  %-16s %-10s %-24s %s" % (p, v, cmd, res))
    if not (live or live2):
        print("  nothing. The route table is not keyed on a readable path.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
