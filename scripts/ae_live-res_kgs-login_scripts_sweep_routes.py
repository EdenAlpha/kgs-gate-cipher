#!/usr/bin/env python3
"""A targeted route sweep: lowercase, short, and built from the game's own
vocabulary.

The broad sweep over every `/`-prefixed string in the binary is 2711 candidates
and almost all of them are UE4 asset paths (`/Docking/CloseApp_Hovered`,
`/Compe_Default`) that could not possibly be API routes. Real routes are
lowercase and short.

So this builds a much smaller candidate set from two sources:

  * the *suffixes* of the 384 `CMD_*` identifiers, in snake, kebab and camel
    form, with and without a leading slash and with `/v1` and `/api` prefixes;
  * a short list of structural probes, to learn the router's shape — whether an
    unknown first segment behaves differently from an unknown second segment,
    and whether a known root with a bad child is distinguishable.

Any path that resolves is printed with the command name the server reports.
"""
from __future__ import annotations

import os
import re
import sys
import uuid
from urllib.parse import unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kgs_client import call, command_response  # noqa: E402

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"


def suffixes():
    d = open(SO, "rb").read()
    names = sorted(set(m.group(0).decode()
                       for m in re.finditer(rb"CMD_[A-Z0-9_]{2,48}", d)))
    out = set()
    for n in names:
        s = n[4:] if n.startswith("CMD_") else n
        out.add(s.lower())
        out.add(s.lower().replace("_", "-"))
        out.add(s.lower().replace("_", ""))
        # first and last words, which is how REST routes are often written
        parts = s.lower().split("_")
        if parts:
            out.add(parts[0])
            out.add(parts[-1])
            if len(parts) > 1:
                out.add("_".join(parts[:2]))
                out.add("_".join(parts[-2:]))
    return sorted(x for x in out if 2 <= len(x) <= 28)


def main() -> int:
    words = suffixes()
    print("%d vocabulary words from the CMD_* identifiers\n" % len(words))

    shapes = ["/%s", "/v1/%s", "/api/%s", "/%s/", "/%s/%s"]
    cands = set()
    for w in words:
        cands.add("/" + w)
        cands.add("/v1/" + w)
        cands.add("/api/" + w)
    # structural probes
    for a in ("a", "zzz", "notarealroute"):
        for b in ("b", "zzz"):
            cands.add("/%s/%s" % (a, b))
    cands = sorted(cands)
    print("%d candidate paths\n" % len(cands))

    hits = []
    n = 0
    for p in cands:
        n += 1
        try:
            r = call(p, "{}", 0, str(uuid.uuid4()), settle=2.0)
        except Exception:
            continue
        st, gm = None, ""
        for _f, h in r["headers"]:
            if "grpc-status" in h:
                st = h["grpc-status"]
                gm = unquote_plus(h.get("grpc-message", ""))
        if st == "14" or st is None:
            continue
        cmd, res = "", ""
        d = r["data"]
        if len(d) >= 5:
            mlen = int.from_bytes(d[1:5], "big")
            dec = command_response(d[5:5 + mlen])
            cmd, res = dec.get("id") or "", (dec.get("res") or "")[:70]
        print("  %-40s -> grpc=%-4s cmd=%-24s %s"
              % (p[:40], st, cmd, res), flush=True)
        hits.append((p, st, cmd, res))
        if n % 50 == 0:
            print("     ...%d/%d, %d hits" % (n, len(cands), len(hits)), flush=True)

    print("\nswept %d, %d resolved" % (n, len(hits)))
    real = [h for h in hits if h[2] and h[2] != "CMD_END_CONNECTION"]
    if real:
        print("\n=== COMMANDS REACHED ===")
        for p, st, cmd, res in real:
            print("  %-40s %s  %s" % (p, cmd, res))
    else:
        print("\nOnly the default route resolved. The command paths are not")
        print("derivable from the binary's string table, which is why the")
        print("on-device capture is the remaining route to them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
