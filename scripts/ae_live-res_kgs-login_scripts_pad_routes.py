#!/usr/bin/env python3
"""Scan the 780 MB asset packs for command route strings.

The base APK and every `config.*` split yielded nothing, so the route table — if
it is shipped at all — is in `pad_it_0.apk` / `pad_it_1.apk`. Those are read
straight out of the XAPK and scanned for route-shaped strings without being
extracted to disk.

To keep it tractable the scan looks for the byte pattern that starts a route
(`/a` .. `/z`) rather than running a full regex over everything, and only keeps
candidates that are delimited on the left by a NUL, quote or brace.
"""
from __future__ import annotations

import io
import json
import os
import re
import time
import zipfile

XAPK = os.path.expanduser(r"~\Downloads\apk\jp.konami.pesam.xapk")
OUT = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work"
       r"\pad_routes.txt")

ROUTE = re.compile(rb"/[a-z][a-z0-9_.\-]{2,40}(?:/[a-z0-9_.\-]{2,40}){0,3}")
DELIM = (b"\x00", b'"', b"'", b" ", b"\n", b"\r", b"\t", b",", b"[", b"]",
         b"{", b"}", b":")
SKIP = re.compile(rb"^/(usr|proc|sys|dev|lib|bin|etc|var|tmp|opt|home|root|"
                  rb"basic|google|android|codegen|common|system|vendor|data|"
                  rb"build|out|src|third_party|textures|shaders|sound|font|"
                  rb"material|animation|montage|cinematic|umap|blueprint)"
                  rb"(/|$)")


def main() -> int:
    z = zipfile.ZipFile(XAPK)
    mf = json.loads(z.read("manifest.json"))
    targets = [e["file"] for e in mf["split_apks"]
               if e.get("id") in ("pad_it_0", "pad_it_1")]
    print("scanning %s\n" % targets, flush=True)
    seen: dict = {}
    t0 = time.time()
    for apk in targets:
        with z.open(apk) as f:
            data = f.read()
        print("  %s: %.1f MB in memory, scanning..." % (apk, len(data) / 1e6),
              flush=True)
        n = 0
        for m in ROUTE.finditer(data):
            s = m.group(0)
            if SKIP.match(s):
                continue
            i = m.start()
            if i and data[i - 1:i] not in DELIM:
                continue
            seen.setdefault(s, 0)
            seen[s] += 1
            n += 1
        print("  %s: %d candidate occurrences, %d distinct so far (%.0fs)"
              % (apk, n, len(seen), time.time() - t0), flush=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        for s, c in sorted(seen.items(), key=lambda kv: -kv[1]):
            fh.write("%s\t%d\n" % (s.decode("latin1"), c))
    print("\n%d distinct route-shaped strings -> %s"
          % (len(seen), OUT))
    for s, c in sorted(seen.items(), key=lambda kv: -kv[1])[:60]:
        print("  %-52s %d" % (s.decode("latin1"), c))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
