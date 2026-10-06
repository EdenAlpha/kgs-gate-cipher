#!/usr/bin/env python3
"""Search the APK's own assets for the command route table.

`libUE4.so` does not contain the command paths, but the game's configuration
does: the base APK ships assets, and Konami keeps service route tables in
configuration rather than in code. This walks every entry in the base APK
(22 MB) and the small `config.*` splits, and reports any string that looks like
a command route — a leading slash, lowercase, short, no file extension — along
with which file it came from.

Compressed asset blobs are searched in their stored form first; if a candidate
file is itself compressed (gzip/zlib), it is inflated and searched too, since
route tables are usually stored deflated.
"""
from __future__ import annotations

import binascii
import io
import json
import os
import re
import sys
import zipfile
import zlib

XAPK = os.path.expanduser(r"~\Downloads\apk\jp.konami.pesam.xapk")

# a route: leading slash, lowercase-ish, 2..48 chars, 1..3 segments
ROUTE = re.compile(rb"/[a-z][a-z0-9_.-]{1,40}(?:/[a-z0-9_.-]{1,40}){0,2}\b")
# things that are definitely not routes
SKIP = re.compile(rb"^/(usr|proc|sys|dev|lib|bin|etc|var|tmp|opt|home|root|"
                  rb"basic|google|android|codegen|common|system|vendor|data|"
                  rb"build|out|src|third_party)(/|$)")


def interesting(path: str) -> bool:
    low = path.lower()
    return not low.endswith((".png", ".jpg", ".jpeg", ".webp", ".mp3", ".wav",
                             ".ogg", ".mp4", ".ttf", ".otf", ".so", ".dex",
                             ".arsc", ".resources.arsc", ".rcc", ".obb"))


def scan_bytes(blob: bytes, origin: str, out: dict, limit=4000):
    for m in ROUTE.finditer(blob):
        s = m.group(0)
        if SKIP.match(s):
            continue
        # must be surrounded by a delimiter, not part of a longer token
        i = m.start()
        if i and blob[i - 1:i] not in (b"\x00", b'"', b"'", b" ", b"\n", b",",
                                      b"[", b"]", b"{", b"}"):
            continue
        out.setdefault(s, set()).add(origin)


def main() -> int:
    if not os.path.exists(XAPK):
        print("xapk not found at", XAPK)
        return 1
    z = zipfile.ZipFile(XAPK)
    mf = json.loads(z.read("manifest.json"))
    splits = [e for e in mf["split_apks"]
              if e.get("id") == "base" or str(e.get("id", "")).startswith("config.")]
    found: dict = {}
    scanned = 0
    for e in splits:
        name = e["file"]
        if name.endswith("pad_it_0.apk") or name.endswith("pad_it_1.apk"):
            continue
        try:
            inner = zipfile.ZipFile(io.BytesIO(z.read(name)))
        except Exception as ex:
            print("  %-28s cannot open: %s" % (name, ex))
            continue
        names = inner.namelist()
        assets = [n for n in names if n.startswith("assets/")
                  or n.endswith((".json", ".xml", ".ini", ".cfg", ".txt",
                                 ".dat", ".csv", ".properties", ".yaml",
                                 ".yml", ".list", ".bin", ".bytes"))]
        assets = [n for n in assets if interesting(n)]
        print("%-28s %d entries, %d candidate text/config files"
              % (name, len(names), len(assets)))
        for n in assets:
            try:
                raw = inner.read(n)
            except Exception:
                continue
            scanned += 1
            before = len(found)
            scan_bytes(raw, "%s!%s" % (name, n), found)
            # if it looks compressed, inflate and look again
            if raw[:2] in (b"\x1f\x8b", b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
                try:
                    if raw[:2] == b"\x1f\x8b":
                        import gzip
                        raw2 = gzip.decompress(raw)
                    else:
                        raw2 = zlib.decompress(raw)
                    scan_bytes(raw2, "%s!%s(inflated)" % (name, n), found)
                except Exception:
                    pass
            if len(found) > before:
                print("     +%d new route candidates from %s"
                      % (len(found) - before, n))
            if scanned % 200 == 0:
                print("     ...%d files scanned, %d candidates" % (scanned,
                                                                    len(found)))
    print("\nscanned %d files, %d distinct route-shaped strings\n"
          % (scanned, len(found)))
    for s, origins in sorted(found.items()):
        o = sorted(origins)[0]
        print("  %-46s %s" % (s.decode("latin1"), o))
    with open(r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work"
              r"\asset_routes.txt", "w", encoding="utf-8") as f:
        for s, origins in sorted(found.items()):
            f.write("%s\t%s\n" % (s.decode("latin1"), ";".join(sorted(origins))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
