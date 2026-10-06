#!/usr/bin/env python3
"""What is the current Play Store version, and can we get its APK?"""
from __future__ import annotations

import json
import re
import ssl
import urllib.parse
import urllib.request

PKG = "jp.konami.pesam"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work"


def get(url, data=None, headers=None):
    ctx = ssl.create_default_context()
    h = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h)
    return urllib.request.urlopen(req, timeout=45, context=ctx).read()


def main() -> int:
    page = get(f"https://play.google.com/store/apps/details?id={PKG}&hl=en&gl=US"
               ).decode("utf-8", "replace")
    print("store page bytes:", len(page))
    with open(OUT + r"\play_page.html", "w", encoding="utf-8") as f:
        f.write(page)

    vers = sorted(set(re.findall(r"\b\d+\.\d+\.\d+\b", page)),
                  key=lambda s: [int(x) for x in s.split(".")],
                  reverse=True)
    print("version-like strings on the page (top 12):", vers[:12])

    m = re.search(r"Current Version[^0-9]{0,40}(\d+\.\d+\.\d+)", page)
    print("explicit 'Current Version':", m.group(1) if m else "not found")

    for pat in (r"\bBuild\s*(\d+)\b", r"\b(\d{9,10})\b"):
        got = sorted(set(re.findall(pat, page)))[:5]
        if got:
            print("  %-22s %s" % (pat, got))

    # the version record the store embeds
    for key in ("[null,[2,[[", "AF_initDataCallback"):
        idx = page.find(key)
        print("  %-20s at %s" % (key, idx))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
