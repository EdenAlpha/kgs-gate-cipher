#!/usr/bin/env python3
"""Fetch the older eFootball 10.5.1 build from APKCombo.

11.0.1 (what we have) has zeroed vtables.  10.5.1 predates it and may still
carry its relocations, which would make the game's own code runnable.
"""
from __future__ import annotations

import os
import re
import ssl
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work"
UAH = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}


def get(url, timeout=60, headers=None):
    ctx = ssl.create_default_context()
    h = dict(UAH)
    if headers:
        h.update(headers)
    return urllib.request.urlopen(
        urllib.request.Request(url, headers=h), timeout=timeout,
        context=ctx).read()


def main() -> int:
    page = get("https://apkcombo.com/download/jp.konami.pesam/")
    body = page.decode("utf-8", "replace")

    # find the per-version rows and their download links
    print("=== version rows found ===")
    for m in re.finditer(r"(1[01]\.\d+\.\d+)", body):
        v = m.group(1)
        seg = body[max(0, m.start() - 400): m.start() + 400]
        links = re.findall(r'href="([^"]*download[^"]*)"', seg)
        print(f"  {v}: {[l[:110] for l in links[:3]]}")

    print("\n=== all /download/ links on the page ===")
    seen = set()
    for l in re.findall(r'href="([^"]*/download/[^"]*)"', body):
        if l in seen:
            continue
        seen.add(l)
        print("  ", l[:150])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
