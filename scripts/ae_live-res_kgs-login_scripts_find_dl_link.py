#!/usr/bin/env python3
"""Pull the real download link out of an APKCombo version page."""
from __future__ import annotations

import re
import ssl
import sys
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work"


def fetch(url):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url, headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
    return urllib.request.urlopen(req, timeout=60, context=ctx).read()


def main() -> int:
    url = ("https://apkcombo.com/efootball-2024/jp.konami.pesam"
           "/download/phone-10.5.1-apk")
    d = fetch(url).decode("utf-8", "replace")
    with open(OUT + r"\dlpage.html", "w", encoding="utf-8") as f:
        f.write(d)
    print("page bytes", len(d))

    hrefs = list(dict.fromkeys(re.findall(r'href="([^"]+)"', d)))
    print("\n--- hrefs mentioning download / apk / dl ---")
    for h in hrefs:
        if any(k in h for k in ("download", ".apk", ".xapk", "dl.", "?id=")):
            print("   ", h[:180])

    print("\n--- data-* attributes with urls ---")
    for m in re.findall(r'data-[a-z-]+="([^"]*https?://[^"]*)"', d):
        print("   ", m[:180])

    print("\n--- <a> blocks with 'variant' / arm64 ---")
    for m in re.finditer(r'<a[^>]*>(.{0,400}?)</a>', d, re.S):
        blk = m.group(0)
        if re.search(r'arm64|apk\b|variant', blk, re.I):
            txt = re.sub(r"<[^>]+>", " ", blk)
            txt = re.sub(r"\s+", " ", txt).strip()
            if txt:
                print("   ", txt[:140])
    return 0


if __name__ == "__main__":
    sys.exit(main())
