#!/usr/bin/env python3
"""Try to fetch an older eFootball APK that may predate the vtable stripping.

Play Store's current build is 11.0.1, which is the copy we already have and
whose vtables are zero.  Older releases are worth trying: the stripping may
have been introduced by a later build.

Strategy, in order of reliability:
  1. apkpure's version list (403s on plain fetch, so try their API host)
  2. apkcombo's /download/<pkg>/versions/  (also 404s on the guessed path)
  3. Play Store's own version-archive endpoints
Nothing is installed or executed; we only read the download page.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.request

PKG = "jp.konami.pesam"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work"


def get(url, headers=None, timeout=40):
    ctx = ssl.create_default_context()
    h = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    return urllib.request.urlopen(req, timeout=timeout, context=ctx).read()


def main() -> int:
    targets = [
        f"https://d.apkpure.com/b/APK/jp.konami.pesam?version=latest",
        f"https://apkpure.com/{PKG}/versions",
        f"https://apkpure.net/{PKG}/versions",
        f"https://apkcombo.com/{PKG}/",
        f"https://apkcombo.com/download/{PKG}/",
        f"https://apkpure.net/{PKG}/download",
    ]
    for u in targets:
        try:
            d = get(u)
            body = d.decode("utf-8", "replace")
            print(f"OK   {u}  ({len(d)} bytes)")
            name = re.sub(r"[^a-zA-Z0-9]+", "_", u)[-60:] + ".html"
            with open(OUT + "\\" + name, "w", encoding="utf-8") as f:
                f.write(body)
            vers = sorted(set(re.findall(r"\b1[01]\.\d+\.\d+\b", body)),
                          reverse=True)
            if vers:
                print("      versions seen:", vers[:14])
            links = re.findall(r"https?://[^\"'\s]+?(?:download|d\.apkpure|"
                               r"file\.apk)[^\"'\s]*", body)
            for l in links[:8]:
                print("      link:", l[:160])
        except Exception as e:
            print(f"FAIL {u}  {type(e).__name__}: {str(e)[:70]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
