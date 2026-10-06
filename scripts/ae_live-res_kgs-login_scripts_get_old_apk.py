#!/usr/bin/env python3
"""Download eFootball 10.5.1 (and 11.0.0) and check whether their vtables
are populated.

If an older build still has its relative relocations, the game's own code
becomes runnable and the whole login path opens up.
"""
from __future__ import annotations

import io
import os
import re
import struct
import ssl
import sys
import urllib.request
import zipfile

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work"
TEXT_LO, TEXT_HI = 0x28293C0, 0x8B75140


def get(url, timeout=120, headers=None, method="GET"):
    ctx = ssl.create_default_context()
    h = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}
    if headers:
        h.update(headers)
    return urllib.request.urlopen(
        urllib.request.Request(url, headers=h, method=method),
        timeout=timeout, context=ctx)


def find_real_link(page: str) -> str | None:
    m = re.search(r'href="(https?://[^"]*?(?:download|\.apk|\.xapk)[^"]*)"',
                  page)
    return m.group(1) if m else None


def check_zip(raw: bytes, label: str) -> None:
    """Look for libUE4.so inside a single .apk and test its vtables."""
    z = zipfile.ZipFile(io.BytesIO(raw))
    names = z.namelist()
    print(f"  {label}: {len(names)} entries")
    cands = [n for n in names if n.endswith("libUE4.so")]
    if not cands:
        print("    no libUE4.so; top entries:")
        for n in names[:12]:
            print("      ", n)
        return
    for c in cands:
        info = z.getinfo(c)
        print(f"    {c}  {info.file_size} bytes")
        with z.open(info) as f:
            head = f.read(0x200000)
        # a zip member: find the ELF start
        off = head.find(b"\x7fELF")
        if off < 0:
            print("      no ELF header in first 2MB")
            continue
        print("      ELF at member offset", off)


def main() -> int:
    for ver in ("10.5.1", "11.0.0"):
        page_url = (f"https://apkcombo.com/efootball-2024/jp.konami.pesam"
                    f"/download/phone-{ver}-apk")
        print("=" * 70)
        print(ver, page_url)
        try:
            r = get(page_url)
        except Exception as e:
            print("  page FAIL", type(e).__name__, str(e)[:80])
            continue
        page = r.read().decode("utf-8", "replace")
        print(f"  page {len(page)} bytes, final URL {r.geturl()[:110]}")
        real = find_real_link(page)
        if not real:
            print("  no direct link found on the page")
            for k in ("variant", "architecture", "arm64"):
                if k in page:
                    print("   page mentions", k)
            continue
        print("  direct:", real[:150])
        try:
            blob = get(real, timeout=900).read()
        except Exception as e:
            print("  download FAIL", type(e).__name__, str(e)[:80])
            continue
        print(f"  downloaded {len(blob)} bytes")
        dest = os.path.join(OUT, f"efootball_{ver}.apk")
        with open(dest, "wb") as f:
            f.write(blob)
        print("  saved", dest)
        if blob[:2] == b"PK":
            try:
                check_zip(blob, "apk")
            except Exception as e:
                print("   zip inspect failed", e)
        else:
            print("   not a zip; first bytes", blob[:16])
    return 0


if __name__ == "__main__":
    sys.exit(main())
