#!/usr/bin/env python3
"""Fetch the .apks straight from R2 storage, bypassing APKCombo's /r2 shim."""
from __future__ import annotations

import io
import os
import re
import ssl
import struct
import sys
import urllib.parse
import urllib.request
import zipfile

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
OUT = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work"
TEXT_LO, TEXT_HI = 0x28293C0, 0x8B75140


def fetch(url, timeout=900, referer=None):
    ctx = ssl.create_default_context()
    h = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9"}
    if referer:
        h["Referer"] = referer
    return urllib.request.urlopen(
        urllib.request.Request(url, headers=h), timeout=timeout,
        context=ctx).read()


def vtable_report(so: bytes, label: str) -> None:
    print(f"\n  --- {label}: {len(so):,} bytes ---")
    e_phoff = struct.unpack_from("<Q", so, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", so, 0x36)[0]
    e_phnum = struct.unpack_from("<H", so, 0x38)[0]
    tags = {}
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", so, o)[0] != 2:      # not PT_DYNAMIC
            continue
        vaddr, filesz, off = (struct.unpack_from("<Q", so, o + 8)[0],
                              struct.unpack_from("<Q", so, o + 0x20)[0],
                              struct.unpack_from("<Q", so, o + 0x18)[0])
        j = 0
        while j + 16 <= filesz:
            t, v = struct.unpack_from("<QQ", so, off + j)
            if t == 0:
                break
            tags.setdefault(t, v)
            j += 16
    print(f"    dynamic entries: {len(tags)}")
    for t, name in ((7, "DT_RELA"), (8, "DT_RELASZ"), (9, "DT_RELAENT"),
                    (36, "DT_RELR"), (37, "DT_RELRENT"), (35, "DT_RELRSZ"),
                    (0x6fffe000, "DT_ANDROID_RELR"),
                    (0x6fffe001, "DT_ANDROID_RELRSZ"),
                    (0x6ffffff9, "DT_RELACOUNT")):
        if t in tags:
            print(f"      {name:22s} = {tags[t]:#x}")

    runs = 0
    biggest = (0, 0)
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", so, o)[0] != 1:
            continue
        p_off = struct.unpack_from("<Q", so, o + 8)[0]
        p_fsz = struct.unpack_from("<Q", so, o + 0x20)[0]
        if p_fsz == 0 or p_off + p_fsz > len(so):
            continue
        seg = so[p_off:p_off + p_fsz]
        n = len(seg) // 8
        cur = -1
        for k in range(n + 1):
            v = struct.unpack_from("<Q", seg, k * 8)[0] if k < n else 0
            ok = TEXT_LO <= v < TEXT_HI
            if ok and cur < 0:
                cur = k
            if not ok and cur >= 0:
                if k - cur >= 3:
                    runs += 1
                    if k - cur > biggest[1]:
                        biggest = (p_off + cur * 8, k - cur)
                cur = -1
    print(f"    vtable-shaped runs (>=3 text ptrs): {runs}")
    print(f"    largest table: {biggest[0]:#x} ({biggest[1]} slots)")
    print("    VERDICT:", "VABLES PRESENT" if runs > 2
          else "vtables still absent")


def main() -> int:
    page = ("https://apkcombo.com/efootball-2024/jp.konami.pesam"
            "/download/phone-10.5.1-apk")
    html = fetch(page).decode("utf-8", "replace")
    m = re.search(r'href="(/r2\?u=([^"]+))"', html)
    if not m:
        print("no /r2 link")
        return 1
    direct = urllib.parse.unquote(m.group(2))
    print("R2 url:", direct[:220], "\n")

    for attempt, url in (("R2 direct", direct),
                         ("R2 via r2 shim", "https://apkcombo.com"
                          + m.group(1))):
        try:
            blob = fetch(url, referer=page)
        except Exception as e:
            print(f"{attempt}: FAIL {type(e).__name__} {str(e)[:60]}")
            continue
        print(f"{attempt}: {len(blob):,} bytes, magic {blob[:4]!r}")
        if blob[:2] != b"PK":
            print("   not a zip --", blob[:120])
            continue
        dest = os.path.join(OUT, "efootball_10.5.1.apks")
        with open(dest, "wb") as f:
            f.write(blob)
        z = zipfile.ZipFile(io.BytesIO(blob))
        print("   splits:")
        for i in z.infolist():
            print(f"      {i.filename:40s} {i.file_size:>13,}")
        for i in z.infolist():
            if not i.filename.endswith(".apk"):
                continue
            inner = zipfile.ZipFile(io.BytesIO(z.read(i)))
            for c in [n for n in inner.namelist() if n.endswith("libUE4.so")]:
                print(f"\n   >>> {i.filename} has {c}")
                so = inner.read(c)
                with open(os.path.join(OUT, "libUE4_10.5.1.so"), "wb") as f:
                    f.write(so)
                vtable_report(so, i.filename)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
