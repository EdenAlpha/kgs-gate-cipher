#!/usr/bin/env python3
"""Download eFootball 10.5.1's real .apks from Konami's storage and check
whether its vtables are populated."""
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


def fetch(url, timeout=900, headers=None):
    ctx = ssl.create_default_context()
    h = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}
    if headers:
        h.update(headers)
    return urllib.request.urlopen(
        urllib.request.Request(url, headers=h), timeout=timeout,
        context=ctx).read()


def vtable_report(so: bytes, label: str) -> None:
    """Does this .so have DT_RELA/DT_RELR, and are vtables populated?"""
    print(f"  --- {label} ({len(so)} bytes) ---")

    # PT_DYNAMIC: find program headers
    e_phoff = struct.unpack_from("<Q", so, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", so, 0x36)[0]
    e_phnum = struct.unpack_from("<H", so, 0x38)[0]
    dyn = None
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", so, o)[0]
        if p_type == 2:                       # PT_DYNAMIC
            dyn = (struct.unpack_from("<Q", so, o + 8)[0],
                   struct.unpack_from("<Q", so, o + 0x20)[0],
                   struct.unpack_from("<Q", so, o + 0x18)[0])
            break
    if not dyn:
        print("    no PT_DYNAMIC")
        return
    vaddr, filesz, off = dyn
    tags = {}
    i = 0
    while i + 16 <= filesz:
        t, v = struct.unpack_from("<QQ", so, off + i)
        if t == 0:
            break
        tags.setdefault(t, v)
        i += 16
    print(f"    dynamic entries: {len(tags)}")
    for t, name in ((7, "DT_RELA"), (8, "DT_RELASZ"), (9, "DT_RELAENT"),
                    (36, "DT_RELR"), (37, "DT_RELRENT"), (35, "DT_RELRSZ"),
                    (0x6fffe000, "DT_ANDROID_RELR"),
                    (0x6fffe001, "DT_ANDROID_RELRSZ")):
        if t in tags:
            print(f"      {name:22s} = {tags[t]:#x}")

    # vtable runs in the data segments
    runs = 0
    biggest = (0, 0)
    for p in range(e_phnum):
        o = e_phoff + p * e_phentsize
        if struct.unpack_from("<I", so, o)[0] != 1:      # PT_LOAD
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
    print(f"    largest: {biggest[0]:#x} with {biggest[1]} slots")
    print("    VERDICT:", "VABLES PRESENT" if runs > 2 else
          "vtables still absent")


def main() -> int:
    page = ("https://apkcombo.com/efootball-2024/jp.konami.pesam"
            "/download/phone-10.5.1-apk").encode()
    html = fetch(page.decode()).decode("utf-8", "replace")
    m = re.search(r'href="(/r2\?u=[^"]+)"', html)
    if not m:
        print("no /r2 link found")
        return 1
    real = urllib.parse.unquote(m.group(1))
    real = "https://apkcombo.com" + real
    print("target:", real[:200])
    blob = fetch(real)
    print("downloaded", len(blob), "bytes; magic", blob[:4])
    dest = os.path.join(OUT, "efootball_10.5.1.apks")
    with open(dest, "wb") as f:
        f.write(blob)
    print("saved", dest)

    # an .apks is a zip of splits; find whichever split has libUE4.so
    z = zipfile.ZipFile(io.BytesIO(blob))
    print("\nsplits:")
    for i in z.infolist():
        print(f"   {i.filename:44s} {i.file_size:>12,}")
    for i in z.infolist():
        if not i.filename.endswith(".apk"):
            continue
        inner = zipfile.ZipFile(io.BytesIO(z.read(i)))
        cands = [n for n in inner.namelist() if n.endswith("libUE4.so")]
        if cands:
            print(f"\n>>> {i.filename} carries libUE4.so")
            with inner.open(cands[0]) as f:
                so = f.read()
            with open(os.path.join(OUT, "libUE4_10.5.1.so"), "wb") as f:
                f.write(so)
            vtable_report(so, i.filename)
    return 0


if __name__ == "__main__":
    sys.exit(main())
