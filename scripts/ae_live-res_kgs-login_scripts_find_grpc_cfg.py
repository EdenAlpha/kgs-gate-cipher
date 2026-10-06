#!/usr/bin/env python3
"""Find the gRPC server address/port/path VALUES in the UE4 data packs.

The keys  Def_Online_gRPC_server_address / _port / _path / _insecure
are DataTable row names (UE4 "Def_" config system).  Their values live in
the game data packs (pad_it_0.apk / pad_it_1.apk, ~780 MB of .pak).

Search those for the key names and dump what surrounds them.
"""
from __future__ import annotations

import os
import re
import zipfile

ROOT = (r"C:\Users\Administrator\Documents\Default Project"
        r"\peerlink-efootball-disconnects\efootball-apk\xapk_out")

KEYS = [b"Def_Online_gRPC_server_address", b"Def_Online_gRPC_server_port",
        b"Def_Online_gRPC_server_path", b"Def_Online_gRPC_insecure",
        b"Def_Online_gRPC_Disable", b"Def_Online_gRPC_debug_root_ca",
        b"Def_Online_gRPC_Log_Level", b"Def_Online_Use_Cronet"]


def scan_bytes(label: str, data: bytes) -> None:
    for k in KEYS:
        i = data.find(k)
        if i < 0:
            continue
        st = i - 220
        en = i + 260
        chunk = data[max(0, st):en]
        print(f"\n--- {label}  {k.decode()} @ {i:#x} ---", flush=True)
        # printable runs around it
        for m in re.finditer(rb"[ -~]{4,80}", chunk):
            t = m.group(0).decode("latin1")
            if t.startswith("Def_") and not t.startswith(k.decode()):
                continue
            print(f"    [{m.start()+max(0,st):#x}] {t[:90]!r}", flush=True)


def main() -> int:
    for fn in sorted(os.listdir(ROOT)):
        if not fn.startswith("pad_it"):
            continue
        p = os.path.join(ROOT, fn)
        print(f"\n\n########## {fn}  ({os.path.getsize(p):,} bytes) ##########",
              flush=True)
        try:
            z = zipfile.ZipFile(p)
        except Exception as e:
            print(f"  not a zip: {e}", flush=True)
            continue
        for info in z.infolist():
            print(f"  entry {info.filename}  {info.file_size:,}", flush=True)
            # read in chunks to avoid holding 400MB
            with z.open(info) as f:
                buf = b""
                off = 0
                while True:
                    chunk = f.read(8 << 20)
                    if not chunk:
                        break
                    scan_bytes(f"{fn}:{info.filename}@{off:#x}",
                               buf[-400:] + chunk)
                    buf = chunk
                    off += len(chunk)
    return 0


if __name__ == "__main__":
    main()
