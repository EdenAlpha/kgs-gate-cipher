#!/usr/bin/env python3
"""Scan every match export for the game's gRPC ClientHello (ALPN grpc-exp/h2).

Export 1790619339531 turned out to contain only ALPN=http/1.1 handshakes to
pes22-game.cs.konami.net -- no gRPC connection at all. The gRPC handshake this
hunt needs is in some other export, so all of them are scanned and ranked by
whether a gRPC ClientHello is present.
"""
from __future__ import annotations

import collections
import glob
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract_game_hello import parse_client_hello, detail, tcp_segments, NAME  # noqa: E402

PAT = (r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\uploads"
       r"\*\peerlink_match_*.zip")
import binascii  # noqa: E402


def hellos_from_csv(data: str):
    for line in data.splitlines():
        if line.startswith("#"):
            continue
        parts = line.rstrip("\n").split(",")
        if len(parts) < 9:
            continue
        # ts_ms,dir,proto,src,sport,dst,dport,ip_len,payload_hex
        #  0    1     2     3    4     5    6      7       8
        try:
            dport = int(parts[6])
            raw = binascii.unhexlify(parts[8].strip())
        except Exception:
            continue
        if dport != 443:
            continue
        pay = tcp_segments(raw)
        if not pay or len(pay) < 60 or pay[0] != 0x16:
            continue
        for info in parse_client_hello(pay):
            sni = alpn = ""
            for et, body in info["exts"]:
                if et == 0:
                    sni = detail(et, body)
                elif et == 16:
                    alpn = detail(et, body)
            yield parts[1], parts[3], parts[5], sni, alpn, info


def main() -> int:
    found = []
    print("%-22s %6s %6s  %s" % ("export", "hellos", "grpc", "pes22-game SNIs seen"))
    for z in sorted(glob.glob(PAT)):
        name = os.path.basename(z)[len("peerlink_match_"):-len(".zip")]
        try:
            with zipfile.ZipFile(z) as zf:
                n = [x for x in zf.namelist() if x.endswith("passthrough_capture.csv")]
                if not n:
                    continue
                data = zf.read(n[0]).decode("utf-8", "replace")
        except Exception as e:
            print("%-22s ERROR %s" % (name, e))
            continue
        total = 0
        grpc = []
        snis = collections.Counter()
        for d, src, dst, sni, alpn, info in hellos_from_csv(data):
            total += 1
            if "pes22-game" in sni:
                snis[alpn] += 1
            if "grpc" in alpn:
                grpc.append((d, src, dst, sni, alpn, info))
        print("%-22s %6d %6d  %s"
              % (name, total, len(grpc), dict(snis) or "-"))
        for g in grpc:
            found.append((name,) + g)
    if not found:
        print("\nNO gRPC ClientHello in any export.")
        return 1
    print("\n" + "=" * 74)
    for name, d, src, dst, sni, alpn, info in found:
        vers = ""
        for et, body in info["exts"]:
            if et == 43:
                vers = detail(et, body)
        print("\n### export %s   dir=%s  %s -> %s" % (name, d, src, dst))
        print("  SNI                 %s" % sni)
        print("  ALPN                [%s]" % alpn)
        print("  record bytes        %d" % len(info["raw"]))
        print("  legacy_version      0x%03x" % info["ver"])
        print("  supported_versions  %s" % (vers or "(none -> TLS 1.2 only)"))
        print("  ciphers (%d)         %s"
              % (len(info["ciphers"]), " ".join(hex(c) for c in info["ciphers"])))
        print("  extensions (%d)      %s"
              % (len(info["exts"]),
                 " ".join(NAME.get(et, hex(et)) for et, _ in info["exts"])))
        h = info["raw"].hex()
        for i in range(0, len(h), 64):
            print("    %s" % h[i:i + 64])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
