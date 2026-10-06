#!/usr/bin/env python3
"""What did the phone do on its TLS connections to Konami in the seconds
around each stall?  We cannot see the replies (capture is outbound-only),
but we CAN see when the phone opens, uses, and closes a connection."""
from __future__ import annotations

import sys
from collections import defaultdict

from stall_focus import load, ROOT, STALLS, T0, wall  # type: ignore


def tls_records(buf: bytes):
    """Parse outbound TLS records (type, ver, len). Returns [] if not TLS."""
    out = []
    off = 0
    while off + 5 <= len(buf):
        typ = buf[off]
        ver = buf[off + 1:off + 3].hex()
        ln = int.from_bytes(buf[off + 3:off + 5], "big")
        if typ not in (20, 21, 22, 23) or ln > 18432 or off + 5 + ln > len(buf):
            return out
        out.append((typ, ver, ln))
        off += 5 + ln
    return out


RTN = {20: "CCS", 21: "ALERT", 22: "HS", 23: "APP"}


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "z1-tiamant-client"
    recs = load(f"{ROOT}\\{which}\\passthrough_capture.csv")
    print(f"=== {which} ===")

    ip2name = {}
    for r in recs:
        if r["kind"] == "dns" and r["ans"]:
            for rt, val in r["ans"]:
                if rt == 1:
                    ip2name[val] = r["name"]

    tcp = [r for r in recs if r["proto"] == 6]
    konami = [r for r in tcp if "konami" in ip2name.get(
        r["dst"] if r["dport"] == 443 else r["src"], "")]

    # connection lifecycle keyed by local port
    conns = defaultdict(list)
    for r in konami:
        conns[r["sport"]].append(r)

    print(f"\n  konami TLS connections: {len(conns)}")

    for s, e, tag in STALLS:
        print(f"\n############ {tag}  stall {wall(s)}..{wall(e)} ############")
        # connections alive or born in a +-15 s window
        for port, pkts in sorted(conns.items(),
                                 key=lambda kv: kv[1][0]["ts"]):
            pkts.sort(key=lambda x: x["ts"])
            a, b = pkts[0]["ts"], pkts[-1]["ts"]
            if b < s - 15000 or a > e + 15000:
                continue
            host = ip2name.get(pkts[0]["dst"], pkts[0]["dst"])
            born = "BORN" if a > s - 15000 else ""
            died = "DIED" if b <= e + 15000 and b >= s - 15000 else ""
            print(f"\n  --- sport={port} {host} n={len(pkts)} "
                  f"{wall(a)}..{wall(b)} {born} {died}")
            for r in pkts:
                if not (s - 6000 <= r["ts"] <= e + 6000):
                    continue
                body = r["_payload"]
                recs2 = tls_records(body) if body else []
                desc = ",".join(f"{RTN.get(t, t)}:{ln}"
                                for t, _v, ln in recs2) if recs2 else (
                    "len%d" % len(body) if body else "ack")
                flags = r["flags"]
                mark = ""
                if r["ts"] >= s:
                    mark = "  <<<STALL>>>"
                print(f"      {wall(r['ts'])} {flags:<4} {desc:<34} "
                      f"{r['src']}:{r['sport']} -> {r['dst']}:{r['dport']}"
                      f"{mark}")

    # fresh connections opened after each stall (rejoin evidence)
    print("\n\n=== connections OPENED after each stall start ===")
    for s, e, tag in STALLS:
        print(f"  [{tag} {wall(s)}]")
        for port, pkts in sorted(conns.items(), key=lambda kv: kv[1][0]["ts"]):
            a = pkts[0]["ts"]
            if s < a <= e + 20000:
                host = ip2name.get(pkts[0]["dst"], pkts[0]["dst"])
                print(f"      {wall(a)}  sport={port} {host} n={len(pkts)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
