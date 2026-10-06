#!/usr/bin/env python3
"""Hex + ascii dump of the Konami UDP keepalive flow around each stall."""
from __future__ import annotations

import sys
from collections import defaultdict

from stall_focus import load, ROOT, STALLS, T0, wall  # type: ignore


def hx(b: bytes) -> str:
    return b.hex()


def asc(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


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

    # candidate flows: UDP remotes that are NOT dns / not the 5521-sweep
    flows = defaultdict(list)
    for r in recs:
        if r["proto"] != 17:
            continue
        if r["dir"] == "t":
            if r["dport"] in (53, 5521, 10000, 30000, 50000):
                continue
            key = (r["dst"], r["dport"])
        else:
            if r["sport"] in (53, 5521, 10000, 30000, 50000):
                continue
            key = (r["src"], r["sport"])
        flows[key].append(r)

    print("\n  candidate Konami UDP flows:")
    for k, v in sorted(flows.items(), key=lambda kv: -len(kv[1]))[:14]:
        print(f"    {k[0]:<18}:{k[1]:<6} n={len(v):<5} "
              f"{wall(v[0]['ts'])}..{wall(v[-1]['ts'])}  {ip2name.get(k[0],'')}")

    for s, e, tag in STALLS:
        print(f"\n############ {tag}  stall {wall(s)}..{wall(e)} ############")
        for k, v in sorted(flows.items()):
            # flow that ends just before this stall
            if not (s - 12000 <= v[-1]["ts"] <= s + 3000):
                continue
            if len(v) < 20:
                continue
            print(f"\n  --- flow {k[0]}:{k[1]} n={len(v)} ---")
            # first 6 packets (setup)
            print("  FIRST (setup):")
            for r in v[:6]:
                body = r["_payload"]
                print(f"    {wall(r['ts'])} {r['dir']} len={len(body):<4} "
                      f"{r['src']}:{r['sport']} -> {r['dst']}:{r['dport']}")
                print(f"      hex {hx(body)}")
                print(f"      asc {asc(body)}")
            print("  LAST 20 (death):")
            for r in v[-20:]:
                body = r["_payload"]
                mark = ""
                if r["ts"] >= s:
                    mark = " <<<STALL>>>"
                elif s - r["ts"] <= 4000:
                    mark = " <<PRE>>"
                print(f"    {wall(r['ts'])} {r['dir']} len={len(body):<4} "
                      f"{r['src']}:{r['sport']} -> {r['dst']}:{r['dport']}"
                      f"{mark}")
                print(f"      hex {hx(body)}")
                print(f"      asc {asc(body)}")

            # sizes distribution
            sizes = defaultdict(lambda: [0, 0])
            for r in v:
                sizes[(r["dir"], len(r["_payload"]))][0] += 1
            print("  size histogram (dir,len -> out,in):")
            for (d, L), (a, b) in sorted(sizes.items()):
                print(f"    {d} len={L:<5} out={a:<4} in={b}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
