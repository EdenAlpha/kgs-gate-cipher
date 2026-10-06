#!/usr/bin/env python3
"""Quantify what starts/stops at each stall, on both phones."""
from __future__ import annotations

import sys
from collections import defaultdict

from stall_focus import load, ROOT, STALLS, T0, wall  # type: ignore


def analyse(which: str):
    recs = load(f"{ROOT}\\{which}\\passthrough_capture.csv")
    print(f"\n################ {which}  packets={len(recs)} ################")

    # --- ip -> name from DNS answers -------------------------------
    ip2name = defaultdict(set)
    for r in recs:
        if r["kind"] == "dns" and r["ans"]:
            for rt, val in r["ans"]:
                if rt in (1, 28):
                    ip2name[val].add(r["name"])
    def nm(ip):
        n = ip2name.get(ip)
        return sorted(n)[0] if n else ip

    # --- remote flow lifetimes -------------------------------------
    flows = defaultdict(lambda: [0, None, None, 0, 0])
    for r in recs:
        remote = r["dst"] if r["dir"] == "t" else r["src"]
        rp = r["dport"] if r["dir"] == "t" else r["sport"]
        key = (r["proto"], remote, rp)
        f = flows[key]
        f[0] += 1
        f[1] = r["ts"] if f[1] is None else min(f[1], r["ts"])
        f[2] = r["ts"] if f[2] is None else max(f[2], r["ts"])
        if r["dir"] == "t":
            f[3] += 1
        else:
            f[4] += 1

    print("\n  flows whose LAST packet lands within 12s of a stall start:")
    for s, e, tag in STALLS:
        hits = []
        for k, (n, a, b, to, fr) in flows.items():
            if b is None:
                continue
            d = b - s
            if -12000 <= d <= 12000:
                hits.append((d, k, n, a, b, to, fr))
        print(f"   [{tag} start {wall(s)}]")
        for d, k, n, a, b, to, fr in sorted(hits):
            print(f"      end {d:+7d}ms  {k[0]:<4} {nm(k[1]):<46} :{k[2]:<6} "
                  f"n={n:<5} life {wall(a)}..{wall(b)}  out/in {to}/{fr}")

    print("\n  flows whose FIRST packet lands within 12s of a stall start:")
    for s, e, tag in STALLS:
        hits = []
        for k, (n, a, b, to, fr) in flows.items():
            d = a - s
            if -12000 <= d <= 12000:
                hits.append((d, k, n, a, b, to, fr))
        print(f"   [{tag} start {wall(s)}]")
        for d, k, n, a, b, to, fr in sorted(hits):
            print(f"      start {d:+7d}ms {k[0]:<4} {nm(k[1]):<46} :{k[2]:<6} "
                  f"n={n:<5} life {wall(a)}..{wall(b)}  out/in {to}/{fr}")

    # --- agones / region-sweep timing ------------------------------
    sweep = [r for r in recs
             if r["kind"] == "dns" and "agones-ping" in r["name"]]
    print(f"\n  agones-ping DNS queries: {len(sweep)}")
    if sweep:
        groups = []
        for r in sweep:
            if groups and r["ts"] - groups[-1][1] < 60000:
                groups[-1][1] = r["ts"]
                groups[-1][2] += 1
            else:
                groups.append([r["ts"], r["ts"], 1])
        for a, b, c in groups:
            inside = [tag for s, e, tag in STALLS if a <= e and b >= s]
            print(f"      {wall(a)} .. {wall(b)}  n={c:<4} "
                  f"{'STALL ' + ','.join(inside) if inside else 'OUTSIDE'}")

    # --- the 5521 / 10000 / 30000 / 50000 probe sweep --------------
    print("\n  UDP probe sweep (ports 5521/10000/30000/50000) timing:")
    probed = defaultdict(list)
    for r in recs:
        if r["proto"] == 17 and r["dport"] in (5521, 10000, 30000, 50000) \
                and r["dir"] == "t":
            probed[r["dport"]].append(r["ts"])
    for p, ts in sorted(probed.items()):
        groups = []
        for t in sorted(ts):
            if groups and t - groups[-1][1] < 60000:
                groups[-1][1] = t
                groups[-1][2] += 1
            else:
                groups.append([t, t, 1])
        for a, b, c in groups:
            inside = [tag for s, e, tag in STALLS if a <= e and b >= s]
            print(f"      :{p:<5} {wall(a)} .. {wall(b)}  n={c:<5} "
                  f"{'STALL ' + ','.join(inside) if inside else 'OUTSIDE'}")

    # --- every non-DNS packet in +-3s of each stall start ----------
    for s, e, tag in STALLS:
        print(f"\n  non-DNS packets {wall(s-3000)}..{wall(s+3000)} [{tag}]:")
        for r in recs:
            if not (s - 3000 <= r["ts"] <= s + 3000):
                continue
            if r["kind"] == "dns":
                continue
            remote = r["dst"] if r["dir"] == "t" else r["src"]
            rp = r["dport"] if r["dir"] == "t" else r["sport"]
            mark = " <<<" if r["ts"] >= s else ""
            print(f"      {wall(r['ts'])} {r['dir']} p{r['proto']:<3} "
                  f"{r['src']:>15}:{r['sport']:<6} -> {r['dst']:>15}:{rp:<6} "
                  f"{r['flags']:<4} {nm(remote)}{mark}")


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else None
    for w in ([which] if which else
              ["z1-tiamant-client", "z2-elijah-hotspot-owner"]):
        analyse(w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
