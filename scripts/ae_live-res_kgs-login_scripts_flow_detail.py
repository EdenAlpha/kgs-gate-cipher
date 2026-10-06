#!/usr/bin/env python3
"""Full flow table + forensic detail on flows that die near a stall."""
from __future__ import annotations

import sys
from collections import defaultdict

from stall_focus import load, ROOT, STALLS, T0, wall  # type: ignore


def analyse(which: str):
    recs = load(f"{ROOT}\\{which}\\passthrough_capture.csv")
    print(f"\n################ {which}  packets={len(recs)} ################")

    ip2name = defaultdict(set)
    for r in recs:
        if r["kind"] == "dns" and r["ans"]:
            for rt, val in r["ans"]:
                if rt in (1, 28):
                    ip2name[val].add(r["name"])
    def nm(ip):
        n = ip2name.get(ip)
        return sorted(n)[0] if n else ""

    # ---------- flow table ----------------------------------------
    flows = defaultdict(lambda: dict(n=0, o=0, i=0, a=None, b=None,
                                     ob=0, ib=0, pkts=[]))
    for r in recs:
        remote = r["dst"] if r["dir"] == "t" else r["src"]
        rp = r["dport"] if r["dir"] == "t" else r["sport"]
        k = (r["proto"], remote, rp)
        f = flows[k]
        f["n"] += 1
        f["a"] = r["ts"] if f["a"] is None else min(f["a"], r["ts"])
        f["b"] = r["ts"] if f["b"] is None else max(f["b"], r["ts"])
        if r["dir"] == "t":
            f["o"] += 1
            f["ob"] += r["n"]
        else:
            f["i"] += 1
            f["ib"] += r["n"]
        f["pkts"].append(r)

    print("\n  --- ALL flows (match window 00:04:00..00:33:00) ---")
    print(f"  {'proto':<5}{'remote':<46}{':port':<8}{'n':<6}{'out/in':<10}"
          f"{'life':<30}name")
    rows = sorted(flows.items(), key=lambda kv: kv[1]["a"])
    for k, f in rows:
        if f["b"] - T0 < 240000 or f["a"] - T0 > 1980000:
            continue
        life = f"{wall(f['a'])}..{wall(f['b'])}"
        name = nm(k[1])
        tag = ""
        for s, e, t in STALLS:
            if f["b"] >= s - 6000 and f["a"] <= s:
                tag += f" <die~{t}>"
            if f["a"] > s and f["a"] < e + 5000:
                tag += f" <born~{t}>"
        print(f"  {k[0]:<5}{k[1]:<46}{':' + str(k[2]):<8}{f['n']:<6}"
              f"{str(f['o']) + '/' + str(f['i']):<10}{life:<30}{name}{tag}")

    # ---------- detail on flows dying near a stall -----------------
    for s, e, tag in STALLS:
        print(f"\n  === flows DYING within 8s before {tag} ({wall(s)}) ===")
        for k, f in rows:
            if not (s - 8000 <= f["b"] <= s + 2000):
                continue
            print(f"    {k[0]} {k[1]}:{k[2]} {nm(k[1])} "
                  f"n={f['n']} out/in={f['o']}/{f['i']} "
                  f"bytes {f['ob']}/{f['ib']}")
            tail = f["pkts"][-34:]
            prev = None
            for r in tail:
                gap = "" if prev is None else f" +{r['ts']-prev}ms"
                prev = r["ts"]
                mark = " <<<" if r["ts"] >= s else ""
                print(f"      {wall(r['ts'])} {r['dir']} len={r['n']:<5} "
                      f"{r['src']:>15}:{r['sport']:<6} -> "
                      f"{r['dst']:>15}:{r['dport']:<6} {r['flags']:<4}"
                      f"{gap}{mark}")

    # ---------- outbound-only quitters ----------------------------
    print("\n  === ALL flows that never got a reply (out>0, in==0) ===")
    for k, f in rows:
        if f["i"] == 0 and f["o"] >= 3 and k[0] != 17:
            print(f"    {k[0]} {k[1]}:{k[2]} {nm(k[1])} out={f['o']} "
                  f"life {wall(f['a'])}..{wall(f['b'])} flags=" +
                  ",".join(sorted({p["flags"] for p in f["pkts"] if p["flags"]})))


def main():
    for w in (sys.argv[1:] or ["z1-tiamant-client", "z2-elijah-hotspot-owner"]):
        analyse(w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
