#!/usr/bin/env python3
"""Reassemble the plain-HTTP requests to ntl.service.konami.net and decode the
hex-encoded `dat=` diagnostic log the game posts to Konami."""
from __future__ import annotations

import sys
from collections import defaultdict
from urllib.parse import parse_qs, unquote

from stall_focus import load, ROOT, STALLS, T0, wall  # type: ignore

HDR = b"\r\n\r\n"


def split_requests(stream: bytes, ts0: int):
    """Yield (ts_marker, method_path, headers, body)."""
    out = []
    i = 0
    while True:
        j = stream.find(b"POST ", i)
        if j < 0:
            break
        k = stream.find(HDR, j)
        if k < 0:
            break
        head = stream[j:k]
        first = head.split(b"\r\n")[0].decode("latin1", "replace")
        clen = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                clen = int(line.split(b":", 1)[1].strip() or 0)
        body = stream[k + 4:k + 4 + clen]
        out.append((ts0, first, body))
        i = k + 4 + clen
    return out


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "z1-tiamant-client"
    recs = load(f"{ROOT}\\{which}\\passthrough_capture.csv")
    print(f"=== {which} ===")

    # --- group by (remote, local port) and concat payloads ---------
    streams = defaultdict(list)
    for r in recs:
        if r["proto"] == 6 and r["dir"] == "t" and r["_payload"]:
            if r["dport"] == 80:
                streams[r["sport"]].append(r)

    allreq = []
    for port, segs in streams.items():
        segs.sort(key=lambda x: x["ts"])
        blob = b"".join(s["_payload"] for s in segs)
        for ts, first, body in split_requests(blob, segs[0]["ts"]):
            allreq.append((ts, port, first, body))
    allreq.sort()
    print(f"  reassembled {len(allreq)} HTTP requests")

    # --- summary of endpoints hit ---------------------------------
    hits = defaultdict(int)
    for _ts, _p, first, _b in allreq:
        hits[first.split(" ")[1] if " " in first else first] += 1
    print("\n  endpoints:")
    for k, v in sorted(hits.items(), key=lambda x: -x[1]):
        print(f"    {v:<4} {k}")

    # --- decode each ------------------------------------------------
    print("\n  === decoded requests ===")
    for ts, port, first, body in allreq:
        url = first.split(" ")[1] if " " in first else "?"
        try:
            form = parse_qs(body.decode("latin1", "replace"),
                            keep_blank_values=True)
        except Exception:
            form = {}
        dat = form.get("dat", [""])[0]
        prefix = form.get("prefix", [""])[0]
        typ = form.get("type", [""])[0]
        reqh = form.get("req", [""])[0]

        print(f"\n########## {wall(ts)}  {url}  (sport={port}) ##########")
        if reqh:
            try:
                print("  req= " + bytes.fromhex(reqh).decode("utf-8", "replace"))
            except Exception:
                print("  req= " + reqh)
        if dat:
            try:
                txt = bytes.fromhex(dat).decode("utf-8", "replace")
            except Exception:
                txt = dat
            print(f"  type={typ} prefix={prefix} decoded_len={len(txt)}")
            print("  ---- begin dat ----")
            print(txt)
            print("  ---- end dat ----")
        else:
            for k, v in form.items():
                if k != "dat":
                    print(f"  {k} = {v[0][:300]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
