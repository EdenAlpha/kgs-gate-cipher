#!/usr/bin/env python3
"""Parse the DTLS record stream to turn.konami.com and hunt for alerts /
sequence anomalies right before each stall."""
from __future__ import annotations

import sys
from collections import defaultdict

from stall_focus import load, ROOT, STALLS, T0, wall  # type: ignore

RT = {20: "CCS", 21: "ALERT", 22: "HS", 23: "APP"}
ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    21: "decryption_failed", 22: "record_overflow", 30: "decompression_failure",
    40: "handshake_failure", 42: "bad_certificate", 46: "certificate_unknown",
    47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied",
    50: "decode_error", 51: "decrypt_error", 60: "export_restriction",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    90: "user_canceled", 100: "no_renegotiation", 110: "unrecognized_name",
    112: "inappropriate_fallback", 120: "no_application_protocol",
}
HS = {0: "hello_request", 1: "client_hello", 2: "server_hello",
      3: "hello_verify_request", 11: "certificate", 12: "server_key_exchange",
      13: "certificate_request", 14: "server_hello_done",
      15: "certificate_verify", 16: "client_key_exchange",
      20: "finished", 4: "new_session_ticket"}


def records(buf: bytes):
    off = 0
    out = []
    while off + 13 <= len(buf):
        typ = buf[off]
        ver = buf[off + 1:off + 3].hex()
        epoch = int.from_bytes(buf[off + 3:off + 5], "big")
        seq = int.from_bytes(buf[off + 5:off + 11], "big")
        ln = int.from_bytes(buf[off + 11:off + 13], "big")
        if ln > 1 << 14 + 200 or off + 13 + ln > len(buf):
            out.append(("BAD", typ, epoch, seq, ln, b""))
            break
        pl = buf[off + 13:off + 13 + ln]
        out.append((RT.get(typ, f"?{typ}"), typ, epoch, seq, ln, pl))
        off += 13 + ln
    if off < len(buf) and not out:
        out.append(("PARTIAL", 0, 0, 0, len(buf), buf))
    return out, off, len(buf)


def describe(recs):
    parts = []
    for name, typ, epoch, seq, ln, pl in recs:
        s = f"{name}(ep{epoch} seq{seq} len{ln})"
        if typ == 21 and len(pl) >= 2:
            lvl = "fatal" if pl[0] == 2 else "warning"
            s += f" <!! {ALERTS.get(pl[1], pl[1])} {lvl}!!>"
        elif typ == 22 and len(pl) >= 4:
            s += f" [{HS.get(pl[0], pl[0])}]"
        parts.append(s)
    return "  ".join(parts)


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "z1-tiamant-client"
    recs = load(f"{ROOT}\\{which}\\passthrough_capture.csv")
    print(f"=== {which} ===")

    # UDP flows that look like DTLS (first byte 0x14..0x19)
    flows = defaultdict(list)
    for r in recs:
        if r["proto"] != 17 or not r["_payload"]:
            continue
        if r["_payload"][0] not in (0x14, 0x15, 0x16, 0x17, 0x18):
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

    print("\n  DTLS-looking UDP flows:")
    for k, v in sorted(flows.items(), key=lambda kv: -len(kv[1])):
        print(f"    {k[0]:<18}:{k[1]:<6} n={len(v):<5} "
              f"{wall(v[0]['ts'])}..{wall(v[-1]['ts'])}")

    alerts = 0
    for s, e, tag in STALLS:
        print(f"\n############ {tag}  stall {wall(s)}..{wall(e)} ############")
        for k, v in sorted(flows.items()):
            if not (s - 60000 <= v[-1]["ts"] <= s + 3000):
                continue
            print(f"\n  --- flow {k[0]}:{k[1]}  n={len(v)} ---")
            # walk the whole stream tracking epoch/seq
            last = None
            for r in v:
                body = r["_payload"]
                recs2, consumed, total = records(body)
                line = describe(recs2)
                if "ALERT" in line:
                    alerts += 1
                    print(f"    {wall(r['ts'])} {r['dir']} *** {line}")
                if consumed != total:
                    print(f"    {wall(r['ts'])} {r['dir']} !! unparsed "
                          f"{consumed}/{total}: {body[:24].hex()}")
                last = (r, line)
            # print last 14 records in detail
            print("  LAST 16 packets:")
            for r in v[-16:]:
                body = r["_payload"]
                recs2, consumed, total = records(body)
                mark = ""
                if r["ts"] >= s:
                    mark = "  <<<STALL>>>"
                elif s - r["ts"] <= 5000:
                    mark = "  <<PRE>>"
                print(f"    {wall(r['ts'])} {r['dir']} n={len(body):<4} "
                      f"{describe(recs2)}{mark}")
            # seq monotonicity per direction
            print("  sequence summary per direction:")
            for d in ("t", "r"):
                seqs = []
                for r in v:
                    if r["dir"] != d:
                        continue
                    for name, typ, epoch, seq, ln, pl in records(r["_payload"])[0]:
                        if typ in (17, 23, 0x17):
                            seqs.append((epoch, seq))
                if seqs:
                    gaps = sum(1 for i in range(1, len(seqs))
                               if seqs[i][1] != seqs[i - 1][1] + 1)
                    print(f"    {d}: n={len(seqs)} first={seqs[0]} "
                          f"last={seqs[-1]} non_consecutive={gaps}")
    print(f"\n  TOTAL ALERT records seen: {alerts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
