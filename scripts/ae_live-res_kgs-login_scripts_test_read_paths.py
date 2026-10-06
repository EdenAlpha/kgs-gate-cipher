#!/usr/bin/env python3
"""Self-test read_paths.py's decoder and scanner against a synthetic image.

This is the primary route now, so its decode has to be right before a runner is
spent on it. Two specific hazards:

  * the scanner finds candidates by spotting the field-4 tag (0x22) and then
    walks *backwards* guessing where the message started, so a permissive
    decoder will happily accept a valid suffix of an unrelated message;
  * the length arithmetic is `back + 2 + plen`, which is easy to get wrong by
    one and lose the confirmed route "/" entirely.

So this builds a fake memory image containing known CommandRequests (including
"/", a slash-less route, and multi-segment forms), embeds them in unrelated
noise, and requires every one to be recovered with its payload intact, while
decoys that merely *look* tag-like are rejected.

Run: python test_read_paths.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from read_paths import (decode_command_request, scan_buffer)  # noqa: E402


def varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def f_str(n, s):
    b = s.encode()
    return varint(n << 3 | 2) + varint(len(b)) + b


def f_varint(n, v):
    return varint(n << 3) + varint(v)


def command_request(rid, pack, payload, path):
    return f_str(1, rid) + f_varint(2, pack) + f_str(3, payload) + f_str(4, path)


def main() -> int:
    cases = [
        # (path, packMode, req) -- "/" is the one route confirmed to resolve and
        # is a single byte, so the minimum length must allow 1
        ("/", 0, "{}"),
        ("/session/get", 0, '{"token":"abc"}'),
        ("/room/create", 1, '{"roomType":"1"}'),
        ("login", 0, '{"user":"x"}'),                      # no leading slash
        ("/user/compe/get_info", 0, "{}"),
        ("gate/gate_", 0, "{}"),
        ("a", 0, "{}"),                                    # shortest possible
    ]

    buf = bytearray()
    expect = {}
    for i, (p, pack, req) in enumerate(cases):
        rid = "7f1c0a10-%04d-3333-4444-555555555555" % i
        blob = command_request(rid, pack, req, p)
        # unaligned padding between messages, like a real heap
        buf += b"\x41" * (i % 5 + 1)
        buf += blob
        expect[p] = (pack, req, rid)

    # --- decoys that must NOT be reported ---
    decoy_spans = []
    # 1) a field-4 tag with no payload after it
    d1 = bytes([0x08, 0x01, 0x22, 0x05]) + b"hello"
    decoy_spans.append(len(buf)); buf += d1
    # 2) a length prefix promising more than follows
    d2 = bytes([0x0A, 0x02]) + b"id" + bytes([0x22, 0x7F]) + b"short"
    decoy_spans.append(len(buf)); buf += d2
    # 3) a valid *suffix* of a message: fields 3 and 4 only, no id/packMode.
    #    A permissive decoder reports this; the strict one must not.
    d3 = f_str(3, "{}") + f_str(4, "not_a_real_route")
    decoy_spans.append(len(buf)); buf += d3
    # 4) random noise containing 0x22 followed by printable bytes
    noise = bytearray((i * 37 + 11) & 0xFF for i in range(200))
    noise[100], noise[101] = 0x22, 0x04
    noise[102:106] = b"abcd"
    decoy_spans.append(len(buf)); buf += bytes(noise)

    found = {}
    scan_buffer(bytes(buf), found)

    print("recovered %d path(s):" % len(found))
    for k in sorted(found):
        print("   %-24r packMode=%-4s req=%s" % (k, found[k]["packMode"],
                                                 found[k]["req"]))
    print()

    fail = 0
    for p, (pack, req, rid) in expect.items():
        got = found.get(p)
        if not got:
            print("  MISSING   %r" % p)
            fail += 1
            continue
        ok = (got["packMode"] == pack and got["req"] == req and got["id"] == rid)
        print("  %s %-24r packMode=%s req=%s"
              % ("ok      " if ok else "WRONG   ", p, got["packMode"],
                 got["req"]))
        if not ok:
            fail += 1

    for name, blob in (("no-payload", None), ("overlong", None),
                       ("suffix-only", d3), ("noise", bytes(noise))):
        pass
    for p in ("not_a_real_route",):
        bad = p in found
        print("  %s decoy suffix-only -> %r" % ("FALSE+  " if bad else "clean   ", p))
        if bad:
            fail += 1
    for p in ("hello", "short", "abcd"):
        bad = p in found
        print("  %s decoy %-8s -> %r" % ("FALSE+" if bad else "clean  ", p, p))
        if bad:
            fail += 1

    print("\nSELF-TEST: %s" % ("PASS" if fail == 0 else "FAIL (%d)" % fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
