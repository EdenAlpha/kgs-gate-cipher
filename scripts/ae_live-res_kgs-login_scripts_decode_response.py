#!/usr/bin/env python3
"""Decode an HTTP/2 server response byte stream (the replayer saves one)."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decode_capture import TYPES, FLAGS, hpack_decode, fl  # noqa: E402

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def main() -> int:
    path = sys.argv[1]
    raw = open(path, "rb").read()
    print("%s: %d bytes" % (path, len(raw)))
    i = len(PREFACE) if raw.startswith(PREFACE) else 0
    table = []
    while i + 9 <= len(raw):
        ln = int.from_bytes(raw[i:i + 3], "big")
        typ, flags = raw[i + 3], raw[i + 4]
        sid = int.from_bytes(raw[i + 5:i + 9], "big") & 0x7FFFFFFF
        body = raw[i + 9:i + 9 + ln]
        if i + 9 + ln > len(raw):
            print("  truncated frame at %d (want %d, have %d)"
                  % (i, ln, len(raw) - i - 9))
            break
        i += 9 + ln
        print("\n--- %s len=%d stream=%d flags=%s ---"
              % (TYPES.get(typ, "TYPE%d" % typ), ln, sid, fl(flags)))
        if typ == 4 and not (flags & 0x100):
            for k in range(0, len(body) - 5, 6):
                sid_ = int.from_bytes(body[k:k + 2], "big")
                val = int.from_bytes(body[k + 2:k + 6], "big")
                print("  setting 0x%04x = %d" % (sid_, val))
        elif typ == 1:
            j = 0
            pad = 0
            if flags & 0x8:
                pad = body[0]
                j = 1
            if flags & 0x20:
                j += 5
            blk = body[j:len(body) - pad]
            try:
                for name, val in hpack_decode(blk, table):
                    if isinstance(name, tuple):
                        print("  %s: %s" % (name[0], name[1]))
                    else:
                        print("  %s: %s" % (name, val))
            except Exception as e:
                print("  hpack decode failed: %s" % e)
                print("  block hex: %s" % blk.hex())
        elif typ == 0:
            print("  %d data bytes: %s" % (len(body), body[:64].hex()))
        else:
            if body:
                print("  %s" % body.hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
