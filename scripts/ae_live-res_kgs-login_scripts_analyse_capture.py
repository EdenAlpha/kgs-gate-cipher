#!/usr/bin/env python3
"""Turn a capture directory into the answer: the command `path` values.

Consumes whatever the ARM64 runner published and pulls the route table out of
it in one pass:

  * `kgs/frame_*.bin`  -- plaintext HTTP/2 frames from the Frida send/write
    hook, with the channel forced to PACK_MODE-insecure. These are the frames
    that carry `CommandRequest`, so the `path` field is directly readable.
  * `capture/game.pcap.gz` -- the game's real TLS session, for the ClientHello
    and the connection pattern, decoded with the same h2/HPACK code.

For every DATA frame it decodes the gRPC envelope, then the
`CommandRequest{id=1, packMode=2, req=3, path=4}`, and prints the `path`, the
`packMode` and the payload. Any path that is not `/` is a real command route,
and the payload beside it is what that command takes -- which is the second
half of what is needed to actually call it.
"""
from __future__ import annotations

import glob
import gzip
import io
import json
import os
import re
import shutil
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from decode_capture import TYPES, FLAGS, hpack_decode, fl  # noqa: E402

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


# ------------------------------------------------------------------ protobuf
def varint(b, i):
    v, shift = 0, 0
    while i < len(b):
        x = b[i]
        v |= (x & 0x7F) << shift
        i += 1
        if not (x & 0x80):
            break
        shift += 7
    return v, i


def pb_fields(b):
    """Yield (field_number, wire_type, value) from a protobuf message."""
    i = 0
    while i < len(b):
        key, i = varint(b, i)
        fn, wt = key >> 3, key & 7
        if fn == 0:
            return
        if wt == 0:
            v, i = varint(b, i)
        elif wt == 1:
            v = struct.unpack_from("<Q", b, i)[0]
            i += 8
        elif wt == 2:
            ln, i = varint(b, i)
            v = b[i:i + ln]
            i += ln
        elif wt == 5:
            v = struct.unpack_from("<I", b, i)[0]
            i += 4
        else:
            return
        yield fn, wt, v


def decode_command_request(b):
    """CommandRequest{id=1, packMode=2, req=3, path=4}."""
    out = {"id": None, "packMode": None, "req": None, "path": None}
    for fn, wt, v in pb_fields(b):
        if fn == 1 and wt == 2:
            out["id"] = v.decode("utf-8", "replace")
        elif fn == 2 and wt == 0:
            out["packMode"] = v
        elif fn == 3 and wt == 2:
            out["req"] = v.decode("utf-8", "replace")
        elif fn == 4 and wt == 2:
            out["path"] = v.decode("utf-8", "replace")
    return out


def maybe_unpack(path):
    """The msgpack flag can be 0/1, or the msb set for a length prefix."""
    if path and len(path) > 1 and (ord(path[0]) & 0x80):
        n = ord(path[0]) & 0x7F
        if n == len(path) - 1:
            return path[1:].decode("latin1", "replace")
    return path


# ------------------------------------------------------------------ h2 walk
def walk_h2(blob, label):
    i = len(PREFACE) if blob.startswith(PREFACE) else 0
    table = []
    n_frames = 0
    requests = []
    while i + 9 <= len(blob):
        ln = int.from_bytes(blob[i:i + 3], "big")
        if i + 9 + ln > len(blob):
            break
        typ, flags = blob[i + 3], blob[i + 4]
        body = blob[i + 9:i + 9 + ln]
        i += 9 + ln
        n_frames += 1
        if typ == 1:
            j, pad = 0, 0
            if flags & 0x8:
                pad, j = body[0], 1
            try:
                for name, val in hpack_decode(body[j:len(body) - pad], table):
                    n = name[0] if isinstance(name, tuple) else name
                    v = name[1] if isinstance(name, tuple) else val
                    if n == ":path":
                        print("  %s: :path %s" % (label, v))
            except SystemExit as e:
                print("  (hpack: %s)" % e)
        elif typ == 0 and body:
            # gRPC envelope: 1 byte compressed flag, 4 byte length
            if len(body) < 5:
                continue
            mlen = int.from_bytes(body[1:5], "big")
            msg = body[5:5 + mlen]
            if not msg:
                continue
            cr = decode_command_request(msg)
            if cr["path"] is not None or cr["id"] is not None:
                requests.append(cr)
                print("  %s: CommandRequest  path=%r  packMode=%s  id=%r"
                      % (label, cr["path"], cr["packMode"], cr["id"]))
                req = cr["req"]
                if req:
                    shown = req if len(req) <= 400 else req[:400] + "..."
                    print("        req (%d) %s" % (len(req), shown))
    return n_frames, requests


def load_frames(d):
    files = sorted(glob.glob(os.path.join(d, "frame_*.bin")),
                   key=lambda p: int(p.rsplit("_", 1)[1].split(".")[0]))
    if not files:
        return None, []
    return b"".join(open(f, "rb").read() for f in files), files


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    print("=" * 74)
    print("CAPTURE ANALYSIS  (%s)" % root)
    print("=" * 74)

    all_requests = []

    # 1. plaintext frames from the Frida hook
    for cand in (os.path.join(root, "kgs"),
                 os.path.join(root, "capture", "kgs"),
                 root):
        blob, files = load_frames(cand)
        if blob is None:
            continue
        print("\n--- plaintext frames in %s ---" % cand)
        print("  %d files, %d bytes" % (len(files), len(blob)))
        print("  starts with h2 preface: %s" % blob.startswith(PREFACE))
        n, reqs = walk_h2(blob, cand)
        print("  %d frames, %d CommandRequests" % (n, len(reqs)))
        all_requests += reqs
        break

    # 2. the TLS session, if published
    for gz in glob.glob(os.path.join(root, "**", "game.pcap.gz"), recursive=True):
        print("\n--- TLS capture %s ---" % gz)
        tmp = tempfile.mkdtemp()
        pcap = os.path.join(tmp, "game.pcap")
        with gzip.open(gz, "rb") as fi, open(pcap, "wb") as fo:
            shutil.copyfileobj(fi, fo)
        r = os.system('python "%s" "%s" 2>&1'
                      % (os.path.join(HERE, "summarise_pcap.py"), pcap))
        del r

    # 3. summary
    print("\n" + "=" * 74)
    print("COMMAND ROUTES FOUND")
    print("=" * 74)
    paths = []
    for cr in all_requests:
        p = cr["path"]
        if p and p not in paths:
            paths.append(p)
    if not paths:
        print("  none - no CommandRequest carried a path")
    for p in paths:
        cr = next(c for c in all_requests if c["path"] == p)
        print("  %-44s packMode=%s" % (p, cr["packMode"]))
        if cr["req"]:
            print("      req: %s" % (cr["req"][:300]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
