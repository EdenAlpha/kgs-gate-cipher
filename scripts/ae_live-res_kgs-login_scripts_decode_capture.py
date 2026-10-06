#!/usr/bin/env python3
"""Decode what the game's own gRPC stack sent us.

Reads the frame_*.bin files produced by capture_insecure.js (libc send/write
hook while the channel was forced plaintext), reassembles them into an HTTP/2
byte stream, and prints:

    * the connection preface and SETTINGS
    * every HEADERS frame, fully HPACK-decoded (static table + Huffman)
    * the gRPC length-prefixed envelope for each DATA frame
    * a recursive protobuf field dump of the payload

The point is to see the request the game ACTUALLY builds, rather than a
reconstruction of it. Nothing here guesses: every value is decoded from the
captured bytes.
"""
from __future__ import annotations

import base64
import glob
import os
import re
import struct
import sys

# ---------------------------------------------------------------- HPACK table
# RFC 7541 Appendix A, verbatim. The intermediate :status entries (204, 206,
# 304, 400, 404, 500) matter: an earlier version of this list collapsed them,
# which shifted every later index and made the decoder emit plausible-looking
# garbage names ("vary: awel") for real headers.
STATIC = [
    None,                             # 0 unused
    ":authority",                     # 1
    ":method", "GET",                 # 2  (name, value)
    ":method", "POST",                # 3
    ":path", "/",                     # 4
    ":path", "/index.html",           # 5
    ":scheme", "http",                # 6
    ":scheme", "https",               # 7
    ":status", "200",                 # 8
    ":status", "204",                 # 9
    ":status", "206",                 # 10
    ":status", "304",                 # 11
    ":status", "400",                 # 12
    ":status", "404",                 # 13
    ":status", "500",                 # 14
    "accept-charset",                 # 15
    "accept-encoding",                # 16
    "accept-language",                # 17
    "accept-ranges",                  # 18
    "accept",                         # 19
    "access-control-allow-origin",    # 20
    "age",                            # 21
    "allow",                          # 22
    "authorization",                  # 23
    "cache-control",                  # 24
    "content-disposition",            # 25
    "content-encoding",               # 26
    "content-language",               # 27
    "content-length",                 # 28
    "content-location",               # 29
    "content-range",                  # 30
    "content-type",                   # 31
    "cookie",                         # 32
    "date",                           # 33
    "etag",                           # 34
    "expect",                         # 35
    "expires",                        # 36
    "from",                           # 37
    "host",                           # 38
    "if-match",                       # 39
    "if-modified-since",              # 40
    "if-none-match",                  # 41
    "if-range",                       # 42
    "if-unmodified-since",            # 43
    "last-modified",                  # 44
    "link",                           # 45
    "location",                       # 46
    "max-forwards",                   # 47
    "proxy-authenticate",             # 48
    "proxy-authorization",            # 49
    "range",                          # 50
    "referer",                        # 51
    "refresh",                        # 52
    "retry-after",                    # 53
    "server",                         # 54
    "set-cookie",                     # 55
    "strict-transport-security",      # 56
    "transfer-encoding",              # 57
    "user-agent",                     # 58
    "vary",                           # 59
    "via",                            # 60
    "www-authenticate",               # 61
]

# RFC 7541 Appendix B
HUFF = [
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6,
    0xfffffe7, 0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea,
    0x3ffffffd, 0xfffffeb, 0xfffffec, 0xfffffed, 0xfffffee, 0xfffffef,
    0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4,
    0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa,
    0xffffffb, 0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
    0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18, 0x0, 0x1, 0x2,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc,
    0x20, 0xffb, 0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61,
    0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
    0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb,
    0x7fff0, 0x1ffc, 0x3ffc, 0x22, 0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5,
    0x25, 0x26, 0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7, 0x2b,
    0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe,
    0x7fc, 0x3ffd, 0x1ffd, 0xffffffc, 0xfffe6, 0x3fffd2, 0xfffe7,
    0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda,
    0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf, 0xffffec,
    0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7,
    0xffffef, 0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8,
    0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf,
    0x3fffdf, 0x7fffeb, 0x7fffec, 0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2,
    0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3,
    0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, 0x3ffffe0, 0x3ffffe1,
    0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2,
    0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1,
    0x1ffffed, 0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1,
    0x3ffffe7, 0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8,
    0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5, 0xfffec,
    0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea,
    0x7ffff4, 0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7,
    0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb, 0xffffffe, 0x7ffffec,
    0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee, 0x3fffffff,
]
CLEN = [
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 6, 5, 5, 5, 5, 6,
    6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 8, 9, 10, 11, 12, 13,
    14, 15, 6, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13,
    6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 8, 8, 15, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
]


def _huff_table():
    """(code, bit-length) -> symbol, built once."""
    t = {}
    for sym, (code, ln) in enumerate(zip(HUFF, CLEN)):
        t[(code, ln)] = sym
    return t


_HUFF = _huff_table()
_BY_LEN = {}
for (code, ln), sym in _HUFF.items():
    _BY_LEN.setdefault(ln, {})[code] = sym


def huff_decode(data: bytes) -> str:
    """Canonical HPACK Huffman decode (RFC 7541 Appendix B).

    The previous version special-cased a 5-bit prefix, which does not exist in
    the code, and scanned all 257 symbols per bit -- it produced wrong strings
    for anything the server Huffman-encoded.
    """
    out = []
    acc = 0
    nbits = 0
    maxlen = max(CLEN)
    for byte in data:
        acc = (acc << 8) | byte
        nbits += 8
        while nbits >= 5:
            for ln in range(5, min(nbits, maxlen) + 1):
                code = (acc >> (nbits - ln)) & ((1 << ln) - 1)
                sym = _BY_LEN.get(ln, {}).get(code)
                if sym is not None:
                    out.append(chr(sym) if 0x20 <= sym < 0x7F else
                               ("<%d>" % sym))
                    nbits -= ln
                    acc &= (1 << nbits) - 1
                    break
            else:
                # no symbol fits: consume one bit and resync
                nbits -= 5
                acc &= (1 << nbits) - 1
    return "".join(out)


def read_int(b, i, prefix_bits):
    mask = (1 << prefix_bits) - 1
    v = b[i] & mask
    i += 1
    if v < mask:
        return v, i
    shift = 0
    while i < len(b):
        add = b[i] & 0x7F
        v += add << shift
        shift += 7
        i += 1
        if not (b[i - 1] & 0x80):
            break
    return v, i


def read_str(b, i):
    huff = bool(b[i] & 0x80)
    ln, i = read_int(b, i, 7)
    raw = b[i:i + ln]
    i += ln
    return (huff_decode(raw) if huff else raw.decode("latin1")), i


def hpack_decode(block: bytes, table: list):
    """Decode an HPACK header block.

    Uses the `hpack` library (RFC 7541 Appendix B) when available. The
    hand-rolled Huffman table that used to live here had a wrong CLEN array,
    which silently produced plausible-looking garbage for every header the
    server encoded ("vary" decoded as "awel"). A wrong decoder is worse than
    none when you are hunting for a header the game sends, so the library is
    the default and the fallback is only used if it is missing.
    """
    try:
        from hpack import Decoder
        if not hasattr(hpack_decode, "_dec"):
            hpack_decode._dec = Decoder()
        out = hpack_decode._dec.decode(block, raw=True)
        res = []
        for name, value in out:
            if isinstance(name, (bytes, bytearray)):
                name = name.decode("latin1")
            if isinstance(value, (bytes, bytearray)):
                value = value.decode("latin1")
            res.append((name, value))
        return res
    except Exception as e:
        raise SystemExit(
            "the `hpack` library is required for correct HPACK/Huffman decoding"
            " (pip install hpack).\nRefusing to fall back: the hand-rolled table"
            " in this file was wrong and produced plausible-looking garbage"
            " headers, which is worse than no output when hunting for a header"
            " the game actually sends.\nunderlying error: %r" % (e,))


# ---------------------------------------------------------------- protobuf
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


def pb_dump(b, indent=2, path="", depth=0):
    i = 0
    while i < len(b):
        try:
            key, i = varint(b, i)
        except Exception:
            return
        fld, wt = key >> 3, key & 7
        pre = " " * indent * depth
        if wt == 0:
            v, i = varint(b, i)
            print("%s%d: varint %d" % (pre, fld, v))
        elif wt == 1:
            v = struct.unpack_from("<Q", b, i)[0]
            i += 8
            print("%s%d: fixed64 %d" % (pre, fld, v))
        elif wt == 2:
            ln, i = varint(b, i)
            v = b[i:i + ln]
            i += ln
            try:
                s = v.decode("utf-8")
                printable = all(c == "\n" or c == "\t" or 32 <= ord(c) < 127
                                for c in s)
            except Exception:
                printable = False
            if printable and ln:
                print("%s%d: str(%d) %r" % (pre, fld, ln, s))
            else:
                print("%s%d: bytes(%d) %s" % (pre, fld, ln, v.hex()))
                if ln and depth < 4 and v and v[0] != 0:
                    print("%s  {" % pre)
                    pb_dump(v, indent, path, depth + 1)
                    print("%s  }" % pre)
        elif wt == 5:
            v = struct.unpack_from("<I", b, i)[0]
            i += 4
            print("%s%d: fixed32 %d" % (pre, fld, v))
        else:
            print("%s<wire type %d unknown, stopping>" % (pre, wt))
            return


# ---------------------------------------------------------------- h2 frames
TYPES = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS",
         5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE",
         9: "CONTINUATION"}
FLAGS = {0x1: "END_STREAM", 0x4: "END_HEADERS", 0x8: "PADDED",
         0x20: "PRIORITY", 0x100: "ACK"}

# A plain gRPC request carries only pseudo-headers plus a small standard set.
# Anything else is the interesting part -- that is the whole reason we are
# decoding the game's own bytes rather than guessing at them.
STANDARD = {
    ":method", ":scheme", ":path", ":authority",
    "content-type", "user-agent", "te", "grpc-encoding", "grpc-accept-encoding",
    "grpc-timeout", "grpc-status", "grpc-message", "grpc-status-details-bin",
    "accept-encoding", "content-encoding", "cache-control", "date",
    "x-forwarded-for", "x-forwarded-proto", "x-envoy-upstream-service-time",
    "server", "via", "alt-svc",
}

notable = []


def flag_header(name, value):
    low = name.lower()
    if low.startswith(":") or low in STANDARD:
        return
    notable.append(("non-standard header", name, value))
    if low.startswith("x-") or low.startswith("grpc-"):
        notable.append(("custom metadata", name, value))
    # base64-looking values are the classic "sealed identity" carrier
    compact = value.strip()
    if len(compact) >= 24 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        try:
            raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
            if len(raw) >= 16:
                notable.append(("base64 value, %d B decoded" % len(raw),
                                name, value[:72] + "..."))
        except Exception:
            pass


def fl(flags):
    return ",".join(n for b, n in sorted(FLAGS.items()) if flags & b) or "-"


def main() -> int:
    d = sys.argv[1] if len(sys.argv) > 1 else "kgs"
    files = sorted(glob.glob(os.path.join(d, "frame_*.bin")),
                   key=lambda p: int(p.rsplit("_", 1)[1].split(".")[0]))
    if not files:
        print("no frames in %s" % d)
        return 1
    stream = b"".join(open(f, "rb").read() for f in files)
    print("reassembled %d bytes from %d captured send() calls\n"
          % (len(stream), len(files)))

    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    if stream.startswith(preface):
        print("connection preface: OK (%d bytes)" % len(preface))
        i = len(preface)
    else:
        print("NOTE: stream does not start with the h2 preface")
        i = 0

    table = []
    while i + 9 <= len(stream):
        ln = int.from_bytes(stream[i:i + 3], "big")
        typ = stream[i + 3]
        flags = stream[i + 4]
        sid = int.from_bytes(stream[i + 5:i + 9], "big") & 0x7FFFFFFF
        body = stream[i + 9:i + 9 + ln]
        if i + 9 + ln > len(stream):
            print("truncated frame: want %d body bytes, have %d"
                  % (ln, len(stream) - i - 9))
            break
        i += 9 + ln
        print("\n--- %s len=%d stream=%d flags=%s ---"
              % (TYPES.get(typ, "TYPE%d" % typ), ln, sid, fl(flags)))
        if typ == 4:                                   # SETTINGS
            if flags & 0x100:
                print("  ACK")
            else:
                for k in range(0, len(body) - 5, 6):
                    sid_ = struct.unpack_from(">H", body, k)[0]
                    val = struct.unpack_from(">I", body, k + 2)[0]
                    print("  setting 0x%04x = %d" % (sid_, val))
        elif typ == 1:                                 # HEADERS
            j = 0
            pad = 0
            if flags & 0x8:
                pad = body[0]
                j = 1
            if flags & 0x20:
                j += 5
            blk = body[j:len(body) - pad]
            for name, val in hpack_decode(blk, table):
                if isinstance(name, tuple):
                    print("  %s: %s" % (name[0], name[1]))
                    flag_header(name[0], name[1])
                else:
                    print("  %s: %s" % (name, val))
                    flag_header(name, val)
        elif typ == 0:                                 # DATA
            j = 0
            pad = 0
            if flags & 0x8:
                pad = body[0]
                j = 1
            payload = body[j:len(body) - pad]
            print("  %d bytes" % len(payload))
            if len(payload) >= 5:
                comp = payload[0]
                mlen = int.from_bytes(payload[1:5], "big")
                msg = payload[5:5 + mlen]
                print("  gRPC: compressed=%d message_len=%d" % (comp, mlen))
                if msg:
                    print("  protobuf:")
                    pb_dump(msg, depth=1)
            else:
                print("  raw: %s" % payload.hex())
        elif typ == 6:
            print("  opaque: %s" % body.hex())
        elif typ == 7:
            last = int.from_bytes(body[0:4], "big")
            print("  last_stream=%d code=%d debug=%r"
                  % (last, int.from_bytes(body[4:8], "big"),
                     body[8:].decode("latin1", "replace")))
        else:
            if body:
                print("  %s" % body.hex())
    if notable:
        print("\n" + "=" * 70)
        print("NOTABLE -- anything outside a plain gRPC request")
        print("=" * 70)
        for kind, name, val in notable:
            print("  [%s] %s: %s" % (kind, name, val))
    else:
        print("\nNOTABLE: nothing. Every header is standard gRPC.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
