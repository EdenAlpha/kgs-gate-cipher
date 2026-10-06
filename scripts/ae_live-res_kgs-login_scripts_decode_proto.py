#!/usr/bin/env python3
"""Decode the embedded FileDescriptorProto for command_service.proto.

protobuf libraries serialize their own schema into the binary (the
FileDescriptorProto blob).  The game carries command_service.proto's
descriptor, which gives the exact CommandRequest / CommandResponse /
CommandStream definitions.

Layout clues found in the strings:
    command_service.CommandRequest.id
    command_service.CommandRequest.req
    command_service.CommandRequest.path
    command_service.CommandResponse.id
    command_service.CommandResponse.res
    .command_service.PackMode
    /command_service.CommandService/CommandStream   (bidi stream RPC)
"""
from __future__ import annotations

import re
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")

data = open(SO, "rb").read()


# --- minimal protobuf wire decoder -------------------------------------
def read_varint(b, i):
    v = 0
    sh = 0
    while i < len(b):
        c = b[i]
        i += 1
        v |= (c & 0x7F) << sh
        if not (c & 0x80):
            return v, i
        sh += 7
    return v, i


def fields(b):
    """yield (field_no, wire_type, value_bytes_or_int)"""
    i = 0
    out = []
    while i < len(b):
        try:
            key, i = read_varint(b, i)
        except Exception:
            break
        fno, wt = key >> 3, key & 7
        if wt == 0:
            v, i = read_varint(b, i)
            out.append((fno, wt, v))
        elif wt == 1:
            v = b[i:i + 8]
            i += 8
            out.append((fno, wt, v))
        elif wt == 2:
            n, i = read_varint(b, i)
            v = b[i:i + n]
            i += n
            out.append((fno, wt, v))
        elif wt == 5:
            v = b[i:i + 4]
            i += 4
            out.append((fno, wt, v))
        else:
            break
    return out


def walk(b, depth=0, label=""):
    pad = "  " * depth
    for fno, wt, v in fields(b):
        if wt == 2 and isinstance(v, (bytes, bytearray)):
            # try nested message, else show string
            isstr = all(32 <= c < 127 or c in (9, 10, 13) for c in v) and len(v) > 0
            if isstr and len(v) > 2:
                print(f"{pad}f{fno} str = {v[:120]!r}")
            else:
                print(f"{pad}f{fno} bytes[{len(v)}] (nested)")
                if depth < 4 and len(v) < 4000:
                    walk(v, depth + 1)
        else:
            print(f"{pad}f{fno} wt={wt} = {v if isinstance(v, int) else v.hex()}")


def main() -> int:
    # protobuf FileDescriptorProto always starts with field 1 (name) as a
    # length-delimited "command_service.proto".  Find that and walk the blob.
    anchors = [m.start() for m in re.finditer(rb"command_service\.proto", data)]
    print("anchors:", [hex(a) for a in anchors], flush=True)

    for a in anchors:
        # the descriptor blob starts a few bytes before the name string
        for start in range(max(0, a - 8), a):
            blob = data[start:start + 4000]
            fs = fields(blob[:2000])
            names = [v for f, w, v in fs if w == 2 and isinstance(v, bytes)
                     and v.startswith(b"command_service")]
            if names:
                print(f"\n\n########## descriptor candidate @ {start:#x} ##########",
                      flush=True)
                walk(blob, 0)
                break

    # also show the proto source-ish region (the .proto may be embedded)
    print("\n\n########## raw region around 0xc95b02 ##########", flush=True)
    i = 0xC95B02
    st = i
    while st > 0 and (32 <= data[st - 1] < 127 or data[st - 1] == 0):
        st -= 1
    for p in [x for x in data[st - 300:i + 400].split(b"\x00") if len(x) > 1]:
        print("   ", repr(p[:120]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
