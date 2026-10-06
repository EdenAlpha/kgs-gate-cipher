#!/usr/bin/env python3
"""Parse the embedded command_service FileDescriptorProto for real.

Located by its own name field: at 0xc95b00 the bytes are `0a 15` followed by
"command_service.proto" (21 = 0x15 bytes), which is FileDescriptorProto field 1
(`name`). The message definitions follow inline:

    0xc95b2a  0a 0d "CommandRequest"
    0xc95b90  0a 0f "CommandResponse"
    0xc95be9  0a 08 "PackMode"

The earlier attempt searched for `\x0a\x18` (assuming a 24-character name) and
found nothing, which is why it reported "could not locate the descriptor". The
name is 21 characters, not 24.
"""
from __future__ import annotations

import struct
import sys

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"
START = 0xc95b00

TYPES = {1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
         6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 10: "group",
         11: "message", 12: "bytes", 13: "uint32", 14: "enum", 15: "sfixed32",
         16: "sfixed64", 17: "sint32", 18: "sint64"}
LABEL = {1: "optional", 2: "required", 3: "repeated"}


def varint(b, i):
    v, shift = 0, 0
    while i < len(b):
        x = b[i]
        v |= (x & 0x7F) << shift
        i += 1
        if not (x & 0x80):
            break
        shift += 7
        if shift > 63:
            break
    return v, i


def fields(b, lo=0, hi=None):
    """Yield (field_number, wire_type, value, start_offset, end_offset)."""
    i = lo
    end = len(b) if hi is None else hi
    while i < end:
        st = i
        try:
            key, i = varint(b, i)
        except Exception:
            return
        fn, wt = key >> 3, key & 7
        if fn == 0:
            return
        if wt == 0:
            v, i = varint(b, i)
        elif wt == 1:
            if i + 8 > end:
                return
            v = struct.unpack_from("<Q", b, i)[0]
            i += 8
        elif wt == 2:
            ln, i = varint(b, i)
            if ln > end - i:
                return
            v = b[i:i + ln]
            i += ln
        elif wt == 5:
            if i + 4 > end:
                return
            v = struct.unpack_from("<I", b, i)[0]
            i += 4
        else:
            return
        yield fn, wt, v, st, i


def parse_field(b):
    name = number = label = typ = type_name = None
    json_name = None
    for fn, wt, v, _s, _e in fields(b):
        if fn == 1 and wt == 2:
            name = v.decode()
        elif fn == 3 and wt == 0:
            number = v
        elif fn == 4 and wt == 0:
            label = v
        elif fn == 5 and wt == 0:
            typ = v
        elif fn == 6 and wt == 2:
            type_name = v.decode()
        elif fn == 10 and wt == 2:
            json_name = v.decode()
    return dict(name=name, number=number, label=label, type=typ,
                type_name=type_name, json_name=json_name)


def parse_message(b):
    name = None
    flds = []
    nested = []
    enums = []
    for fn, wt, v, _s, _e in fields(b):
        if fn == 1 and wt == 2:
            name = v.decode()
        elif fn == 2 and wt == 2:
            flds.append(parse_field(v))
        elif fn == 3 and wt == 2:
            nested.append(parse_message(v))
        elif fn == 4 and wt == 2:
            enums.append(parse_enum(v))
    return dict(name=name, fields=flds, nested=nested, enums=enums)


def parse_enum(b):
    name = None
    vals = []
    for fn, wt, v, _s, _e in fields(b):
        if fn == 1 and wt == 2:
            name = v.decode()
        elif fn == 2 and wt == 2:
            vn = num = None
            for f2, w2, v2, _a, _b2 in fields(v):
                if f2 == 1 and w2 == 2:
                    vn = v2.decode()
                elif f2 == 2 and w2 == 0:
                    num = v2
            vals.append((vn, num))
    return dict(name=name, values=vals)


def main() -> int:
    d = open(SO, "rb").read()
    blob = d[START:START + 0x2000]
    print("descriptor candidate at %#x" % START)
    print("  first bytes: %s" % blob[:48].hex())
    print("  name field : %r\n" % blob[2:2 + blob[1]])

    name = pkg = syntax = None
    msgs, enums, services = [], [], []
    for fn, wt, v, st, en in fields(blob, 0, 0x400):
        if fn == 1 and wt == 2:
            name = v.decode()
        elif fn == 2 and wt == 2:
            pkg = v.decode()
        elif fn == 4 and wt == 2:
            msgs.append(parse_message(v))
        elif fn == 5 and wt == 2:
            enums.append(parse_enum(v))
        elif fn == 6 and wt == 2:
            sname = None
            methods = []
            for f2, w2, v2, _a, _b2 in fields(v):
                if f2 == 1 and w2 == 2:
                    sname = v2.decode()
                elif f2 == 2 and w2 == 2:
                    mn = it = ot = cs = None
                    streaming = None
                    for f3, w3, v3, _c, _dd in fields(v2):
                        if f3 == 1 and w3 == 2:
                            mn = v3.decode()
                        elif f3 == 2 and w3 == 2:
                            it = v3.decode()
                        elif f3 == 3 and w3 == 2:
                            cs = v3.decode()
                        elif f3 == 4 and w3 == 2:
                            ot = v3.decode()
                        elif f3 == 5 and w3 == 0:
                            streaming = v3
                    methods.append(dict(name=mn, input=it, output=ot,
                                        client_stream=cs, server_stream=streaming))
            services.append(dict(name=sname, methods=methods))
        elif fn == 12 and wt == 2:
            syntax = v.decode()

    print('// file    : %s' % name)
    print('// package : %s' % pkg)
    print('// syntax  : %s\n' % syntax)

    for e in enums:
        print("enum %s {" % e["name"])
        for vn, num in e["values"]:
            print("    %s = %s;" % (vn, num))
        print("}\n")

    for m in msgs:
        print("message %s {" % m["name"])
        for f in sorted(m["fields"], key=lambda x: (x["number"] or 0)):
            t = f["type_name"] or TYPES.get(f["type"], "?%s" % f["type"])
            print("    %-9s %-34s = %s;%s"
                  % (LABEL.get(f["label"], "?"), t, f["number"],
                     ("   // " + f["name"]) if f["name"] else ""))
        for nn in m["nested"]:
            print("    // nested: %s" % nn["name"])
        print("}\n")

    for s in services:
        print("service %s {" % s["name"])
        for mm in s["methods"]:
            print("    rpc %s(%s%s) returns (%s%s);"
                  % (mm["name"],
                     "stream " if mm["client_stream"] else "", mm["input"],
                     "stream " if mm["server_stream"] else "", mm["output"]))
        print("}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
