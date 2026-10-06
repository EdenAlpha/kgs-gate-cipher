#!/usr/bin/env python3
"""Extract and parse the embedded command_service.proto FileDescriptorProto.

The generated pb.cc in libUE4.so embeds the serialized FileDescriptorProto. Its
field names are visible as strings:

    command_service.proto / CommandRequest / path / packMode / req
    CommandResponse / packMode / res / PackMode / PACK_MODE_JSON
    PACK_MODE_MSGPACK / CommandService / CommandStream

Field *numbers* are varints inside the descriptor, not in the string table, so
the descriptor blob is located by searching for its own name field
(0x0a 0x18 "command_service.proto") and then parsed properly. That gives the
exact wire contract instead of an inferred one:

    message CommandRequest  { string path = ?; PackMode packMode = ?; bytes req = ?; }
    message CommandResponse { PackMode packMode = ?; bytes res = ?; }
"""
from __future__ import annotations

import struct
import sys

SO = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"

TYPES = {1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
         8: "bool", 9: "string", 11: "message", 12: "bytes", 13: "uint32",
         14: "enum", 15: "sfixed32", 16: "sfixed64", 17: "sint32", 18: "sint64"}
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
    return v, i


def fields(b):
    """Yield (field_number, wire_type, value) for a protobuf message."""
    i = 0
    while i < len(b):
        key, i = varint(b, i)
        fn, wt = key >> 3, key & 7
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


def parse_field(b):
    name = number = label = typ = type_name = None
    for fn, wt, v in fields(b):
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
    return name, number, label, typ, type_name


def parse_enum(b):
    name = None
    values = []
    for fn, wt, v in fields(b):
        if fn == 1 and wt == 2:
            name = v.decode()
        elif fn == 2 and wt == 2:
            vn = num = None
            for f2, w2, v2 in fields(v):
                if f2 == 1 and w2 == 2:
                    vn = v2.decode()
                elif f2 == 2 and w2 == 0:
                    num = v2
            values.append((vn, num))
    return name, values


def parse_message(b):
    name = None
    flds = []
    nested = []
    for fn, wt, v in fields(b):
        if fn == 1 and wt == 2:
            name = v.decode()
        elif fn == 2 and wt == 2:
            flds.append(parse_field(v))
        elif fn == 3 and wt == 2:
            nested.append(parse_message(v))
    return name, flds, nested


def main() -> int:
    d = open(SO, "rb").read()
    needle = b"\x0a\x18command_service.proto"
    hits = []
    i = 0
    while True:
        i = d.find(needle, i)
        if i < 0:
            break
        hits.append(i)
        i += 1
    print("descriptor name-field occurrences: %d -> %s"
          % (len(hits), [hex(h) for h in hits]))
    if not hits:
        print("could not locate the descriptor")
        return 1

    start = hits[0]
    # walk forward parsing the FileDescriptorProto, keeping whole fields
    i = start
    end = start
    # find a sane end by parsing fields until we hit something implausible
    while i < len(d) and i < start + 8192:
        before = i
        try:
            key, j = varint(d, i)
            fn, wt = key >> 3, key & 7
            if wt == 2:
                ln, j = varint(d, j)
                if ln > 4096 or j + ln > len(d):
                    break
                j += ln
            elif wt == 0:
                _, j = varint(d, j)
            else:
                break
        except Exception:
            break
        if j <= before:
            break
        i = j
        end = j
    blob = d[start:end]
    print("descriptor blob: %d bytes from %#x\n" % (len(blob), start))

    pkg = syntax = None
    msgs = []
    enums = []
    services = []
    for fn, wt, v in fields(blob):
        if fn == 2 and wt == 2:
            pkg = v.decode()
        elif fn == 4 and wt == 2:
            msgs.append(parse_message(v))
        elif fn == 5 and wt == 2:
            enums.append(parse_enum(v))
        elif fn == 6 and wt == 2:
            sname = None
            methods = []
            for f2, w2, v2 in fields(v):
                if f2 == 1 and w2 == 2:
                    sname = v2.decode()
                elif f2 == 2 and w2 == 2:
                    mn = it = ot = cs = ss = None
                    for f3, w3, v3 in fields(v2):
                        if f3 == 1 and w3 == 2:
                            mn = v3.decode()
                        elif f3 == 2 and w3 == 2:
                            it = v3.decode()
                        elif f3 == 3 and w3 == 2:
                            cs = v3.decode()
                        elif f3 == 4 and w3 == 2:
                            ss = v3.decode()
                    methods.append((mn, it, cs, ss, ot))
            services.append((sname, methods))
        elif fn == 12 and wt == 2:
            syntax = v.decode()

    print('syntax = "%s";  package %s;\n' % (syntax, pkg))
    for name, vals in enums:
        print("enum %s {" % name)
        for vn, num in vals:
            print("    %-24s = %s;" % (vn, num))
        print("}\n")

    for name, flds, nested in msgs:
        print("message %s {" % name)
        for fn_, number, label, typ, tn in sorted(flds, key=lambda x: (x[1] or 0)):
            t = TYPES.get(typ, typ)
            if tn:
                t = tn
            print("    %-10s %-38s = %s;   // %s, %s"
                  % (LABEL.get(label, "?"), t, number, fn_,
                     LABEL.get(label, "?")))
        for nn, nf, _ in nested:
            print("    // nested message %s" % nn)
        print("}\n")

    for sname, methods in services:
        print("service %s {" % sname)
        for mn, it, cs, ss, ot in methods:
            print("    rpc %s(%s) returns (%s);" % (mn, it, ot or ss))
        print("}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
