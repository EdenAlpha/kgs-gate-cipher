#!/usr/bin/env python3
"""Extract the TRUE CommandRequest/CommandResponse schema from the binary.

Our gRPC 502s may come from wrong protobuf field numbers: we ASSUMED
id=1, packMode=2, req=3, path=4, but never verified.  The binary embeds the
serialized FileDescriptorProto for command_service.proto (protobuf reflection
strings prove it).  Parse it with a minimal wire-format reader -> exact field
names, numbers and types.  No guesses.
"""
from __future__ import annotations

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")

NAME = b"command_service.proto"

TYPE = {1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
        6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 10: "group",
        11: "message", 12: "bytes", 13: "uint32", 14: "enum", 15: "sint32",
        16: "sfixed32", 17: "sfixed64", 18: "sint64"}
LABEL = {1: "optional", 2: "required", 3: "repeated"}


def varint(d: bytes, i: int):
    out, sh = 0, 0
    while True:
        b = d[i]
        i += 1
        out |= (b & 0x7F) << sh
        sh += 7
        if not b & 0x80:
            return out, i


def fields(d: bytes):
    """Yield (field_no, wire_type, value_bytes_or_int) for one message."""
    i, n = 0, len(d)
    while i < n:
        key, i = varint(d, i)
        no, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(d, i)
            yield no, wt, v
        elif wt == 2:
            ln, i = varint(d, i)
            yield no, wt, d[i:i + ln]
            i += ln
        elif wt in (1, 5):
            ln = 8 if wt == 1 else 4
            yield no, wt, d[i:i + ln]
            i += ln
        else:
            return


def show_field(fdp: bytes, ind: str):
    name, num, typ, label, type_name = "?", -1, -1, 1, ""
    for no, wt, v in fields(fdp):
        if no == 1:
            name = v.decode()
        elif no == 3 and wt == 0:
            num = v
        elif no == 4 and wt == 0:
            label = v
        elif no == 5 and wt == 0:
            typ = v
        elif no == 6 and wt == 2:
            type_name = v.decode()
    t = TYPE.get(typ, typ)
    if typ == 11 or typ == 14:
        t += "(%s)" % type_name.split(".")[-1]
    print("    %s%s %s = %d;" % (LABEL.get(label, label) + " "
                                 if label == 3 else "", t, name, num))


def show_msg(dp: bytes, ind=""):
    name = ""
    for no, wt, v in fields(dp):
        if no == 1 and wt == 2:
            name = v.decode()
        elif no == 2 and wt == 2:
            show_field(v, ind)
    print("  message %s" % name)


def main() -> int:
    d = open(SO, "rb").read()
    hits = []
    start = 0
    while True:
        i = d.find(NAME, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    print("occurrences of %r: %d" % (NAME.decode(), len(hits)))
    for i in hits:
        # name is field 1 of FileDescriptorProto: expect 0x0A 0x15 before it
        if d[i - 2:i] != b"\x0a\x15":
            print("  @%#x: no 0x0A14 prefix, skipping" % i)
            continue
        # walk the enclosing message: blob starts at i-2; find its extent by
        # parsing the top-level fields until we run out
        blob_start = i - 2
        # rewind over preceding length-delimited wrappers is unnecessary:
        # FileDescriptorProto is stored whole; parse forward and stop when
        # trailing bytes no longer parse.  Take a 64KB window.
        window = d[blob_start:blob_start + 65536]
        # find message end: parse top-level fields, track consumed length
        consumed = 0
        try:
            for no, wt, v in fields(window):
                pass
        except Exception:
            pass
        print("\n--- FileDescriptorProto @%#x ---" % blob_start)
        # print package + messages + enums
        pos = 0
        # re-parse with length tracking
        i2 = 0
        try:
            while i2 < len(window):
                key, ni = varint(window, i2)
                no, wt = key >> 3, key & 7
                if wt == 0:
                    _, ni = varint(window, ni)
                elif wt == 2:
                    ln, ni = varint(window, ni)
                    val = window[ni:ni + ln]
                    if no == 2:
                        print("  package %s" % val.decode())
                    elif no == 4:
                        show_msg(val)
                    elif no == 5:      # enum
                        ename = ""
                        for eno, ewt, ev in fields(val):
                            if eno == 1:
                                ename = ev.decode()
                            elif eno == 2:
                                vname, vnum = "?", -1
                                for fno, fwt, fv in fields(ev):
                                    if fno == 1:
                                        vname = fv.decode()
                                    elif fno == 2:
                                        vnum = fv
                                print("    %s = %d" % (vname, vnum))
                        print("  enum %s" % ename)
                    elif no == 6:      # service
                        sname = ""
                        for sno, swt, sv in fields(val):
                            if sno == 1:
                                sname = sv.decode()
                            elif sno == 2:
                                mname, inp, out, cs, ss = "?", "", "", False, False
                                for mno, mwt, mv in fields(sv):
                                    if mno == 1:
                                        mname = mv.decode()
                                    elif mno == 2:
                                        inp = mv.decode()
                                    elif mno == 3:
                                        out = mv.decode()
                                    elif mno == 5 and mwt == 0:
                                        cs = bool(mv)
                                    elif mno == 6 and mwt == 0:
                                        ss = bool(mv)
                                print("    %s(%s) returns (%s) "
                                      "client_stream=%s server_stream=%s"
                                      % (mname, inp, out, cs, ss))
                        print("  service %s" % sname)
                    ni += ln
                elif wt in (1, 5):
                    ni += 8 if wt == 1 else 4
                else:
                    break
                i2 = ni
                if i2 > 8192:      # descriptors are small; stop runaway
                    break
        except Exception as e:
            print("  (parse stopped: %s)" % e)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
