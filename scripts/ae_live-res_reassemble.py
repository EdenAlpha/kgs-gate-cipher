import csv, re, collections, urllib.parse, struct, sys

T0 = 1790385845.048


def hms(ms):
    off = (ms - T0 * 1000.0) / 1000.0
    return "%02d:%06.3f" % (off // 60, off % 60)


def safe(s):
    return s.encode("ascii", "replace").decode("ascii")


def http_messages(path):
    """Reassemble outbound TCP port-80 streams using TCP sequence numbers,
    skipping retransmissions, then split into HTTP requests by Content-Length."""
    segs_by_flow = collections.defaultdict(dict)   # key -> {seq: (ts, payload)}
    for row in csv.reader(open(path, newline="", encoding="utf-8", errors="replace")):
        if not row or row[0].startswith("#") or row[0] == "ts_ms":
            continue
        if len(row) < 9:
            continue
        ts, d, proto, src, sport, dst, dport, iplen, hexs = row[:9]
        if proto != "tcp" or d != "t" or int(dport) != 80:
            continue
        try:
            pb = bytes.fromhex(hexs)
        except Exception:
            continue
        ihl = (pb[0] & 0xF) * 4
        thl = (pb[ihl + 12] >> 4) * 4
        if thl < 20:
            continue
        seq = struct.unpack_from(">I", pb, ihl + 4)[0]     # TCP seq is network order
        pl = pb[ihl + thl:]
        if not pl:
            continue
        segs_by_flow[(src, sport, dst, dport)].setdefault(seq, (int(ts), pl))

    msgs = []
    for key, table in segs_by_flow.items():
        # unwrap relative to the connection's ISN (the SYN segment, if present)
        ordered = sorted(table, key=lambda s: s)
        buf = b"".join(table[s][1] for s in ordered)
        ts0 = table[ordered[0]][0]
        i = 0
        while True:
            m = re.search(rb"(?:GET|POST) (\S+) HTTP/1\.[01]\r\n", buf[i:])
            if not m:
                break
            start = i + m.start()
            hend = buf.find(b"\r\n\r\n", start)
            if hend < 0:
                break
            cl = re.search(rb"Content-Length: (\d+)", buf[start:hend])
            n = int(cl.group(1)) if cl else 0
            body = buf[hend + 4:hend + 4 + n]
            hdrs = buf[start:hend]
            msgs.append((ts0, m.group(1).decode(), hdrs, body))
            i = hend + 4 + n
            if n == 0:
                break
    return sorted(msgs)


def decode(body):
    txt = body.decode("ascii", "replace")
    if "dat=" not in txt:
        return None, txt
    raw = txt.split("dat=", 1)[1].split("&", 1)[0]
    raw = urllib.parse.unquote(raw)
    raw = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(raw) % 2:
        raw = raw[:-1]
    try:
        return bytes.fromhex(raw).decode("utf-8", "replace"), txt
    except Exception as e:
        return "<decode failed: %s>" % e, txt
