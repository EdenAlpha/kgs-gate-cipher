import csv, struct, collections, re

def pr(s):
    if isinstance(s, bytes):
        return s.decode("ascii", "replace")
    return s.encode("ascii", "replace").decode()

def sni_of(b):
    try:
        if b[0] != 0x16:
            return None
        rl = struct.unpack("!H", b[3:5])[0]
        p = b[5:5 + rl]
        if not p or p[0] != 0x01:
            return None
        q = 4 + 2 + 32
        sid = p[q]; q += 1 + sid
        cs = struct.unpack("!H", p[q:q + 2])[0]; q += 2 + cs
        cm = p[q]; q += 1 + cm
        el = struct.unpack("!H", p[q:q + 2])[0]; q += 2
        end = q + el
        while q + 4 <= end:
            et, xl = struct.unpack("!HH", p[q:q + 4]); q += 4
            if et == 0 and xl >= 5:
                nl = struct.unpack("!H", p[q + 3:q + 5])[0]
                return p[q + 5:q + 5 + nl].decode("ascii", "replace")
            q += xl
    except Exception:
        return None
    return None

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
sni = collections.Counter(); reqs = collections.Counter(); hosts = collections.Counter()
posts = []
with open(path, newline="") as f:
    rdr = csv.reader(f); hdr = None
    for row in rdr:
        if not row or row[0].startswith("#"):
            continue
        if hdr is None:
            hdr = row; continue
        ts, d, proto, src, sport, dst, dport, iplen, hexs = row[:9]
        try:
            pb = bytes.fromhex(hexs)
        except Exception:
            continue
        if proto != "tcp" or len(pb) < 40:
            continue
        ihl = (pb[0] & 0xF) * 4
        thl = (pb[ihl + 12] >> 4) * 4
        pl = pb[ihl + thl:]
        if not pl:
            continue
        if int(dport) == 443 and pl[0] == 0x16:
            s = sni_of(pl)
            if s:
                sni[s] += 1
        if int(dport) == 80:
            m = re.match(rb"(GET|POST|PUT) (\S+) HTTP/1\.[01]", pl)
            if m:
                reqs[(m.group(1).decode(), m.group(2).decode())] += 1
                hm = re.search(rb"Host: ([^\r\n]+)", pl)
                if hm:
                    hosts[hm.group(1).decode()] += 1
                if m.group(1) == b"POST":
                    posts.append(pl)

print("--- ALL plaintext HTTP requests (port 80) ---")
for k, v in reqs.most_common(60):
    print("   %-6s %-55s %d" % (k[0], k[1], v))
print("\n--- plaintext HTTP Host headers ---")
for k, v in hosts.most_common(20):
    print("   %-45s %d" % (k, v))
print("\n--- TLS SNI (encrypted channels) ---")
for k, v in sni.most_common(30):
    print("   %-55s %d" % (pr(k), v))
print("\n--- first POST (headers + body) decoded ---")
if posts:
    p = posts[0]
    he = p.find(b"\r\n\r\n")
    print("   " + pr(p[:he]).replace("\r\n", "\n   "))
    body = p[he + 4:]
    print("\n   BODY[0:700] decoded:\n   " + pr(body[:700]))
