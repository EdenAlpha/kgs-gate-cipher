import csv, struct, socket, collections
from reassemble import hms, safe

path = r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
T0 = 1790385845.048
SCORE_COMMIT = 1790387785479

# resolve konami names
def read_name(b, i, depth=0):
    out=[]
    if depth>8: return "", i
    while i < len(b):
        l=b[i]
        if l==0: i+=1; break
        if l & 0xC0 == 0xC0:
            ptr=((l&0x3F)<<8)|b[i+1]; i+=2
            n,_=read_name(b, ptr, depth+1); out.append(n); break
        i+=1; out.append(b[i:i+l].decode("latin-1","replace")); i+=l
    return ".".join(out), i

a2n = collections.defaultdict(set)
syns = []
for row in csv.reader(open(path, newline="", encoding="utf-8", errors="replace")):
    if not row or row[0].startswith("#") or row[0]=="ts_ms" or len(row)<9: continue
    ts,d,proto,src,sport,dst,dport,iplen,hexs = row[:9]
    try: pb=bytes.fromhex(hexs)
    except Exception: continue
    if proto=="udp" and int(sport)==53:
        dns=pb[28:]
        if len(dns)>=12:
            qd,an=struct.unpack("!HH", dns[4:8]); i=12
            for _ in range(qd):
                _,i=read_name(dns,i); i+=4
            for _ in range(an):
                nm,i=read_name(dns,i)
                typ,cls,ttl,rdlen=struct.unpack("!HHIH", dns[i:i+10]); i+=10
                rd=dns[i:i+rdlen]; i+=rdlen
                if typ==1 and rdlen==4: a2n[socket.inet_ntoa(rd)].add(nm)
    elif proto=="tcp":
        ihl=(pb[0]&0xF)*4; thl=(pb[ihl+12]>>4)*4
        if thl<20: continue
        flags=pb[ihl+13]
        if flags & 0x02 and not (flags & 0x10):   # pure SYN
            syns.append((int(ts), dst, int(dport)))

print("TCP connections opened, session-relative (score_commit at %s):" % hms(SCORE_COMMIT))
for t,dst,dp in sorted(syns):
    host = sorted(a2n.get(dst, []))
    host = host[0] if host else "(unknown)"
    dt = (t - SCORE_COMMIT)/1000.0
    mark = ""
    if abs(dt) < 30: mark = "   <== within 30s of match end"
    elif -60 < dt < 0: mark = "   (before match end)"
    print("   %s  %-18s:%-5d  %-45s  dt=%+8.1fs%s" % (hms(t), dst, dp, host, dt, mark))
