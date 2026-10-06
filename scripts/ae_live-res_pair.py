import csv, re, collections, urllib.parse, datetime

T0 = 1790385845.048
def hms(ms):
    off = (ms - T0*1000.0)/1000.0
    return "%02d:%06.3f" % (off//60, off%60)

def events(path):
    out=[]
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            if row and row[0].startswith("# event"):
                parts = row[0].split()
                if len(parts) > 2 and parts[2].isdigit():
                    out.append(row[0])
    return out

def reports(path):
    flows=collections.defaultdict(list)
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        rdr=csv.reader(f); hdr=None
        for row in rdr:
            if not row or row[0].startswith("#"): continue
            if hdr is None: hdr=row; continue
            ts,d,proto,src,sport,dst,dport,iplen,hexs=row[:9]
            if proto!="tcp": continue
            try: pb=bytes.fromhex(hexs)
            except Exception: continue
            ihl=(pb[0]&0xF)*4; thl=(pb[ihl+12]>>4)*4
            pl=pb[ihl+thl:]
            if pl: flows[(src,sport,dst,dport,d)].append((int(ts),pl))
    msgs=[]
    for key,segs in flows.items():
        if int(key[3])!=80 or key[4]!="t": continue
        segs.sort(); buf=b"".join(s for _,s in segs); i=0
        while True:
            m=re.search(rb"POST (\S+) HTTP/1\.[01]\r\n", buf[i:])
            if not m: break
            start=i+m.start(); hend=buf.find(b"\r\n\r\n", start)
            if hend<0: break
            cl=re.search(rb"Content-Length: (\d+)", buf[start:hend])
            n=int(cl.group(1)) if cl else 0
            msgs.append((segs[0][0], m.group(1).decode(), buf[hend+4:hend+4+n]))
            i=hend+4+n
            if n==0: break
    return sorted(msgs)

def decode(body):
    txt=body.decode("ascii","replace")
    if "dat=" not in txt: return None
    raw=urllib.parse.unquote(txt.split("dat=",1)[1])
    try: return bytes.fromhex(raw).decode("utf-8","replace")
    except Exception as e: return "<fail %s>"%e

def safe(s): return s.encode("ascii","replace").decode("ascii")

for phone in ["z1-tiamant-client","z2-elijah-hotspot-owner"]:
    base=r"captures\match-2026-09-26\%s"%phone
    ev=events(base+r"\passthrough_capture.csv")
    rp=reports(base+r"\passthrough_capture.csv")
    print("="*78)
    print(phone)
    print("  events:")
    for e in ev: print("    ", e, "   @", hms(int(e.split()[2])))
    print("  plaintext HTTP posts:")
    for t,p,b in rp:
        print("    %-42s %s  body=%d" % (p, hms(t), len(b)))
    cliffs=[int(e.split()[2]) for e in ev if "0pps_cliff" in e]
    print("  -> pairing each cliff with the nearest preceding ReportLog:")
    for i in range(0,len(cliffs),2):
        c=cliffs[i]
        best=None
        for t,p,b in rp:
            if p.endswith("ReportLog.php") and t<=c and (best is None or t>best[0]):
                best=(t,b)
        if best:
            dt=(c-best[0])/1000.0
            print("     cliff %s  <- ReportLog %s  (dt = %.2f s)"%(hms(c),hms(best[0]),dt))


