import csv, re, collections, urllib.parse

T0 = 1790385845.048
def hms(ms):
    off=(ms-T0*1000.0)/1000.0
    return "%02d:%06.3f"%(off//60, off%60)
def safe(s): return s.encode("ascii","replace").decode("ascii")

def reports(path):
    flows=collections.defaultdict(list)
    with open(path,newline="",encoding="utf-8",errors="replace") as f:
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

path=r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
TARGET=1790386488724  # cliff #1
best=None
for t,p,b in reports(path):
    if p.endswith("ReportLog.php") and t<=TARGET and (best is None or t>best[0]):
        best=(t,b)
t,b=best
txt=b.decode("ascii","replace")
print("Report sent at %s  (%.2f s BEFORE the 0pps_cliff at %s)"%(hms(t),(TARGET-t)/1000.0,hms(TARGET)))
print("HTTP body bytes:",len(b))
print("\n--- outer form (first 200 chars) ---")
print(safe(txt[:200]))
raw=urllib.parse.unquote(txt.split("dat=",1)[1])
dat=bytes.fromhex(raw).decode("utf-8","replace")
print("\n--- DECODED, %d chars, FULL ---"%len(dat))
print(safe(dat))
