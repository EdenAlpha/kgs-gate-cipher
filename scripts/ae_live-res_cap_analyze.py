import csv, socket, struct, collections, sys, io

def decode_dns_name(b, i):
    out=[]; seen=0
    while i < len(b) and seen < 60:
        l=b[i]
        if l==0: i+=1; break
        if l & 0xC0 == 0xC0:
            ptr=((l&0x3F)<<8)|b[i+1]; i+=2
            n,_=decode_dns_name(b, ptr); out.append(n); break
        i+=1; out.append(b[i:i+l].decode("latin-1","replace")); i+=l; seen+=1
    return ".".join(out), i

path=r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
dnsq=collections.Counter(); conns=collections.Counter(); ports=collections.Counter()
tls=0; plainhttp=0; rows=0
samples=[]
with open(path, newline="") as f:
    rdr=csv.reader(f)
    hdr=None
    for row in rdr:
        if not row or row[0].startswith("#"): continue
        if hdr is None: hdr=row; continue
        rows+=1
        ts,d,proto,src,sport,dst,dport,iplen,hexs = row[:9]
        try: pb=bytes.fromhex(hexs)
        except Exception: continue
        ports[(proto,int(dport))]+=1
        # UDP DNS query to :53
        if proto=="udp" and int(dport)==53 and len(pb)>=28+12:
            dns=pb[28:]  # after udp hdr
            if len(dns)>=12:
                qd=struct.unpack("!H", dns[4:6])[0]
                if qd:
                    nm,_=decode_dns_name(dns,12)
                    dnsq[nm]+=1
        # TCP payload detection: iphdr 20 + tcp hdr
        if proto=="tcp" and len(pb)>=40:
            ihl=(pb[0]&0xF)*4
            off=(pb[ihl+12]>>4)*4
            payload=pb[ihl+off:]
            if payload[:1]==b"G" and b"HTTP" in payload[:16]: plainhttp+=1
            if len(payload)>=3 and payload[0]==0x16 and payload[1]==0x03: tls+=1
        if proto=="tcp":
            conns[(dst,int(dport))]+=1

print("rows=%d  TLS-handshake-sigs=%d  plaintext-HTTP-GET=%d"%(rows,tls,plainhttp))
print("\n--- top ports (proto,dport) ---")
for k,v in ports.most_common(15): print("   ",k,v)
print("\n--- DNS queries ---")
for k,v in dnsq.most_common(40): print("   %-60s %d"%(k,v))
print("\n--- top TCP destinations ---")
for k,v in conns.most_common(20): print("   ",k,v)
