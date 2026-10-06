import csv, struct, collections

def sni_of(clienthello):
    # TLS record 16 03 xx, handshake 01
    try:
        if clienthello[0]!=0x16: return None
        rec_len=struct.unpack("!H", clienthello[3:5])[0]
        p=clienthello[5:5+rec_len]
        if not p or p[0]!=0x01: return None
        q=9                      # hs hdr(4)+ver(2)+rnd(32)+sidlen(1)
        sidlen=p[q]; q+=1+sidlen
        cslen=struct.unpack("!H",p[q:q+2])[0]; q+=2+cslen
        complen=p[q]; q+=1+complen
        extlen=struct.unpack("!H",p[q:q+2])[0]; q+=2
        end=q+extlen
        while q+4<=end:
            et,el=struct.unpack("!HH",p[q:q+4]); q+=4
            if et==0 and el>=5:
                nl=struct.unpack("!H",p[q+3:q+5])[0]
                return p[q+5:q+5+nl].decode("latin-1","replace")
            q+=el
    except Exception: return None
    return None

def decode_dns_name(b,i):
    out=[]
    while i<len(b):
        l=b[i]
        if l==0: i+=1;break
        if l&0xC0==0xC0:
            ptr=((l&0x3F)<<8)|b[i+1]; i+=2
            n,_=decode_dns_name(b,ptr); out.append(n); break
        i+=1; out.append(b[i:i+l].decode("latin-1","replace")); i+=l
    return ".".join(out),i

path=r"captures\match-2026-09-26\z1-tiamant-client\passthrough_capture.csv"
sni=collections.Counter(); p80=[]; konami_dns=collections.Counter()
with open(path,newline="") as f:
    rdr=csv.reader(f); hdr=None
    for row in rdr:
        if not row or row[0].startswith("#"): continue
        if hdr is None: hdr=row; continue
        ts,d,proto,src,sport,dst,dport,iplen,hexs=row[:9]
        try: pb=bytes.fromhex(hexs)
        except Exception: continue
        if proto=="tcp" and len(pb)>=40:
            ihl=(pb[0]&0xF)*4
            thl=(pb[ihl+12]>>4)*4
            pl=pb[ihl+thl:]
            if int(dport)==443 and len(pl)>60 and pl[0]==0x16:
                s=sni_of(pl)
                if s: sni[s]+=1
            if int(dport)==80 and pl:
                p80.append((ts,pl))
        if proto=="udp" and int(dport)==53 and len(pb)>=40:
            dns=pb[28:]
            if len(dns)>=12:
                nm,_=decode_dns_name(dns,12)
                if "konami" in nm: konami_dns[nm]+=1

print("--- TLS SNI (hostname inside the encryption) ---")
for k,v in sni.most_common(30): print("   %-58s %d"%(k.encode("ascii","replace").decode(),v))
print("\n--- konami DNS queries seen ---")
for k,v in konami_dns.most_common(30): print("   %-58s %d"%(k,v))
print("\n--- port 80 payloads: %d packets ---"%len(p80))
shown=0
for ts,pl in p80:
    if len(pl)>10 and shown<14:
        print("   %s %r"%(ts,repr(pl[:150]).encode("ascii","replace").decode()))
        shown+=1
if not shown:
    for ts,pl in p80[:6]:
        print("   (small) %s len=%d %r"%(ts,len(pl),repr(pl[:40]).encode("ascii","replace").decode()))



