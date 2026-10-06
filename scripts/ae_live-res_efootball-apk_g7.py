import re
pats = {
 "SCHEME": r"^https?://|\bhttps?://[A-Za-z0-9.\-]+",
 "PHP": r"\.php$|\.php\b",
 "GATE": r"(?i)gate|/cmd/|cmdget",
 "PIN": r"(?i)certificate.?pin|ssl.?pin|publickeypin|TrustManager|X509TrustManager|HostnameVerifier|ALLOW_ALL",
 "TLS_VER": r"(?i)TLSv1|SSLv3|SSL_CTX|BoringSSL|conscrypt",
}
res={k:[] for k in pats}
with open("ue4_strings.txt",encoding="utf-8",errors="replace") as f:
    for line in f:
        try: off,s=line.split("\t",1)
        except ValueError: continue
        s=s.rstrip("\n")
        for k,p in pats.items():
            if len(res[k])<45 and re.search(p,s):
                res[k].append((off,s))
for k in pats:
    print("="*7,k,"(%d)"%len(res[k]))
    for off,s in res[k]:
        print("   %s %r"%(off,s[:130]))
