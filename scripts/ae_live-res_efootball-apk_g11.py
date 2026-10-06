import re
pats={"HTTP11":r"^HTTP/1\.[01]$|^HTTP/1\.1 ","HOSTHDR":r"^Host: $|^Host:$|Host: %s","POST":r"^POST $|^POST /","URLENC":r"x-www-form-urlencoded"}
res={k:[] for k in pats}
with open("ue4_strings.txt",encoding="utf-8",errors="replace") as f:
    for line in f:
        try: off,s=line.split("\t",1)
        except ValueError: continue
        s=s.rstrip("\n")
        for k,p in pats.items():
            if len(res[k])<30 and re.search(p,s): res[k].append((off,s))
for k in pats:
    print("="*7,k,"(%d)"%len(res[k]))
    for off,s in res[k]: print("   %s %r"%(off,s[:120]))
