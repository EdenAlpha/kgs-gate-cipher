import re
pats = {
 "HOSTS": r"(?i)\b[a-z0-9\-]+\.(konami\.(net|com)|konamigames\.com)\b|service\.konami|\.konami\.",
 "GATE": r"(?i)gate\.php|ntl/api|/api/|GateInfo",
 "PORTS": r"(?::|//)(443|80|8080)\b|port.{0,10}(443|80)\b",
}
res={k:[] for k in pats}
with open("ue4_strings.txt",encoding="utf-8",errors="replace") as f:
    for line in f:
        try: off,s=line.split("\t",1)
        except ValueError: continue
        s=s.rstrip("\n")
        for k,p in pats.items():
            if len(res[k])<50 and re.search(p,s):
                res[k].append((off,s))
for k in pats:
    print("="*7,k,"(%d)"%len(res[k]))
    for off,s in res[k]:
        print("   %s %r"%(off,s[:140]))
