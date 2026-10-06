want=["http://","https://","http://ntl.service.konami.net/ntl/api/GateInfo.php","gate.php"]
with open("ue4_strings.txt",encoding="utf-8",errors="replace") as f:
    for line in f:
        try: off,s=line.split("\t",1)
        except ValueError: continue
        s=s.rstrip("\n")
        if s in want:
            print("%-55s %s"%(off,repr(s)))
        elif s.startswith("https://") and len(s)<70:
            print("%-55s %s"%(off,repr(s)))
