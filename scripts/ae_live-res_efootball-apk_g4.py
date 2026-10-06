import re
n=0
with open("ue4_strings.txt",encoding="utf-8",errors="replace") as f:
    for line in f:
        try: off,s=line.split("\t",1)
        except ValueError: continue
        s=s.rstrip("\n")
        if len(s)>200 and s.count(":")>6 and ("{" in s):
            n+=1
            print(off, "LEN=%d"%len(s), repr(s[:700]))
            print()
            if n>25: break
