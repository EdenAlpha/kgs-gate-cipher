import re
with open("ue4_strings.txt",encoding="utf-8",errors="replace") as f:
    for line in f:
        try: off,s=line.split("\t",1)
        except ValueError: continue
        s=s.rstrip("\n")
        if "timeout_sec" in s or "giveup_msec" in s:
            print(off, repr(s[:600]))
