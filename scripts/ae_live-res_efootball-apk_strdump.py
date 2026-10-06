import re,sys,os
src=r"native\lib\arm64-v8a\libUE4.so"
out=r"ue4_strings.txt"
MIN=4
pat=re.compile(rb"[\x20-\x7e]{%d,}"%MIN)
n=0
with open(src,"rb") as f, open(out,"w",encoding="utf-8",errors="replace") as o:
    off=0
    buf=f.read(1<<22)
    while buf:
        for m in pat.finditer(buf):
            s=m.group()
            if len(s)>=MIN:
                o.write("%d\t%s\n"%(off+m.start(),s.decode("latin-1")))
                n+=1
        off+=len(buf)
        buf=f.read(1<<22)
print("strings",n,"->",out,os.path.getsize(out))
