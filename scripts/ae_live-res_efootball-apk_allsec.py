import struct
d=open(r"native\lib\arm64-v8a\libUE4.so","rb").read()
shoff=struct.unpack_from("<Q",d,40)[0]
shentsize,shnum,shstrndx=struct.unpack_from("<HHH",d,58)
o=shoff+shstrndx*shentsize
so=struct.unpack_from("<Q",d,o+24)[0]; sz=struct.unpack_from("<Q",d,o+32)[0]
st=d[so:so+sz]
print("%-4s %-24s %-12s %-12s %s"%("idx","name","off","end","size"))
for i in range(shnum):
    b=shoff+i*shentsize
    nm=st[struct.unpack_from("<H",d,b)[0]:].split(b"\0",1)[0].decode("latin-1")
    off=struct.unpack_from("<Q",d,b+24)[0]; s=struct.unpack_from("<Q",d,b+32)[0]
    if nm and s: print("%-4d %-24s 0x%-10x 0x%-10x %d"%(i,nm,off,off+s,s))
print()
print("JNI string 0x12352d falls in:", [st[struct.unpack_from("<H",d,shoff+i*shentsize)[0]:].split(b"\0",1)[0].decode("latin-1") for i in range(shnum) if struct.unpack_from("<Q",d,shoff+i*shentsize+24)[0] <= 0x12352d < struct.unpack_from("<Q",d,shoff+i*shentsize+24)[0]+struct.unpack_from("<Q",d,shoff+i*shentsize+32)[0]])
