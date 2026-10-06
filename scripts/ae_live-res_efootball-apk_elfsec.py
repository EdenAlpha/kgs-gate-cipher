import struct
f=open(r"native\lib\arm64-v8a\libUE4.so","rb")
e=f.read(64)
assert e[:4]==b"\x7fELF"
shoff=struct.unpack_from("<Q",e,0x28)[0]
shentsize,shnum,shstrndx=struct.unpack_from("<HHH",e,0x3a)
f.seek(shoff)
sh=f.read(shentsize*shnum)
def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u64(b,o): return struct.unpack_from("<Q",b,o)[0]
st_off=u64(sh,shstrndx*shentsize+24)
st_sz=u64(sh,shstrndx*shentsize+32)
f.seek(st_off); strtab=f.read(st_sz)
print("idx  type     flags        addr             off        size         name")
for i in range(shnum):
    o=i*shentsize
    name=strtab[u16(sh,o):].split(b"\0",1)[0].decode("latin-1")
    typ=u32=u16(sh,o+4)
    flags=u64(sh,o+8)
    addr=u64(sh,o+16); off=u64(sh,o+24); sz=u64(sh,o+32)
    if sz>0 and (typ in (1,8) or name.startswith((".rodata",".data",".text"))):
        print("%-4d %-8d 0x%-10x 0x%-14x 0x%-8x 0x%-10x %s"%(i,typ,flags,addr,off,sz,name))
