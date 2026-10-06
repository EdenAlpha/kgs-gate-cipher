import struct
d=open(r"native\lib\arm64-v8a\libUE4.so","rb").read()
# .text va 0x28293c0 off 0x28253c0 -> delta 0x4000
TX_OFF, TX_VA, TX_SZ = 0x28253c0, 0x28293c0, 0x8B31208-0x28253c0
lo, hi = 0x7d2b000, 0x7d42000
o = TX_OFF + (lo - TX_VA); end = TX_OFF + (hi - TX_VA)
hits=[]
while o < end:
    w = struct.unpack_from("<I", d, o)[0]
    va = o - TX_OFF + TX_VA
    # STR Wt,[Xn,#imm12] unsigned offset, size=2 (32-bit) -> 0xB9000000
    if (w & 0xFFC00000) == 0xB9000000:
        imm = ((w >> 10) & 0xFFF) * 4
        if 0x50 <= imm <= 0x8c:
            hits.append((va, w & 0x1F, (w >> 5) & 0x1F, imm))
    o += 4
print("  hits=%d"%len(hits))
for va,rt,rn,imm in hits[:40]:
    print("   0x%08x  str w%-2d -> [x%d, #0x%x]"%(va,rt,rn,imm))
