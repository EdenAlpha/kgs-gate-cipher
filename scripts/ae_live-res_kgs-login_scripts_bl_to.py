"""Scan .text for `bl <target>` (and `b <target>`).

  python bl_to.py 0xTARGET [0xSTART 0xEND]
"""
import struct
import sys

SO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
TEXT_OFF, TEXT_ADDR, TEXT_SIZE = 0x28253C0, 0x28293C0, 0x630BE48


def main():
    t = int(sys.argv[1], 16)
    lo = int(sys.argv[2], 16) if len(sys.argv) > 2 else TEXT_ADDR
    hi = int(sys.argv[3], 16) if len(sys.argv) > 3 else TEXT_ADDR + TEXT_SIZE
    data = open(SO, "rb").read()
    start = TEXT_OFF + max(0, lo - TEXT_ADDR)
    end = TEXT_OFF + min(TEXT_SIZE, hi - TEXT_ADDR)
    hits = []
    for p in range(start & ~3, end, 4):
        w = struct.unpack_from("<I", data, p)[0]
        op = w >> 26
        if op == 0x25:            # BL
            imm26 = w & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= 1 << 26
            pc = TEXT_ADDR + (p - TEXT_OFF)
            if pc + imm26 * 4 == t:
                hits.append((pc, "BL"))
        elif op == 0x5:           # B
            imm26 = w & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= 1 << 26
            pc = TEXT_ADDR + (p - TEXT_OFF)
            if pc + imm26 * 4 == t:
                hits.append((pc, "B"))
    print(f"callers: {len(hits)}")
    for h in hits:
        print(f"  {h[0]:#x}  {h[1]}")


if __name__ == "__main__":
    main()
