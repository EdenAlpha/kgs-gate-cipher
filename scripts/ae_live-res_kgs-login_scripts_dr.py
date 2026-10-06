#!/usr/bin/env python3
"""disasm a byte range:  python dr.py 0xSTART 0xEND"""
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SO = r"C:\Users\Administrator\Documents\Default Project\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a\libUE4.so"
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def main():
    a = int(sys.argv[1], 16)
    b = int(sys.argv[2], 16)
    with open(SO, "rb") as f:
        f.seek(a - 0x4000)
        code = f.read(b - a)
    for ins in md.disasm(code, a):
        print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")


if __name__ == "__main__":
    main()
