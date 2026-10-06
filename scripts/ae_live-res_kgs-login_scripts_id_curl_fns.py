"""Identify the curl entry points by disassembly shape."""
import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_VADDR, TEXT_OFF = 0x28293C0, 0x28253C0

CANDIDATES = [
    0x6858B14,   # called at 0x7d03bb8
    0x6858C98,   # called at 0x7d03bbc (previously assumed init)
    0x68788B4,   # called after setopt cluster
    0x68788C4,
    0x6886B48,   # near setopt (getinfo?)
    0x6858F40,   # near init (cleanup?)
    0x6878E80,
    0x6878A50,
    0x6879928,
    0x6858B48,
]


def cstr(raw, addr, n=120):
    if 0 <= addr < len(raw):
        b = raw[addr:addr + n]
        i = b.find(b"\0")
        if 0 < i < n:
            s = b[:i]
            if all(32 <= c < 127 for c in s) and len(s) >= 3:
                return s.decode("ascii")
    return None


def main():
    with open(SO, "rb") as f:
        raw = f.read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    print("=== call site context: HTTP_POST 0x7d03ba8 .. 0x7d03c30 ===")
    off = 0x7D03BA8 - TEXT_VADDR + TEXT_OFF
    for ins in md.disasm(raw[off:off + 0x88], 0x7D03BA8):
        line = f"  0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}"
        if ins.mnemonic == "bl":
            line += "   <== ?"
        print(line)

    for a in CANDIDATES:
        print(f"\n=== {a:#x} ===")
        off = a - TEXT_VADDR + TEXT_OFF
        if off < 0 or off >= len(raw):
            print("  out of range")
            continue
        n = 0
        adrp = {}
        for ins in md.disasm(raw[off:off + 40 * 4], a):
            line = f"  0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}"
            if ins.mnemonic == "adrp":
                adrp[ins.op_str.split(",")[0].strip()] = \
                    int(ins.op_str.split("#")[-1], 16)
            elif ins.mnemonic == "add" and ", #" in ins.op_str:
                parts = [p.strip() for p in ins.op_str.split(",")]
                if len(parts) > 2 and parts[1] in adrp:
                    try:
                        va = adrp[parts[1]] + int(parts[-1].lstrip("#"), 16)
                        s = cstr(raw, va)
                        if s:
                            line += f'        ; "{s}"'
                    except Exception:
                        pass
            print(line)
            n += 1
            if ins.mnemonic == "ret" and n > 6:
                break
            if n >= 40:
                break
    return 0


if __name__ == "__main__":
    sys.exit(main())
