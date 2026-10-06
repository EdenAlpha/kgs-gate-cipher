"""Read the code around every writer of the URL slot (ctx+0x3968)."""
import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_VADDR, TEXT_OFF = 0x28293C0, 0x28253C0

SITES = [0x8112440, 0x8112428, 0x7D0013C, 0x7D00244, 0x4DE96C4]


def cstr(raw, addr, n=140):
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

    for site in SITES:
        print(f"\n{'='*70}\n=== writer {site:#x} — context ===")
        start = site - 48 * 4
        off = start - TEXT_VADDR + TEXT_OFF
        adrp = {}
        shown = 0
        for ins in md.disasm(raw[off:off + 70 * 4], start):
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
                            line += f'        ; "{s}" @{va:#x}'
                    except Exception:
                        pass
            if ins.address == site:
                line += "     <=== WRITES URL SLOT"
            # only print from 12 before the site to 6 after
            if site - 16 * 4 <= ins.address <= site + 6 * 4:
                print(line)
                shown += 1
            if shown > 30:
                break
    return 0


if __name__ == "__main__":
    sys.exit(main())
