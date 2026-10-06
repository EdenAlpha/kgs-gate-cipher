"""Read the two URL-construction sites and print every string literal they
touch, so we know EXACTLY how the request URL is assembled."""
import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_VADDR, TEXT_OFF = 0x28293C0, 0x28253C0

RANGES = [
    ("URL builder 0x7d65884", 0x7D65884, 0x7D659C4),
    ("concat chain 0x7dbc780", 0x7DBC780, 0x7DBC960),
    ("UA builder 0x7dbc400", 0x7DBC400, 0x7DBC560),
    ("msgid append 0x7d0a7b4", 0x7D0A7B4, 0x7D0A900),
]


def cstr(raw, addr, n=160):
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

    for label, a, b in RANGES:
        print(f"\n{'=' * 72}\n=== {label}  ({a:#x} .. {b:#x}) ===")
        off = a - TEXT_VADDR + TEXT_OFF
        adrp = {}
        for ins in md.disasm(raw[off:off + (b - a)], a):
            line = f"  0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}"
            if ins.mnemonic == "adrp":
                adrp[ins.op_str.split(",")[0].strip()] = \
                    int(ins.op_str.split("#")[-1], 16)
            elif ins.mnemonic == "adr":
                try:
                    va = int(ins.op_str.split("#")[-1], 16)
                    s = cstr(raw, va)
                    if s:
                        line += f'        ; "{s}" @{va:#x}'
                except Exception:
                    pass
            elif ins.mnemonic in ("add", "ldr") and ", #" in ins.op_str:
                parts = [p.strip() for p in ins.op_str.split(",")]
                try:
                    imm = int(parts[-1].split("#")[-1], 16)
                except Exception:
                    imm = None
                if imm is not None and len(parts) > 1 and parts[1] in adrp:
                    s = cstr(raw, adrp[parts[1]] + imm)
                    if s:
                        line += f'        ; "{s}"'
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
