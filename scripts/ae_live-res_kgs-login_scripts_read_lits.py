"""Dump the literal bytes used by the URL concat chain, plus the env getter's
signature and the entry layout."""
import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
TEXT_VADDR, TEXT_OFF = 0x28293C0, 0x28253C0

LITS = [
    (0xAFC02A, 8, "sep @0x7dbc800"),
    (0xB5C11F, 8, "sep @0x7dbc828 / 0x7dbc878"),
    (0x9F38AE, 8, "sep @0x7dbc840"),
    (0xA38C40, 8, "repeated 2-char @0x7dbc8a4"),
    (0xA82922, 8, "scheme sep in URL builder"),
    (0xA82000, 16, "page 0xa82000 region"),
]


def main():
    with open(SO, "rb") as f:
        raw = f.read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    print("=== concat-chain literals ===")
    for va, n, note in LITS:
        b = raw[va:va + n]
        txt = "".join(chr(c) if 32 <= c < 127 else f"\\x{c:02x}" for c in b)
        print(f"  {va:#010x}  {b.hex(' ')}   {txt!r}   {note}")

    # The other literals referenced around the chain (adrp+add pairs)
    print("\n=== scan adrp/add literals in 0x7dbc400..0x7dbcc00 ===")
    a, b = 0x7DBC400, 0x7DBCC00
    off = a - TEXT_VADDR + TEXT_OFF
    adrp = {}
    for ins in md.disasm(raw[off:off + (b - a)], a):
        if ins.mnemonic == "adrp":
            adrp[ins.op_str.split(",")[0].strip()] = \
                int(ins.op_str.split("#")[-1], 16)
        elif ins.mnemonic == "add" and ", #" in ins.op_str:
            parts = [p.strip() for p in ins.op_str.split(",")]
            if len(parts) > 2 and parts[1] in adrp:
                try:
                    va = adrp[parts[1]] + int(parts[-1].lstrip("#"), 16)
                except Exception:
                    continue
                seg = raw[va:va + 40]
                n = seg.find(b"\0")
                if 0 < n <= 40 and all(32 <= c < 127 for c in seg[:n]):
                    print(f"  {ins.address:#x} -> {va:#x}  "
                          f"{seg[:n].decode()!r}")
                elif n > 0 and n <= 6:
                    print(f"  {ins.address:#x} -> {va:#x}  "
                          f"SHORT {seg[:n]!r}")

    # env getter
    print("\n=== env-table getter 0x814a04c ===")
    off = 0x814A04C - TEXT_VADDR + TEXT_OFF
    for ins in list(md.disasm(raw[off:off + 24 * 4], 0x814A04C))[:24]:
        print(f"  0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}")
        if ins.mnemonic == "ret":
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
