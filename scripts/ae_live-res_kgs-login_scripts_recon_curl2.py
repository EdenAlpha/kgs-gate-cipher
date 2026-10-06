"""Locate curl_easy_setopt rigorously: M17's 0x6886498 didn't decode as a
function entry at raw file offset, so try the vaddr interpretation, look for a
symbol table, and scan for any curl-related strings."""
import os, re, sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
M17 = 0x6886498


def disasm(raw, off, n=40, label=""):
    print(f"\n=== {label} ===")
    if off < 0 or off >= len(raw):
        print("  out of range")
        return
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    got = 0
    for ins in md.disasm(raw[off:off + 4 * n], off):
        print(f"  0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}")
        got += 1
        if ins.mnemonic == "ret" and got > 4:
            break
    if not got:
        print("  (no decode)")


def main():
    with open(SO, "rb") as f:
        elf = ELFFile(f)
        print("=== symbol tables present ===")
        for s in elf.iter_sections():
            if s.header["sh_type"] in ("SHT_SYMTAB", "SHT_DYNSYM"):
                print(f"  {s.name}  entries={s.num_symbols()}")
        symtab = elf.get_section_by_name(".symtab")
        if symtab:
            print("\n=== .symtab curl entries ===")
            hits = 0
            for s in symtab.iter_symbols():
                if "curl" in s.name.lower():
                    print(f"  {s.name:40} val=0x{s['st_value']:x} size=0x{s['st_size']:x}")
                    hits += 1
            if not hits:
                print("  (none)")
        else:
            print("  no .symtab (stripped)")

        # rodata strings mentioning curl
        rod = elf.get_section_by_name(".rodata")
        data = rod.data()
        base = rod["sh_addr"]
        print("\n=== rodata strings containing 'curl' ===")
        n = 0
        for m in re.finditer(rb"[\x20-\x7e]{4,120}", data):
            s = m.group().decode("ascii", "replace")
            if "curl" in s.lower():
                print(f"  0x{base + m.start():x}  {s[:110]}")
                n += 1
                if n >= 40:
                    print("  ...")
                    break
        if not n:
            print("  (none)")

    with open(SO, "rb") as f:
        raw = f.read()

    # .text: addr 0x28293c0, offset 0x28253c0  ->  vaddr = offset + 0x4000
    delta = 0x28293c0 - 0x28253c0
    disasm(raw, M17, label=f"raw file offset 0x{M17:x}")
    disasm(raw, M17 - delta, label=f"vaddr 0x{M17:x} -> file offset 0x{M17 - delta:x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
