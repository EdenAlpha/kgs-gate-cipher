"""Static recon: locate curl_easy_setopt before booting anything."""
import json, os, sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")
AN = os.path.join(HERE, "apk_lab", "analysis")
M17 = 0x6886498

def main():
    with open(SO, "rb") as f:
        elf = ELFFile(f)
        print("=== ELF sections that may hold text ===")
        for s in elf.iter_sections():
            if s.name in (".text", ".plt", ".plt.got", ".rodata"):
                print(f"  {s.name:12} addr=0x{s['sh_addr']:x} off=0x{s['sh_offset']:x} size=0x{s['sh_size']:x}")

        print("\n=== .dynsym entries mentioning curl ===")
        dyn = elf.get_section_by_name(".dynsym")
        n = 0
        for s in dyn.iter_symbols():
            if "curl" in s.name.lower():
                print(f"  {s.name:40} value=0x{s['st_value']:x} size=0x{s['st_size']:x}")
                n += 1
        if n == 0:
            print("  (none — curl is statically linked, as M17 said)")

        print("\n=== program headers (vaddr vs offset) ===")
        for i, seg in enumerate(elf.iter_segments()):
            if seg["p_type"] == "PT_LOAD":
                print(f"  LOAD off=0x{seg['p_offset']:x} vaddr=0x{seg['p_vaddr']:x} "
                      f"filesz=0x{seg['p_filesz']:x} flags={seg['p_flags']}")

    # disassemble at M17's address
    with open(SO, "rb") as f:
        raw = f.read()
    for cand, tag in ((M17, "raw file offset"), (M17, "as given")):
        blob = raw[cand:cand + 64]
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        print(f"\n=== capstone @ 0x{cand:x} ({tag}) ===")
        got = False
        for ins in md.disasm(blob, cand):
            print(f"  0x{ins.address:x}: {ins.mnemonic:8} {ins.op_str}")
            got = True
            if ins.mnemonic == "ret":
                break
        if not got:
            print("  (no disassembly)")
        break

    print("\n=== plt_map.json keys / curl entries ===")
    pm = json.load(open(os.path.join(AN, "plt_map.json")))
    print(f"  type={type(pm).__name__} len={len(pm)}")
    if isinstance(pm, dict):
        items = list(pm.items())
        for k, v in items[:5]:
            print(f"  sample {k!r} -> {str(v)[:100]!r}")
        hits = [(k, v) for k, v in items if "curl" in str(k).lower() or "curl" in str(v).lower()]
        print(f"  curl hits: {len(hits)}")
        for k, v in hits[:20]:
            print(f"    {k} -> {str(v)[:140]}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
