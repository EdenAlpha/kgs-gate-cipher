"""Pin down the game's HTTP request function:
  - all BL targets in .text (function-entry candidates)
  - enclosing function of the CmdGetServerEnv.php builders
  - callers of that function
  - callers of curl_easy_init (0x6858c98)
  - every `mov w1, #CURLOPT_URL` site with context
"""
import os
import sys

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

TEXT_VADDR, TEXT_OFF, TEXT_SIZE = 0x28293C0, 0x28253C0, 0x630BE48

CURLOPT_SETOPT = 0x6886498
CURL_EASY_INIT = 0x6858c98
ENV_A = 0x767eba4            # CmdGetServerEnv.php copy site A
ENV_B = 0x767f7dc            # copy site B
MOV_W1_URL = 0x5284E241      # mov w1, #0x2712   CURLOPT_URL
MOV_W1_BODY = 0x5284E3E1     # mov w1, #0x271f   CURLOPT_POSTFIELDS


def bl_scan(raw):
    blob = raw[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    words = np.frombuffer(blob, dtype="<u4")
    is_bl = (words & 0xFC000000) == 0x94000000
    idx = np.nonzero(is_bl)[0]
    imm = (words[idx] & 0x03FFFFFF).astype(np.int64)
    imm = np.where(imm & 0x2000000, imm - 0x4000000, imm)
    callers = (TEXT_VADDR + idx.astype(np.int64) * 4)
    targets = callers + imm * 4
    return np.asarray(callers), np.asarray(targets)


def context(raw, addr, before=6, after=4):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    start = addr - before * 4
    off = start - TEXT_VADDR + TEXT_OFF
    out = []
    for ins in md.disasm(raw[off:off + (before + after) * 4], start):
        mark = " <== HERE" if ins.address == addr else ""
        out.append(f"      0x{ins.address:x}: {ins.mnemonic:8} "
                   f"{ins.op_str}{mark}")
    return out


def main():
    with open(SO, "rb") as f:
        raw = f.read()

    callers, targets = bl_scan(raw)
    uniq_targets = np.unique(targets)

    print(f"BL sites: {len(callers):,}   unique targets: {len(uniq_targets):,}")

    def containing(addr):
        """Nearest function-entry candidate <= addr."""
        i = np.searchsorted(uniq_targets, addr, side="right") - 1
        return int(uniq_targets[i]) if i >= 0 else None

    def callers_of(fn, limit=30):
        hit = callers[targets == fn]
        return sorted(set(int(x) for x in hit))[:limit]

    for label, site in (("CmdGetServerEnv copy A", ENV_A),
                        ("CmdGetServerEnv copy B", ENV_B)):
        fn = containing(site)
        print(f"\n=== {label} @ {site:#x} -> enclosing fn {fn:#x} ===")
        print(f"    len so far: {site - fn:#x} bytes")
        cs = callers_of(fn)
        print(f"    callers of {fn:#x}: {len(cs)} -> {[hex(x) for x in cs]}")
        # callers of the caller
        for c in cs[:6]:
            g = callers_of(c)
            print(f"       caller {c:#x} is itself called by "
                  f"{[hex(x) for x in g]}")

    print("\n=== callers of curl_easy_init 0x%x ===" % CURL_EASY_INIT)
    cs = callers_of(CURL_EASY_INIT, 40)
    print(f"    {len(cs)} -> {[hex(x) for x in cs]}")
    for c in cs[:8]:
        fn = containing(c)
        print(f"      site {c:#x} in fn {fn:#x}   callers="
              f"{[hex(x) for x in callers_of(fn)]}")

    # every mov w1, #CURLOPT_URL
    blob = raw[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    words = np.frombuffer(blob, dtype="<u4")
    for name, w in (("CURLOPT_URL (10002)", MOV_W1_URL),
                    ("CURLOPT_POSTFIELDS (10015)", MOV_W1_BODY)):
        idx = np.nonzero(words == w)[0]
        print(f"\n=== {name}: {len(idx)} sites ===")
        for i in idx[:25]:
            addr = int(TEXT_VADDR + i * 4)
            print(f"  {addr:#x}")
            for line in context(raw, addr, before=4, after=3):
                print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
