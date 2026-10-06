"""Find code that computes exactly ADDR (ADRP+ADD / ADR / ADRP+MOVZ...).

  python xref_exact.py 0xADDR            .text only
  python xref_exact.py 0xADDR 0xSTART 0xEND

Prints (site, kind) for every instruction pair that materialises ADDR.
"""
import struct
import sys

SO = r"apk_lab\libUE4.so"

TEXT_OFF, TEXT_ADDR, TEXT_SIZE = 0x28253C0, 0x28293C0, 0x630BE48


def decode_adrp(pc, w):
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32):
        imm -= 1 << 33
    return pc & ~0xFFF | 0 if False else ((pc & ~0xFFF) + imm) & ((1 << 64) - 1)


def decode_add_imm(w):
    sh = (w >> 22) & 1
    imm12 = (w >> 10) & 0xFFF
    return imm12 << (12 if sh else 0)


def main():
    target = int(sys.argv[1], 16)
    lo = int(sys.argv[2], 16) if len(sys.argv) > 2 else TEXT_ADDR
    hi = int(sys.argv[3], 16) if len(sys.argv) > 3 else TEXT_ADDR + TEXT_SIZE
    data = open(SO, "rb").read()

    adrp_page = target & ~0xFFF
    off = target & 0xFFF

    start = max(TEXT_OFF, TEXT_OFF + (lo - TEXT_ADDR))
    end = min(len(data), TEXT_OFF + (hi - TEXT_ADDR))
    hits = []
    for p in range(start & ~3, end, 4):
        w = struct.unpack_from("<I", data, p)[0]
        if (w & 0x9F000000) != 0x90000000:
            continue          # not ADRP
        pc = TEXT_ADDR + (p - TEXT_OFF)
        if decode_adrp(pc, w) != adrp_page:
            continue
        rd = w & 0x1F
        # scan the next 6 instructions for ADD rd', Xn(rd), #off
        for k in range(1, 7):
            q = p + k * 4
            if q >= end:
                break
            w2 = struct.unpack_from("<I", data, q)[0]
            # ADD Xd, Xn, #imm12  (64-bit, op=0, S=0)
            if (w2 & 0xFF800000) == 0x91000000:
                rn = (w2 >> 5) & 0x1F
                if rn != rd:
                    continue
                if decode_add_imm(w2) == off:
                    rd2 = w2 & 0x1F
                    if rd2 != rd:      # result must go somewhere useful
                        pass
                    hits.append((pc, f"ADRP+ADD x{rd2}, x{rd}, #0x{off:x}"))
            # MOVZ Xd, #off (sometimes used alone for small rodata)
            if (w2 & 0xFF800000) == 0xD2800000 and rn_unused(w2) == off:
                hits.append((pc, "ADRP+MOVZ"))
            if len(hits) > 4000:
                break
        if len(hits) > 4000:
            break
    print(f"exact hits: {len(hits)}")
    for h in hits[:200]:
        print(f"  {h[0]:#x}  {h[1]}")


def rn_unused(w):
    return ((w >> 5) & 0xFFFF) << ((w >> 21) & 3)


if __name__ == "__main__":
    main()
