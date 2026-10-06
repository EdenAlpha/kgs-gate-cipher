#!/usr/bin/env python3
"""Fast BL/BLR cross-reference finder for AArch64 ELF.
Usage:
  bl_xrefs.py --addr 0x7c076dc [0x...]      list callers of these VAs
  bl_xrefs.py --file                        read target VAs from stdin (one hex per line)
Prints: <caller_va>  <target_va>  [prologue_va if resolvable]
"""
import struct, os, sys
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")


def parse_elf(data):
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    ph = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, o)
        p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<QQQQQQ", data, o + 8)
        if p_type == 1:
            ph.append((p_offset, p_vaddr, p_filesz, p_flags))
    return ph


def va2off(ph, va):
    for po, pv, pf, _ in ph:
        if pv <= va < pv + pf:
            return po + (va - pv)
    return None


def off2va(ph, off):
    for po, pv, pf, _ in ph:
        if po <= off < po + pf:
            return pv + (off - po)
    return None


def se(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def main():
    args = sys.argv[1:]
    targets = []
    if args and args[0] == "--file":
        for line in sys.stdin:
            line = line.strip()
            if line:
                targets.append(int(line, 16))
    else:
        i = 0
        while i < len(args):
            if args[i] == "--addr":
                i += 1
                while i < len(args) and args[i].startswith("0x"):
                    targets.append(int(args[i], 16))
                    i += 1
            else:
                i += 1
    if not targets:
        print(__doc__)
        return

    data = open(LIB, "rb").read()
    ph = parse_elf(data)

    # prologue helper (walk back on demand)
    def find_prologue(va, limit=0x8000):
        o = va2off(ph, va)
        if o is None:
            return None
        start = max(0, o - limit)
        off = o
        candidate = None
        while off >= start:
            w = struct.unpack_from("<I", data, off)[0]
            if ((w & 0xFFC07FFF) == 0xA9807BFD) and (((w >> 15) & 0x7F) >= 0x40):
                return off2va(ph, off)
            if candidate is None and (w & 0xFFC003FF) == 0xD10003FF and ((w >> 10) & 0xFFF) >= 0x10:
                candidate = off2va(ph, off)
            if w == 0xD65F03C0:  # ret: crossed a function boundary
                break
            off -= 4
        return candidate

    tset = set(targets)
    results = {t: [] for t in targets}
    kind = {}

    for po, pv, pf, fl in ph:
        if not (fl & 1):
            continue
        chunk = data[po:po + pf]
        n = len(chunk) // 4
        arr = np.frombuffer(chunk[:n * 4], dtype="<u4")
        for name, opc in (("BL", 0x94000000), ("B", 0x14000000)):
            sel = np.nonzero((arr & np.uint32(0xFC000000)) == np.uint32(opc))[0]
            imms = (arr[sel] & np.uint32(0x03FFFFFF)).astype(np.int64)
            imms = np.where(imms >= 0x2000000, imms - 0x4000000, imms)
            pcs = pv + sel.astype(np.uint64) * 4
            tgts = pcs + (imms << 2).astype(np.uint64)
            for tv in tset:
                m = np.nonzero(tgts == np.uint64(tv))[0]
                for idx in m:
                    results[tv].append(int(pcs[idx]))
                    kind[(tv, int(pcs[idx]))] = name

    # function pointers: literal 8-byte values in any PT_LOAD
    for po, pv, pf, fl in ph:
        chunk = data[po:po + pf]
        if len(chunk) < 8:
            continue
        u64 = np.frombuffer(chunk[:len(chunk) // 8 * 8], dtype="<u8")
        for tv in tset:
            m = np.nonzero(u64 == np.uint64(tv))[0]
            for idx in m:
                va = pv + int(idx) * 8
                results[tv].append(va)
                kind[(tv, va)] = "ptr"

    for po, pv, pf, fl in ph:
        if not (fl & 1):
            continue
        chunk = data[po:po + pf]
        n = len(chunk) // 4
        arr = np.frombuffer(chunk[:n * 4], dtype="<u4")
        # BL: 100101 imm26  -> (insn & 0xFC000000) == 0x94000000
        bl_idx = np.nonzero((arr & np.uint32(0xFC000000)) == np.uint32(0x94000000))[0]
        pcs = pv + bl_idx.astype(np.uint64) * 4
        imms = (arr[bl_idx] & np.uint32(0x03FFFFFF)).astype(np.int64)
        imms = np.where(imms >= 0x2000000, imms - 0x4000000, imms)
        tgts = pcs + (imms << 2).astype(np.uint64)
        for k, tv in enumerate(tset):
            m = np.nonzero(tgts == np.uint64(tv))[0]
            for idx in m:
                results[tv].append(int(pcs[idx]))

    for t in targets:
        print("\n== target 0x%x  refs=%d" % (t, len(results[t])))
        for c in sorted(set(results[t])):
            k = kind.get((t, c), "?")
            if k == "ptr":
                print("   ptr@0x%x  (function pointer table)" % c)
                continue
            p = find_prologue(c)
            print("   %s@0x%x  func@%s" % (k, c, ("0x%x" % p) if p else "?"))


if __name__ == "__main__":
    main()
