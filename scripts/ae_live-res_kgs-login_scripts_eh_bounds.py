#!/usr/bin/env python3
"""Manual .eh_frame parser -> every real function's [start, end).

pyelftools returns a bare Section for .eh_frame here, so we parse the CIE/FDE
records ourselves. Then:
  * name the enclosing function of each mystery address
  * ascend the BL call graph through REAL function boundaries
"""
from __future__ import annotations

import os
import struct
import sys
from collections import defaultdict

SO = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                  "apk_lab", "libUE4.so")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "funcs_eh.txt")

TEXT_VADDR = 0x28293C0
TEXT_OFF = 0x28253C0
TEXT_SIZE = 0x630BE48

KEYS = {
    0x7DC7164: "bootstrap_SM",
    0x7A39EA0: "cmdenv_chain_top",
    0x767EAF0: "cmd_getserverenv_builder",
    0x767CEEC: "cmdenv_dispatcher_branch",
    0x7D038C8: "http_post_routine",
    0x7D015B0: "http_post_parent",
    0x7D04570: "curl_writefunction",
    0x7D0C06C: "gateinfo_sender",
    0x6886498: "curl_easy_setopt",
}

# DW_EH_PE_*
FMT_PTR, FMT_UDATA2, FMT_UDATA4, FMT_UDATA8 = 0x0, 0x2, 0x3, 0x4
FMT_ULEB, FMT_SLEB = 0x1, 0x9
FMT_SDATA2, FMT_SDATA4, FMT_SDATA8 = 0xA, 0xB, 0xC
APP_PCREL, APP_TEXTREL, APP_DATAREL, APP_FUNCREL, APP_ABS = \
    0x10, 0x20, 0x30, 0x40, 0x00


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def read_uleb(b, o):
    r = 0
    s = 0
    while True:
        c = b[o]
        o += 1
        r |= (c & 0x7F) << s
        if not (c & 0x80):
            break
        s += 7
    return r, o


def read_sleb(b, o):
    r = 0
    s = 0
    while True:
        c = b[o]
        o += 1
        r |= (c & 0x7F) << s
        s += 7
        if not (c & 0x80):
            if c & 0x40:
                r -= 1 << s
            break
    return r, o


def parse_eh(data, sec_addr):
    cies = {}
    fdes = []
    off = 0
    n = len(data)
    while off + 8 <= n:
        ln = u32(data, off)
        if ln == 0:
            break
        if ln == 0xFFFFFFFF:
            ln = u64(data, off + 4)
            body = off + 12
        else:
            body = off + 4
        rec_end = body + ln
        if rec_end > n:
            break
        cid = u32(data, body)
        if cid == 0:
            # ---------------- CIE
            p = body + 4
            ver = data[p]
            p += 1
            z = data.index(0, p)
            aug = data[p:z].decode("latin1")
            p = z + 1
            if ver >= 4:
                p += 2
            code_align, p = read_uleb(data, p)
            data_align, p = read_sleb(data, p)
            if ver < 4:
                p += 1
            else:
                _, p = read_uleb(data, p)
            ptr_enc = FMT_PTR          # default absptr
            if aug[:1] == "z":
                adl, p = read_uleb(data, p)
                aug_end = p + adl
                rest = aug[1:]
                if "R" in rest:
                    ptr_enc = data[p]
                    p += 1
                    if "P" in rest:
                        p += 1
                        # personality encoding then a pointer of same format
                        p += (8 if (ptr_enc & 0x7) in (FMT_PTR, FMT_UDATA8,
                                                       FMT_SDATA8) else 4)
                    if "L" in rest:
                        p += 1
                    p = aug_end
            cies[off] = (ptr_enc, ver)
        else:
            # ---------------- FDE
            cie_off = body - cid
            ptr_enc, _ver = cies.get(cie_off, (0x1B, 1))
            p = body + 4
            fmt = ptr_enc & 0x0F
            app = ptr_enc & 0x70
            # ---- pc_begin
            if fmt in (FMT_SDATA4, FMT_UDATA4):
                raw = struct.unpack_from("<i", data, p)[0] \
                    if fmt == FMT_SDATA4 else u32(data, p)
                p += 4
            elif fmt in (FMT_SDATA8, FMT_UDATA8, FMT_PTR):
                raw = struct.unpack_from("<q", data, p)[0] \
                    if fmt == FMT_SDATA8 else u64(data, p)
                p += 8
            elif fmt == FMT_UDATA2:
                raw = struct.unpack_from("<H", data, p)[0]
                p += 2
            elif fmt == FMT_SDATA2:
                raw = struct.unpack_from("<h", data, p)[0]
                p += 2
            elif fmt == FMT_ULEB:
                raw, p = read_uleb(data, p)
            elif fmt == FMT_SLEB:
                raw, p = read_sleb(data, p)
            else:
                raw = None
            if raw is None:
                off = rec_end
                continue
            if app == APP_PCREL:
                base = sec_addr + (p - 4 if fmt in (FMT_SDATA4, FMT_UDATA4)
                                   else p - 8)
            elif app == APP_TEXTREL:
                base = TEXT_VADDR
            else:
                base = 0
            start = (base + raw) & 0xFFFFFFFFFFFFFFFF
            # ---- pc_range
            if fmt in (FMT_SDATA4, FMT_UDATA4):
                rng = u32(data, p)
                p += 4
            elif fmt in (FMT_SDATA8, FMT_UDATA8, FMT_PTR):
                rng = u64(data, p)
            elif fmt == FMT_UDATA2:
                rng = struct.unpack_from("<H", data, p)[0]
            else:
                rng = 0
            if rng > 0:
                fdes.append((start, start + rng))
        off = rec_end
    return fdes


def main():
    from elftools.elf.elffile import ELFFile
    with open(SO, "rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(".eh_frame")
        data = sec.data()
        sec_addr = sec["sh_addr"]
    print(f".eh_frame {len(data):,} bytes @ {sec_addr:#x}", flush=True)
    fdes = parse_eh(data, sec_addr)
    print(f"  parsed {len(fdes):,} FDEs")
    intext = [r for r in fdes if TEXT_VADDR <= r[0] < TEXT_VADDR + TEXT_SIZE]
    print(f"  inside .text: {len(intext):,}")
    fdes = sorted(intext)
    if not fdes:
        print("  NOTHING parsed - encoding assumption wrong")
        return 1

    with open(OUT, "w", encoding="utf-8") as g:
        for a, b in fdes:
            g.write(f"{a:#012x} {b:#012x} {b - a:#x}\n")
    print(f"  wrote {OUT}")

    def enclosing(addr):
        lo, hi = 0, len(fdes) - 1
        best = None
        while lo <= hi:
            m = (lo + hi) // 2
            if fdes[m][0] <= addr:
                best = m
                lo = m + 1
            else:
                hi = m - 1
        if best is None:
            return None
        a, b = fdes[best]
        return (a, b) if a <= addr < b else None

    print("\n" + "=" * 74)
    print("ENCLOSING FUNCTIONS (real, from .eh_frame)")
    print("=" * 74)
    enc = {}
    for k, label in KEYS.items():
        e = enclosing(k)
        if not e:
            print(f"  {label:28s} {k:#x}: NOT inside any FDE")
            continue
        a, b = e
        enc[k] = a
        print(f"  {label:28s} {k:#x} -> fn {a:#x}..{b:#x} "
              f"(size {b - a:#x}, +{k - a:#x} into fn)")

    print("\nloading .text for BL scan ...", flush=True)
    with open(SO, "rb") as f:
        f.seek(TEXT_OFF)
        text = f.read(TEXT_SIZE)
    bl = defaultdict(list)
    for idx in range(len(text) // 4):
        insn = struct.unpack_from("<I", text, idx * 4)[0]
        if (insn & 0xFC000000) == 0x94000000:
            imm = insn & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            pc = TEXT_VADDR + idx * 4
            bl[pc + (imm << 2)].append(pc)
    print(f"  {len(bl):,} BL targets", flush=True)

    for k, label in KEYS.items():
        if k not in enc:
            continue
        fn = enc[k]
        print("\n" + "-" * 74)
        print(f"ASCENT: {label}  (fn {fn:#x})")
        print("-" * 74)
        cur = fn
        for hop in range(7):
            sites = sorted(bl.get(cur, []))
            print(f"  hop{hop}: {cur:#x} <- {len(sites)} caller(s)")
            if not sites:
                print("          ** TOP: entry point or indirect dispatch **")
                break
            nxt = None
            for s in sites:
                e = enclosing(s)
                if e:
                    print(f"          site {s:#x} in fn {e[0]:#x} "
                          f"(size {e[1]-e[0]:#x})")
                    if nxt is None:
                        nxt = e[0]
            if nxt is None or nxt == cur:
                break
            cur = nxt
    return 0


if __name__ == "__main__":
    sys.exit(main())
