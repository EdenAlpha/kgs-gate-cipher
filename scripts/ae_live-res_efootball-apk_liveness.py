#!/usr/bin/env python3
"""Prove whether a string in libUE4.so is actually REFERENCED by live code.

A string existing in a 160MB .so proves nothing: linkers keep orphan rodata
from unused translation units. This indexes every ADRP in the executable
segments ONCE, then for each candidate string reports:
    code_xrefs : how many adrp+add / adrp+ldr pairs materialise its address
    ptr_hits   : how many absolute 8-byte/4-byte pointers to its address exist
                 (FString / const char* tables, vtables, relocation slots)
    verdict    : UNREFERENCED (provably dead) / REFERENCED / TABLE_ONLY

Usage:
    liveness.py 10560060 11810754 ...      # file offsets from ue4_strings.txt
    liveness.py --off 0xa41f0c ...         # explicit hex file offsets
"""
import struct
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "native", "lib", "arm64-v8a", "libUE4.so")

MAX_LOOKAHEAD = 24   # instructions scanned after an ADRP
MAX_PTR_HITS = 8


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


def off2va(ph, off):
    for po, pv, pf, _ in ph:
        if po <= off < po + pf:
            return pv + (off - po)
    return None


def build_adrp_index(data, ph):
    """Return (pages_sorted, meta_sorted) where meta = (seg_base, word_idx, rd)."""
    chunks_pages = []
    chunks_meta = []
    for po, pv, pf, fl in ph:
        if not (fl & 1):           # executable only
            continue
        w = np.frombuffer(data, dtype="<u4", count=pf // 4, offset=po)
        # ADRP: bits 31-24 == 1x010000  -> (w>>24) & 0x9F == 0x90
        m = (np.right_shift(w, 24) & np.uint32(0x9F)) == np.uint32(0x90)
        idx = np.nonzero(m)[0]
        if idx.size == 0:
            continue
        immhi = np.right_shift(w[idx], 5) & np.uint32(0x7FFFF)
        immlo = np.right_shift(w[idx], 29) & np.uint32(0x3)
        simm = (immhi << 2) | immlo
        neg = (simm & np.uint32(0x100000)) != 0
        simm = simm.astype(np.int64) - np.where(neg, 0x200000, 0)
        pc = pv + idx.astype(np.int64) * 4
        pages = (pc & ~0xFFF) + (simm << 12)
        pages = (pages & ~0xFFF).astype(np.int64)
        rd = (w[idx] & np.uint32(0x1F)).astype(np.int64)
        chunks_pages.append(pages)
        meta = np.stack([np.full(idx.size, pv, dtype=np.int64),
                         idx.astype(np.int64), rd], axis=1)
        chunks_meta.append(meta)
    pages = np.concatenate(chunks_pages)
    meta = np.concatenate(chunks_pages and chunks_meta)
    order = np.argsort(pages, kind="stable")
    return pages[order], meta[order], data, ph


def code_xrefs(pages, meta, data, ph, target):
    """Find adrp+add / adrp+ldr(unsigned) sequences landing exactly on target."""
    tp = target & ~0xFFF
    lo = target & 0xFFF
    lo_page = np.searchsorted(pages, tp)
    hi_page = np.searchsorted(pages, tp, side="right")
    hits = []
    for k in range(lo_page, hi_page):
        pv, i, rd = (int(v) for v in meta[k])
        # word index relative to segment start
        po = None
        for po_, pv_, pf_, _ in ph:
            if pv_ == pv:
                po = po_
                break
        if po is None:
            continue
        w = np.frombuffer(data, dtype="<u4", count=pf_ // 4, offset=po)
        i = int(i)
        for j in range(1, MAX_LOOKAHEAD + 1):
            if i + j >= w.size:
                break
            nw = int(w[i + j])
            # break early on the next adrp (a new addressing sequence)
            if ((nw >> 24) & 0x9F) == 0x90:
                break
            # ADD (immediate) 64-bit, shift==0
            if (nw & 0xFF800000) == 0x91000000 and ((nw >> 22) & 3) == 0:
                if ((nw >> 5) & 0x1F) == rd and ((nw >> 10) & 0xFFF) == lo:
                    hits.append(pv + (i + j) * 4)
                continue
            # LDR/STR unsigned offset (byte/half/word/dword) off the same reg
            if (nw & 0x3B000000) == 0x39000000 and ((nw >> 24) & 3) == 1:
                if ((nw >> 5) & 0x1F) == rd:
                    size = (nw >> 30) & 3
                    if (((nw >> 10) & 0xFFF) << size) == lo:
                        hits.append(pv + (i + j) * 4)
                continue
            # LDR (literal) can't target rodata; ADR after ADRP is unusual but valid
            if (nw & 0x9F000000) == 0x10000000:
                imm = ((nw >> 5) << 2) | ((nw >> 29) & 3)
                if imm & (1 << 20):
                    imm -= 1 << 21
                if (pv + (i + j) * 4 + imm) == target:
                    hits.append(pv + (i + j) * 4)
                continue
            # Only give up when the address is provably dead: another ADRP
            # starts a fresh addressing sequence, and a call/branch means the
            # base register may have been clobbered. Anything else (mov, str,
            # alu) is transparent - a hard `break` here is what previously
            # risked mislabelling live code as legacy.
            if ((nw >> 24) & 0x9F) == 0x90:
                break
            if (nw & 0xFC000000) in (0x94000000, 0x14000000, 0xD6000000,
                                     0xD6100000):
                break
            continue
    return sorted(set(hits))


def bad_ptr_regions(data):
    """Sections where an 8/4-byte match is an artefact, not a real pointer.

    .eh_frame / .eh_frame_hdr / .gcc_except_table are unwind encodings; their
    FDE/CIE pointer blobs routinely reproduce arbitrary 4-8 byte patterns.
    Counting those as 'referenced' would mark dead strings live.
    """
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    o = e_shoff + e_shstrndx * e_shentsize
    str_off = struct.unpack_from("<Q", data, o + 24)[0]
    str_sz = struct.unpack_from("<Q", data, o + 32)[0]
    strtab = data[str_off:str_off + str_sz]
    bad = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        name = strtab[struct.unpack_from("<H", data, b)[0]:].split(b"\0", 1)[0]
        name = name.decode("latin-1")
        if name.startswith((".eh_frame", ".gcc_except_table", ".comment")):
            off = struct.unpack_from("<Q", data, b + 24)[0]
            sz = struct.unpack_from("<Q", data, b + 32)[0]
            bad.append((off, off + sz))
    return bad


def ptr_hits(data, target, bad, limit=MAX_PTR_HITS):
    out = []
    for fmt, width in (("<Q", 8), ("<I", 4)):
        pat = struct.pack(fmt, target)
        i = data.find(pat)
        while i != -1 and len(out) < limit:
            if not any(lo <= i < hi for lo, hi in bad):
                out.append((i, width))
            i = data.find(pat, i + 1)
    return out


def section_of(data, off):
    """Return (name, lo, hi) of the section containing file offset `off`."""
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    o = e_shoff + e_shstrndx * e_shentsize
    str_off = struct.unpack_from("<Q", data, o + 24)[0]
    str_sz = struct.unpack_from("<Q", data, o + 32)[0]
    strtab = data[str_off:str_off + str_sz]
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        name = strtab[struct.unpack_from("<H", data, b)[0]:].split(b"\0", 1)[0]
        name = name.decode("latin-1")
        lo = struct.unpack_from("<Q", data, b + 24)[0]
        sz = struct.unpack_from("<Q", data, b + 32)[0]
        if sz and lo <= off < lo + sz:
            return name, lo, lo + sz
    return "?", 0, 0


# Sections whose contents are addressed by the dynamic loader / relocation
# machinery rather than by adrp+add in .text. A string here is live even with
# zero code xrefs (JNI exports, relocated pointers).
DYNAMIC_SECTIONS = {".dynstr", ".dynsym", ".strtab", ".gnu.hash",
                    ".rela.dyn", ".rela.plt", ".dynamic", ".got", ".got.plt"}


def main():
    args = sys.argv[1:]
    hexmode = False
    if args and args[0] == "--off":
        hexmode = True
        args = args[1:]
    if not args:
        print(__doc__)
        return

    data = open(LIB, "rb").read()
    ph = parse_elf(data)
    bad = bad_ptr_regions(data)
    pages, meta, _, _ = build_adrp_index(data, ph)
    print("[index] %d ADRP sites across executable segments\n" % pages.size)
    print("[ptrs] excluding unwind sections: %s\n"
          % ", ".join("0x%x-0x%x" % r for r in bad))

    for a in args:
        off = int(a, 16) if hexmode else int(a)
        va = off2va(ph, off)
        if va is None:
            print("%-10s off=0x%x -> NOT IN ANY PT_LOAD" % (a, off))
            continue
        cx = code_xrefs(pages, meta, data, ph, va)
        pt = ptr_hits(data, va, bad)
        sec, _, _ = section_of(data, off)
        if cx:
            verdict = "REFERENCED"
        elif pt:
            verdict = "TABLE_ONLY"
        elif sec in DYNAMIC_SECTIONS:
            verdict = "DYNAMIC_EXPORT (live via loader, not adrp)"
        else:
            verdict = "UNREFERENCED"
        # grab the literal for context
        lit = data[off:off + 90].split(b"\0", 1)[0].decode("latin-1", "replace")
        print("%-10s off=0x%-9x va=0x%-9x sec=%-9s code=%-3d ptrs=%-3d -> %s\n    %r"
              % (a, off, va, sec, len(cx), len(pt), verdict, lit[:88]))
        for h in cx[:6]:
            print("        xref 0x%x" % h)
        for o, wd in pt[:4]:
            print("        ptr  fileoff 0x%x (%d-byte)" % (o, wd))


if __name__ == "__main__":
    main()
