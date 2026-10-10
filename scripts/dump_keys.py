#!/usr/bin/env python3
"""dump_keys.py -- C-string reader + per-function string-load printer.

Rebuilt 2026-10-10 (original destroyed by temp cleanup).  Interface kept:

    from dump_keys import cstr, strings_in_func
    strings_in_func(path, pc)   # prints header + every adrp+add string load
                                # from `pc` forward (bounded window)
"""
import struct
import sys

sys.path.insert(0, r"C:\Users\Administrator\Documents\Default Project\work")
from xref2 import Elf, adrpf, addimm        # noqa: E402


def cstr(e, va, limit=400):
    """NUL-terminated string at virtual address `va` (best effort)."""
    raw = e.va_read(va, limit)
    if raw is None:
        return None
    end = raw.find(b"\0")
    if end < 0:
        end = limit
    return raw[:end].decode("latin1")


def is_print(s):
    if not s or len(s) < 2:
        return False
    return all(32 <= ord(c) < 127 for c in s)


def func_start_of(e, pc, back=0x1000):
    """Scan back from pc for a `ret`; return ret+4 (or pc)."""
    _, _, _, tv, to, ts = e.sec(".text")
    text = e.read(to, ts)
    i = pc - tv
    lo = max(0, i - back)
    for j in range(i, lo, -4):
        w = struct.unpack_from("<I", text, j)[0]
        if w & 0xFFFFFC1F == 0xD65F0000:            # ret xN
            return tv + j + 4
    return pc


def string_loads(e, start, end):
    """[(pc, va, text)] for adrp+add string loads in [start, end)."""
    _, _, _, tv, to, ts = e.sec(".text")
    text = e.read(to, ts)
    i0 = max(0, start - tv)
    i1 = min(len(text), end - tv)
    out = []
    for i in range(i0, i1 - 8, 4):
        w = struct.unpack_from("<I", text, i)[0]
        rd, delta = adrpf(w)
        if rd is None:
            continue
        pc = tv + i
        page = (pc & ~0xFFF) + delta
        for k in range(4, 24, 4):
            if i + k >= i1:
                break
            w2 = struct.unpack_from("<I", text, i + k)[0]
            add = addimm(w2)
            if add is None:
                continue
            rd2, rn2, imm = add
            if rd2 is not None and rn2 == rd:
                target = page + imm
                s = cstr(e, target)
                if s is not None and is_print(s):
                    out.append((pc, target, s))
                break
    return out


def strings_in_func(path, pc, window=0x600, maxrows=40):
    e = Elf(path)
    fstart = func_start_of(e, pc)
    rows = string_loads(e, pc, pc + window)
    print("--- libUE4.so pc=%#x  func_start=%#x (len>=%#x)"
          % (pc, fstart, pc - fstart))
    for rpc, va, s in rows[:maxrows]:
        show = s if len(s) <= 90 else s[:87] + "..."
        print("    0x%08x  '%s'" % (rpc, show))


if __name__ == "__main__":
    strings_in_func(sys.argv[1], int(sys.argv[2], 16))
