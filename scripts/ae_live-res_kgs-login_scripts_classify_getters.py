#!/usr/bin/env python3
"""Classify the Def_ config-accessor functions by what they return.

The two offsets previously labelled as the int and string getters are both
string getters -- both bodies contain the libc++ std::string construction
(`cmp xN, #0x17` for the 23-byte SSO limit, `lsl w9, w19, #1` + `strb w9`
for the `2*len|is_long` size byte, `orr x21, x19, #0xf` + `bl operator new`
for the long-string allocation, and `stp x19, x0` for the {size, ptr} pair).

So the int getter is somewhere else. This walks the code around those two and
classifies every function prologue it finds, so the correct offset for
`Def_Online_gRPC_insecure` can be identified by shape instead of by guesswork:

  string  : has the 0x17 SSO compare, returns a pointer to a built string
  int     : small body, returns a value in w0 straight out of the lookup
  other   : anything else, listed for inspection
"""
import os
import re
import subprocess
import sys

BIN = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\ds_check\unz\libUE4.so"
TOOL = r"C:\Users\Administrator\AppData\Local\Temp\2\opencode\peerlink_work\disasm_range.py"

# prologue: stp x29, x30, [sp, #imm]  (pre-index, imm scaled by 8)
PRO = re.compile(r"stp\s+x29, x30, \[sp, #0x[0-9a-f]+\]")


def disasm(start, end, count):
    r = subprocess.run([sys.executable, TOOL, hex(start), hex(end),
                        str(count)], capture_output=True, text=True, timeout=600)
    return r.stdout


def classify(va, body):
    sso = re.search(r"cmp\s+x\d+, #0x17", body) is not None
    sizebyte = re.search(r"lsl\s+w\d+, w\d+, #1", body) is not None
    newop = re.search(r"bl\s+#0x[0-9a-f]+", body) is not None
    tail = body.rstrip().split("\n")
    # the return: look for the last `ret` and what sets w0/x0 just before it
    rets = [i for i, l in enumerate(tail) if l.strip().endswith(": ret")]
    if sso and sizebyte:
        return "string", "%s/%s" % ("SSO@0x17" if sso else "-",
                                    "2*len sizebyte" if sizebyte else "-")
    if rets:
        i = rets[-1]
        prev = [l.strip() for l in tail[max(0, i - 6):i]]
        sets = [p for p in prev
                if re.search(r"(ldr|ldrb|ldrsw|ldrsb|ldur|ldp|add|orr|msub|mov|csel|csinc|ubfiz|sbfiz|and)\s+.*\bw0\b", p)]
        if sets and len(tail) < 40:
            return "int?", "-> w0: %s" % (sets[-1].split(": ", 1)[-1][:44])
        return "other", "%d insns, last: %s" % (
            len(tail), tail[rets[-1]].strip()[:44] if tail else "")
    return "other", "%d insns, no ret" % len(tail)


def main():
    lo, hi = 0x2f0a000, 0x2f11000
    body = disasm(lo, hi, 7000)
    lines = [l for l in body.split("\n") if "0x" in l]
    # find prologues
    starts = []
    for l in lines:
        m = re.match(r"\s*(0x[0-9a-f]+):", l)
        if not m:
            continue
        va = int(m.group(1), 16)
        if PRO.search(l):
            starts.append(va)
    print("prologues found: %d in %#x..%#x" % (len(starts), lo, hi))
    print()
    by_va = {int(re.match(r"\s*(0x[0-9a-f]+):", l).group(1), 16): l
             for l in lines if re.match(r"\s*0x[0-9a-f]+:", l)}
    order = sorted(by_va)
    for i, va in enumerate(starts):
        nxt = starts[i + 1] if i + 1 < len(starts) else va + 0x300
        seg = [by_va[v] for v in order if va <= v < nxt]
        kind, why = classify(va, "\n".join(seg))
        flag = ""
        if va in (0x2f0e18c, 0x2f0eaf0):
            flag = "   <-- previously labelled a getter"
        if kind == "int?":
            flag += "   <<< candidate int accessor"
        print("  %#010x  %-6s  %-52s  (%d insns)%s"
              % (va, kind, why, len(seg), flag))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
