"""Two questions, one script.

Q1: what does 0x2f1ec94 actually return?  Its result becomes w24, the other
    half of the XOR that forms the sign key.  If it is the clock, the key
    changes every request and the server could never verify it -- which
    contradicts the live probe.  Read the function; do not assume.

Q2: does the key material travel with the request?  The 40 sign bytes carry
    no seed, but another header or cookie could.  List header NAMES, value
    lengths and shape only -- never the values (no credential literals here).
"""
import os
import re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

BASE = r"C:\Users\Administrator\AppData\Local\Temp\2"
SO = os.path.join(BASE, "game", "libUE4.so")
MITM = os.path.join(BASE, "rec2", "flows.mitm")
OUT = os.path.join(BASE, "w24_check.txt")

out = []


def say(s=""):
    out.append(str(s))


# --------------------------------------------------------------- Q1: code ---
d = open(SO, "rb").read()

# ELF VA -> file offset, per PT_LOAD (segment 2: va 0x28293c0 / off 0x28253c0,
# delta 0x4000).  0x2f1ec94 sits in that segment, so off = va - 0x4000.
VA = 0x2F1EC94
OFF = VA - 0x4000

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

say("=" * 78)
say("Q1  WHAT IS 0x2f1ec94 ?   (its result becomes w24 in the sign key)")
say("=" * 78)
say("ELF VA 0x%x   file 0x%x   (segment delta 0x4000)" % (VA, OFF))
say("")
for insn in md.disasm(d[OFF:OFF + 0x70], VA):
    note = ""
    if insn.mnemonic == "bl":
        note = "   <- PLT import" if insn.op_str.startswith("#0x8b35") or \
            insn.op_str.startswith("#0x8b38") or \
            insn.op_str.startswith("#0x8b3a") else ""
    if "0x3b9aca00" in insn.op_str:
        note += "   <- 0x3b9aca00 = 1,000,000,000"
    say("  0x%08x  %-8s %s%s" % (insn.address, insn.mnemonic,
                                 insn.op_str, note))
    if insn.mnemonic == "ret":
        break
say("")

# --------------------------------------------------- Q2: request headers ----
say("=" * 78)
say("Q2  DOES ANYTHING ELSE RIDE ALONG WITH THE REQUEST?")
say("=" * 78)
say("(names, lengths and shape only -- values deliberately omitted)")
say("")

if not os.path.exists(MITM):
    say("missing %s" % MITM)
else:
    text = open(MITM, "r", encoding="utf-8", errors="replace").read()
    # split on request lines
    blocks = re.split(r"\n(?=#{3,}\s*REQ|(?=###\s*REQ)|\n###\s*REQ)", text)
    shown = 0
    for m in re.finditer(r"(GET|POST)\s+(\S*gate\S*)[^\n]*\n((?:[^\n]+\n)+)",
                         text, re.I):
        if shown >= 3:
            break
        method, path, hdrs = m.group(1), m.group(2), m.group(3)
        say("REQUEST %d: %s %s" % (shown + 1, method, path))
        for line in hdrs.splitlines():
            if ":" not in line:
                continue
            name, _, val = line.partition(":")
            name = name.strip()
            val = val.strip()
            if not name:
                continue
            shape = []
            if "=" in val:
                shape.append("%d pairs" % val.count("="))
            if re.fullmatch(r"[A-Za-z0-9+/=]+", val or "x"):
                shape.append("b64-ish")
            if val and all(32 <= ord(c) < 127 for c in val):
                shape.append("ascii")
            # value never printed -- only its length and shape
            say("   %-26s len=%-5d %s" % (name, len(val), ",".join(shape)))
        say("")
        shown += 1
    if shown == 0:
        say("no gate request headers matched the pattern -- check parse")

open(OUT, "w", encoding="utf-8").write("\n".join(out))
print("wrote %s (%d lines)" % (OUT, len(out)))
