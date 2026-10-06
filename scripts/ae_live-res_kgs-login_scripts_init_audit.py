#!/usr/bin/env python3
"""Two audits for the harness's broken slots.

1. init_array: run every ctor in isolation, list the ones that fault and how.
   (11,825 of 11,829 ran at boot -- the 4 failures may own the broken tables.)
2. LIEF: for exact file-VAs of broken slots, print the relocation entry
   (type/symbol/addend) or NONE if no entry exists (=> genuinely unrelocated
   in the file => value must come from runtime code, i.e. the failed ctors).
"""
from __future__ import annotations

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

INIT_ARRAY = 0x98BD898
N_CTORS = 11829

# file-VAs of slots observed broken at runtime (base 0x10000000000)
SLOTS = [
    0xA4B01A0,   # epcfg table: 0x31 (should be host string)
    0xA4B01B8,   # epcfg table: garbage
    0xA4B01D0,   # epcfg table: 0x31
    0x97D6668 + 7 * 8,    # CmdLogin vtable slot 7 (if this layout matches)
    0x97D6668 + 13 * 8,
    0x97D6668 + 17 * 8,
]


def audit_init(core) -> None:
    from unicorn import UcError
    base = core.base
    fails = []
    for i in range(N_CTORS):
        try:
            raw = int.from_bytes(
                bytes(core.uc.mem_read(base + INIT_ARRAY + i * 8, 8)),
                "little")
        except Exception as e:
            fails.append((i, "read-err %s" % e))
            continue
        if raw == 0:
            continue
        if raw < base or raw >= base + 0x200000000:
            fails.append((i, "bogus-ptr %#x" % raw))
            continue
        fva = raw - base   # core.call adds base itself; pass file VA
        try:
            ctx = core.uc.context_save()
        except Exception:
            ctx = None
        try:
            r = core.call(fva, timeout_s=15, max_insns=20_000_000)
            if r["error"]:
                fails.append((i, "%#x %s" % (raw, r["error"])))
                if ctx is not None:
                    try:
                        core.uc.context_restore(ctx)
                    except Exception:
                        pass
        except Exception as e:
            fails.append((i, "%#x %s" % (raw, str(e)[:60])))
            if ctx is not None:
                try:
                    core.uc.context_restore(ctx)
                except Exception:
                    pass
        if (i + 1) % 2000 == 0:
            print("[init] %d/%d done, %d fails so far"
                  % (i + 1, N_CTORS, len(fails)), flush=True)
    print("[init] %d failures:" % len(fails), flush=True)
    for i, msg in fails:
        print("   ctor[%d] %s" % (i, msg), flush=True)


def audit_relocs() -> None:
    import lief
    print("[reloc] parsing (takes ~1 min)...", flush=True)
    b = lief.parse(
        r"C:\Users\Administrator\Documents\Default Project"
        r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
        r"\libUE4.so")
    table = {}
    for r in b.dynamic_relocations:
        table.setdefault(r.address, []).append(r)
    for va in SLOTS:
        rs = table.get(va, [])
        if not rs:
            print("  %#x : NO reloc entry" % va, flush=True)
            continue
        for r in rs:
            sym = r.symbol.name[:50] if r.has_symbol else "-"
            print("  %#x : type=%s sym=%s addend=%s"
                  % (va, r.type, sym,
                     hex(r.addend) if hasattr(r, "addend") else "?"),
                  flush=True)


def main() -> int:
    if "--reloc-only" in sys.argv:
        audit_relocs()
        return 0
    from peerlink.online_client import OnlineCore
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    audit_init(core)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
