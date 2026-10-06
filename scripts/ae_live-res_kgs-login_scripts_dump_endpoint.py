#!/usr/bin/env python3
"""Read the game's own endpoint configuration out of a booted instance.

The static initialiser at 0x7d66580 fills a table in .bss, and
get_endpoint_config (0x7d6532c) copies five libc++ strings out of it.
TaskLogin then composes:

    scheme + "://" + host + port + path + "/" + "gate.php"

Nothing here fabricates anything -- we just look at what the binary wrote.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

STATIC_INIT = 0x7D66580      # fills the .bss endpoint table
GET_CFG = 0x7D6532C          # get_endpoint_config(dst)
ENDPOINT_SRC = 0xA4B0218     # the five-string struct get_cfg reads
TABLE = 0xA4B00C0            # raw .bss table written by the static init
TABLE_END = 0xA4B0300


def main():
    print("[ep] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    B = core.base

    # Static vaddrs (.bss) must be rebased; alloc() results are absolute.
    def S(a):
        return B + a

    def rd(a, n):
        return bytes(core.uc.mem_read(a, n))

    def cstr(a, n=80):
        return rd(a, n).split(b"\0")[0]

    def cxx(addr):
        """Decode a libc++ std::string."""
        b0 = rd(addr, 1)[0]
        if b0 & 1:                                     # long form
            size = struct.unpack("<Q", rd(addr + 8, 8))[0]
            ptr = struct.unpack("<Q", rd(addr + 0x10, 8))[0]
            if size > 0x10000 or ptr == 0:
                return f"<long size={size} ptr={ptr:#x}>"
            return bytes(core.uc.mem_read(ptr, size)).decode("utf-8", "replace")
        size = b0 >> 1                                 # short form
        return rd(addr + 1, size).decode("utf-8", "replace")

    raw = rd(S(TABLE), TABLE_END - TABLE)
    print(f"[ep] raw .bss table {S(TABLE):#x}..{S(TABLE_END):#x}:", flush=True)
    if raw.strip(b"\0"):
        print("    non-zero", flush=True)
    else:
        print("    EMPTY -> running static initialiser 0x7d66580", flush=True)
        try:
            core.call(STATIC_INIT, timeout_s=60)
            print("    static init returned", flush=True)
        except Exception as e:
            print(f"    static init failed: {e}", flush=True)

    print("\n[ep] --- strings at 0x18 stride from 0xa4b00e0 ---", flush=True)
    for a in range(0xA4B00E0, 0xA4B01E0, 0x18):
        try:
            print(f"    {a:#x}  {cxx(S(a))!r}", flush=True)
        except Exception as e:
            print(f"    {a:#x}  <err {e}>", flush=True)

    print("\n[ep] --- get_endpoint_config source struct 0xa4b0218 ---",
          flush=True)
    for off in (0x00, 0x18, 0x30, 0x48, 0x60, 0x78):
        a = ENDPOINT_SRC + off
        try:
            print(f"    +{off:#04x} {a:#x}  {cxx(S(a))!r}", flush=True)
        except Exception as e:
            print(f"    +{off:#04x} {a:#x}  <err {e}>", flush=True)

    # Also pull the config the game's own getter produces, exactly as
    # TaskLogin does: dst buffer on our own allocated heap block.
    print("\n[ep] --- calling get_endpoint_config(dst) ---", flush=True)
    dst = core.alloc(0x80, b"\0" * 0x80, name="ep_dst")
    try:
        r = core.call(GET_CFG, w0=dst, timeout_s=60)
        print(f"    -> x0={r['x0']:#x} err={r['error']}", flush=True)
        for off in (0x00, 0x18, 0x30, 0x48, 0x60, 0x78):
            a = dst + off
            try:
                print(f"    dst+{off:#04x}  {cxx(a)!r}", flush=True)
            except Exception as e:
                print(f"    dst+{off:#04x}  <err {e}>", flush=True)
        # Compose the URL the same way TaskLogin does.
        parts = []
        for off in (0x00, 0x18, 0x30, 0x48, 0x60):
            try:
                parts.append(cxx(dst + off))
            except Exception:
                parts.append("")
        if parts[3] == "" and len(parts) > 4:
            parts[3] = parts[4]
        url = parts[0] + "://" + parts[1] + parts[2] + parts[3] + "/gate.php"
        print(f"\n[ep] composed = {url!r}", flush=True)
    except Exception as e:
        print(f"    get_cfg failed: {e}", flush=True)

    print("\n[ep] non-ascii table dump:", flush=True)
    print("    " + raw.hex(), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
