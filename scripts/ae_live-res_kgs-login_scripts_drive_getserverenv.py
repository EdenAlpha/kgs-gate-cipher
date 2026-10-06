#!/usr/bin/env python3
"""Run the game's own CMD_GET_SERVER_ENV builder end to end.

  0x767eaf0(obj)  does the whole thing with the binary's own code:

      * builds the object: vtable 0x97d448,
            +0x138  short string "CMD_GET_SERVER_ENV"   -> msgid
            +0x170  short string "CmdGetServerEnv.php"  -> script name
      * malloc(0x2000) into +0x120 / +0x128, size 0 at +0x118
      * reads lang / region / platform / client_version
      * 0x767edbc serialises the MessagePack request body into that buffer

Nothing here is hand-written: we supply one zeroed object and read back the
bytes the game itself produced.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from peerlink.online_client import OnlineCore, REGISTRARS  # noqa: E402

CTOR = 0x767EAF0           # construct: msgid, filename, vtable, buffer
BIND = 0x767EC60           # copy lang/region/platform/client_version -> map
SERIAL = 0x767EDBC         # write the MessagePack request body


def u64(core, a):
    return struct.unpack("<Q", bytes(core.uc.mem_read(a, 8)))[0]


def decode_msgpack(raw: bytes, i: int = 0):
    """Tiny reader - enough to show a request body."""
    b = raw[i]
    if b <= 0x7f:
        return b, i + 1
    if b >= 0xe0:
        return b - 0x100, i + 1
    if 0xa0 <= b <= 0xbf:
        n = b & 0x1F
        return raw[i + 1:i + 1 + n].decode("utf-8", "replace"), i + 1 + n
    if b == 0xc0:
        return None, i + 1
    if b == 0xc2:
        return False, i + 1
    if b == 0xc3:
        return True, i + 1
    if b in (0xcc, 0xd0):
        return raw[i + 1], i + 2
    if b in (0xcd, 0xd1):
        return struct.unpack(">H", raw[i + 1:i + 3])[0], i + 3
    if b in (0xce, 0xd2):
        return struct.unpack(">I", raw[i + 1:i + 5])[0], i + 5
    if b in (0xca,):
        return struct.unpack(">f", raw[i + 1:i + 5])[0], i + 5
    if b == 0xcb:
        return struct.unpack(">d", raw[i + 1:i + 9])[0], i + 9
    if b == 0xde:
        n = struct.unpack(">H", raw[i + 1:i + 3])[0]
        return ("MAP16", n), i + 3
    if 0x80 <= b <= 0x8f:
        return ("MAP", b & 0x0F), i + 1
    if b == 0xdc:
        n = struct.unpack(">H", raw[i + 1:i + 3])[0]
        return ("ARR16", n), i + 3
    return (f"?{b:#04x}",), i + 1


def main() -> int:
    print("[env] booting ...", flush=True)
    core = OnlineCore(verbose=False)
    core.install_netsplice()
    for fn in REGISTRARS:
        try:
            core.call(fn)
        except Exception:
            pass
    core.call(0x7CDA280, timeout_s=60)
    print("[env] booted", flush=True)

    obj = core.alloc(0x4000, b"\0" * 0x4000, name="server_env_obj")
    print(f"[env] obj={obj:#x}", flush=True)

    r = None
    for fn, label in ((CTOR, "ctor"), (BIND, "bind"), (SERIAL, "serial")):
        try:
            r = core.call(fn, w0=obj, timeout_s=180,
                          max_insns=400_000_000)
        except Exception as e:
            print(f"[env] {label} -> EXC {e}", flush=True)
            return 1
        size = u64(core, obj + 0x118)
        print(f"[env] {label:7s} -> err={r['error']} pc={r['pc']:#x} "
              f"x0={r['x0']:#x}  size={size}", flush=True)
        if r["error"]:
            return 1

    size = u64(core, obj + 0x118)
    ptr = u64(core, obj + 0x120)
    cap = u64(core, obj + 0x128)
    print(f"[env] buffer size={size} ptr={ptr:#x} cap={cap}", flush=True)
    if r["error"] or size == 0 or size > 0x40000 or ptr == 0:
        print("[env] no body produced", flush=True)
        return 1

    raw = bytes(core.uc.mem_read(ptr, size))
    print(f"[env] ---- raw ({size} bytes) ----", flush=True)
    print(raw[:1200], flush=True)

    # msgid / rqid sit at +0x138 / +0x150 on the object
    mid_raw = bytes(core.uc.mem_read(obj + 0x138, 24))
    if mid_raw[0] & 1:
        pass
    else:
        n = mid_raw[0] >> 1
        print(f"[env] obj.msgid = {mid_raw[1:1 + n]!r}", flush=True)
    print(f"[env] obj.rqid  = {struct.unpack('<I', bytes(core.uc.mem_read(obj + 0x150, 4)))[0]}", flush=True)

    print(f"[env] ---- decoded ----", flush=True)
    try:
        v, i = decode_msgpack(raw, 0)
        kind = v if isinstance(v, tuple) else None
        if kind and kind[0] == "MAP16":
            print(f"  map with {kind[1]} entries", flush=True)
            for _ in range(kind[1]):
                k, i = decode_msgpack(raw, i)
                val, i = decode_msgpack(raw, i)
                print(f"    {k!r} = {val!r}", flush=True)
        else:
            print(f"  first = {v!r}", flush=True)
    except Exception as e:
        print(f"  decode failed: {e}", flush=True)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "getserverenv_body.bin")
    open(out, "wb").write(raw)
    print(f"[env] wrote {out}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
