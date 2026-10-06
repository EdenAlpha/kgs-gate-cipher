"""online_client — M21 driver: the headless game gets a real wire.

Run:
    python -m peerlink.online_client

Steps:
  1. boot the headless game core (the proven Unicorn harness)
  2. install the netsplice (real sockets behind the game's imports)
  3. SPLICE PROOF: DNS + connect + HTTP round trip to the game's NTL
     host, driven THROUGH the game's own PLT surface — not from Python
     directly. If bytes come back, the game's network stack is live.
  4. run the game's own online-config registrars and dump the live
     config (server hosts, RSA slot, paths) — everything the online
     session needs, in memory, in our process.
"""
from __future__ import annotations

import os
import socket as _pysock
import struct
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS = os.path.join(os.path.dirname(_HERE), "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

from uc_loader2 import EFootballCoreV2, RET_TRAP          # noqa: E402
from unicorn.arm64_const import (                           # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_SP, UC_ARM64_REG_PC,
    UC_ARM64_REG_LR,
)

from .netsplice import OnlineCoreMixin                      # noqa: E402


class OnlineCore(OnlineCoreMixin, EFootballCoreV2):
    """The headless game with a real network line."""


def call_stub(core, addr, x0=0, x1=0, x2=0, x3=0, x4=0, x5=0,
              timeout_s=30.0):
    """Call one Python-serviced import stub directly."""
    uc = core.uc
    uc.reg_write(UC_ARM64_REG_X0, x0)
    uc.reg_write(UC_ARM64_REG_X1, x1)
    uc.reg_write(UC_ARM64_REG_X2, x2)
    uc.reg_write(UC_ARM64_REG_X3, x3)
    uc.reg_write(UC_ARM64_REG_X4, x4)
    uc.reg_write(UC_ARM64_REG_X5, x5)
    uc.reg_write(UC_ARM64_REG_SP, core.sp0)
    uc.reg_write(UC_ARM64_REG_LR, RET_TRAP)
    uc.emu_start(addr, RET_TRAP, timeout=int(timeout_s * 1_000_000))
    return uc.reg_read(UC_ARM64_REG_X0)


NTL_HOST = "ntl.service.konami.net"

REGISTRARS = [
    0x7d66580,  # game-host/stun/https/pes22 config
    0x7d66e50,  # after RSA accessor region
    0x7d62d74,
    0x7d413f4,
    0x7d41a10,
    0x7d6bef0,
    0x7d6dc90,
    0x7d691f4,
    0x7d6a330,
    0x7d7de54,
    0x7d54c40,
]


def splice_proof(core):
    """DNS + TCP + HTTP round trip through the game's own imports."""
    addr_of = {}
    for a, n in core.stub_of.items():
        addr_of.setdefault(n.rstrip("_h") if n.endswith("_h") else n, a)

    def stub(name):
        a = addr_of.get(name)
        if not a:
            raise RuntimeError(f"no stub for {name}")
        return a

    print(f"\n=== SPLICE PROOF: HTTP round trip to {NTL_HOST} "
          f"via the game's own PLT ===")

    # 1. getaddrinfo through the game's import
    node = core.alloc(len(NTL_HOST) + 1, NTL_HOST.encode() + b"\0",
                      name="node")
    serv = core.alloc(3, b"80\0", name="serv")
    resp = core.alloc(8, b"\0" * 8, name="res")
    r = call_stub(core, stub("getaddrinfo"), node, serv, 0, resp)
    if r != 0:
        print(f"getaddrinfo failed: {r}")
        return False
    head = core.safe_read_u64(resp)
    if not head:
        print("getaddrinfo returned no list")
        return False
    sa_ptr = core.safe_read_u64(head + 32)          # ai_addr
    raw = core.safe_read(sa_ptr, 16)
    fam, port_be = struct.unpack_from("<HH", raw)
    port = _pysock.ntohs(port_be)                    # port is network order
    ip = _pysock.inet_ntop(_pysock.AF_INET, raw[4:8])
    print(f"  DNS via game's getaddrinfo: {NTL_HOST} -> {ip}:{port} "
          f"(family {fam})")

    # 2. socket through the game's import
    fd = call_stub(core, stub("socket"), 2, 1, 0)
    if fd < 10:
        print(f"socket failed: {fd}")
        return False
    print(f"  socket via game's socket(): fd={fd}")

    # 3. connect through the game's import
    sa = core.alloc(16, struct.pack("<HH", 2, _pysock.htons(port))
                    + _pysock.inet_aton(ip) + b"\0" * 8, name="sockaddr")
    r = call_stub(core, stub("connect"), fd, sa, 16)
    if r != 0:
        print(f"connect failed: {r}")
        return False
    print(f"  connect via game's connect(): TCP established to {ip}:{port}")

    # 4. send the GateInfo GET through the game's sendto
    req = (f"GET /ntl/api/GateInfo.php HTTP/1.0\r\n"
           f"Host: {NTL_HOST}\r\n"
           f"User-Agent: PES/1.0 (peerlink splice proof)\r\n"
           f"Accept: */*\r\n\r\n").encode()
    buf = core.alloc(len(req) + 1, req, name="req")
    n = call_stub(core, stub("sendto"), fd, buf, len(req), 0, 0, 0)
    if n != len(req):
        print(f"sendto sent {n}/{len(req)}")
        return False
    print(f"  sendto via game's sendto(): {n} bytes of HTTP on the wire")

    # 5. receive through the game's recvfrom
    rbuf = core.alloc(4096, b"\0" * 4096, name="rbuf")
    total = b""
    for _ in range(4):
        n = call_stub(core, stub("recvfrom"), fd, rbuf, 2048, 0, 0, 0,
                      timeout_s=12.0)
        if n <= 0:
            break
        total += bytes(core.safe_read(rbuf, n))
        if b"\r\n\r\n" in total and len(total) > 200:
            break
    if not total:
        print("  recvfrom: no data came back")
        return False
    head = total.split(b"\r\n")[0].decode("utf-8", "replace")
    print(f"  recvfrom via game's recvfrom(): {len(total)} bytes back")
    print(f"  *** SERVER ANSWERED: {head} ***")
    body_note = total.split(b"\r\n\r\n", 1)
    if len(body_note) > 1 and body_note[1]:
        print(f"  body head: {body_note[1][:120]!r}")

    call_stub(core, stub("close"), fd)
    print("  (connection closed via game's close())")
    return True


def registrar_dump(core):
    """Run the game's own online-config registrars; dump live config."""
    print("\n=== GAME ONLINE CONFIG (game's own registrars, in our memory) ===")
    ok = 0
    for fn in REGISTRARS:
        try:
            core.call(fn)
            ok += 1
        except Exception as e:
            print(f"  registrar {fn:#x}: {type(e).__name__} {str(e)[:80]}")
    print(f"  {ok}/{len(REGISTRARS)} registrars ran")

    B = core.base
    data = core.safe_read(B + 0xa4b0000, 0x4000)
    found = []
    off = 0
    while off < len(data) - 24:
        b = data[off]
        if 0 < b <= 44 and b % 2 == 0:
            ln = b >> 1
            s = data[off + 1:off + 1 + ln]
            try:
                t = s.decode("utf8")
                if all(31 < ord(c) < 127 for c in t):
                    found.append((off, t))
            except Exception:
                pass
        off += 8
    print(f"  config strings in 0xa4b0000 region:")
    for off, t in found:
        print(f"    cfg+{off:#06x}: {t!r}")
    return found


def main():
    t0 = time.time()
    print("[online_client] booting headless game core (libUE4.so)...")
    core = OnlineCore(verbose=False)
    print(f"[online_client] core up in {time.time()-t0:.1f}s "
          f"(base {core.base:#x})")
    core.install_netsplice()
    print(f"[online_client] netsplice installed: "
          f"{len(core._net_wired)} imports wired to real sockets")

    ok = splice_proof(core)
    cfg = registrar_dump(core)

    print(f"\n[online_client] RESULT: "
          f"wire={'LIVE' if ok else 'DEAD'}, "
          f"config={'PRESENT' if cfg else 'EMPTY'}")
    print("[online_client] next: drive the game's own GateInfo sender "
          "(0x7d0c06c) through this wire, then the online session "
          "state machine (0x7dc7164) — guest login, room create.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
