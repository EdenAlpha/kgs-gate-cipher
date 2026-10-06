#!/usr/bin/env python3
"""Wire-level debug: what actually crosses the two processes' sockets.

Logs every sendto/recvfrom on both peers' transports + the lobby.
"""
import multiprocessing as mp
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from peerlink import FriendMatchSession, LobbyServer            # noqa: E402
from peerlink import transport as T                             # noqa: E402

TICKS = 12


def peer_process(role, lobby_port, code_q, result_q):
    tag = f"[{role}]"
    logf = open(f"/tmp/wire_{role}.log", "w", buffering=1)

    # instrument the transport at the raw socket level
    orig_send = T.Transport.send

    def send_dbg(self, dest, data):
        logf.write(f"SEND -> {dest} len={len(data)} "
                   f"head={data[:12].hex()}\n")
        return orig_send(self, dest, data)

    T.Transport.send = send_dbg

    orig_recv = T.Transport.recv

    def recv_dbg(self, timeout=0.0):
        out = orig_recv(self, timeout)
        for (src, ptype, room, peer, tick, payload) in out:
            logf.write(f"RECV <- {src} ptype={ptype} room={room} "
                      f"tick={tick} len={len(payload)}\n")
        return out

    T.Transport.recv = recv_dbg

    sim = FakeSim()
    sess = FriendMatchSession(sim, lobby_addr=("127.0.0.1", lobby_port),
                              name=role)
    try:
        if role == "host":
            code = sess.create(timeout=10.0)
            code_q.put(code)
            code_q.put(code)
            sess.wait_for_guest(timeout=30.0)
            logf.write("ATTACHED, remote="
                       f"{sess.peer.remote} room={sess.room}\n")
        else:
            code = code_q.get(timeout=60.0)
            sess.join(code, timeout=10.0)
            logf.write(f"ATTACHED, remote={sess.peer.remote} "
                       f"room={sess.room}\n")
        frame = 0
        while sess.tick < TICKS:
            sess.frame([frame & 0xFF] * 56)
            frame += 1
        result_q.put({"role": role, "ticks": sess.tick})
        sess.close()
    except Exception as e:
        import traceback
        logf.write(f"ERROR {e}\n{traceback.format_exc()}\n")
        result_q.put({"role": role, "error": str(e)})
    logf.close()


class FakeSim:
    def __init__(self):
        self.n = 0

    def tick(self, a, b):
        self.n += 1

    def state_checksum(self):
        return self.n


def main():
    for f in ("/tmp/wire_host.log", "/tmp/wire_guest.log"):
        if os.path.exists(f):
            os.unlink(f)
    lobby = LobbyServer(bind=("127.0.0.1", 42633)).start()
    time.sleep(0.2)
    code_q, result_q = mp.Queue(), mp.Queue()
    ps = [mp.Process(target=peer_process, args=(r, 42633, code_q, result_q))
          for r in ("host", "guest")]
    ps[0].start()
    code = code_q.get(timeout=60)
    ps[1].start()
    t0 = time.time()
    res = {}
    while len(res) < 2 and time.time() - t0 < 25:
        try:
            r = result_q.get(timeout=2)
            res[r["role"]] = r
        except Exception:
            continue
    for p in ps:
        p.terminate()
    lobby.stop()
    print("results:", res)
    print("\n===== HOST wire (first 25) =====")
    print("".join(open("/tmp/wire_host.log").readlines()[:25]))
    print("===== GUEST wire (first 25) =====")
    print("".join(open("/tmp/wire_guest.log").readlines()[:25]))


if __name__ == "__main__":
    main()
