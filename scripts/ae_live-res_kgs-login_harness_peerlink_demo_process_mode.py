#!/usr/bin/env python3
"""Discriminator: BallSim in SEPARATE PROCESSES over the same net stack.

If this deadlocks the same way as the engine demo, the bug is in the
process/net layer; if it passes, the bug is engine-specific.
"""
import multiprocessing as mp
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from peerlink import FriendMatchSession, LobbyServer            # noqa: E402
from peerlink.lockstep import INPUT_INTS                        # noqa: E402
from peerlink.demo_match import BallSim, recorded_inputs        # noqa: E402

TICKS = 300


def peer_process(role, lobby_port, code_q, result_q):
    tag = f"[{role}]"
    sim = BallSim(seed=1)
    sess = FriendMatchSession(sim, lobby_addr=("127.0.0.1", lobby_port),
                              name=role)
    try:
        if role == "host":
            code = sess.create(timeout=10.0)
            code_q.put(code)
            code_q.put(code)
            sess.wait_for_guest(timeout=60.0)
            print(f"{tag} guest attached", flush=True)
        else:
            code = code_q.get(timeout=60.0)
            sess.join(code, timeout=10.0)
            print(f"{tag} joined", flush=True)
        frame = 0
        while sess.tick < TICKS:
            sess.frame(recorded_inputs(0 if role == "host" else 1, frame))
            frame += 1
            if frame % 20 == 0:
                print(f"{tag} frame {frame} tick {sess.tick} "
                      f"stats={sess.peer.stats}", flush=True)
        for _ in range(6):
            sess.peer.pump(0.02)
        result_q.put({"role": role, "ticks": sess.tick, "frames": frame,
                      "final_cs": f"{sim.state_checksum():016x}",
                      "stats": sess.peer.stats})
        sess.close()
    except Exception as e:
        import traceback
        result_q.put({"role": role, "error": str(e),
                      "tb": traceback.format_exc()})


def main():
    print("=== BallSim in separate processes ===")
    lobby = LobbyServer(bind=("127.0.0.1", 42631)).start()
    time.sleep(0.2)
    code_q, result_q = mp.Queue(), mp.Queue()
    ps = [mp.Process(target=peer_process, args=(r, 42631, code_q, result_q))
          for r in ("host", "guest")]
    ps[0].start()
    code = code_q.get(timeout=60)
    print(f"room code = {code}")
    ps[1].start()
    res = {}
    t0 = time.time()
    while len(res) < 2 and time.time() - t0 < 90:
        try:
            r = result_q.get(timeout=5)
        except Exception:
            continue
        res[r["role"]] = r
        print(f"[{r['role']}] done: ticks={r.get('ticks')} "
              f"cs={r.get('final_cs')}" if "error" not in r
              else f"[{r['role']}] ERROR {r['error']}", flush=True)
    for p in ps:
        p.join(timeout=10)
    lobby.stop()
    if len(res) == 2 and all("error" not in r for r in res.values()):
        a, b = res["host"], res["guest"]
        ok = (a["ticks"] == b["ticks"] == TICKS
              and a["final_cs"] == b["final_cs"])
        print(("\n*** PROCESS-MODE: PASS ***" if ok
               else "\n*** PROCESS-MODE: FAIL ***")
              + f"  cs_host={a['final_cs']} cs_guest={b['final_cs']}")
        return 0 if ok else 1
    print("\n*** PROCESS-MODE: ERROR ***")
    return 1


if __name__ == "__main__":
    sys.exit(main())
