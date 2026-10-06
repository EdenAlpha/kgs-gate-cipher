#!/usr/bin/env python3
"""PeerLink FULL-STACK demo: the real engine under the network lockstep.

Everything real, over real UDP, in two isolated processes:

  process 0 (main)   the LobbyServer (rendezvous + relay)
  process 1 (host)   EngineSim A  — libUE4.so under Unicorn, original code
  process 2 (guest)  EngineSim B  — an INDEPENDENT libUE4.so instance

Flow: room create -> numeric Match ID -> join -> hole punch -> lockstep.
Each display frame feeds both players' recorded controller streams
(the scripted .trep stand-in); the lockstep advances up to 3 physics
ticks per frame; every CHECKSUM_EVERY ticks the peers exchange FNV-1a
state hashes of the ORIGINAL engine state.

PASS: both peers reach TICKS ticks, every exchanged checksum matches,
final engine checksums are bit-identical.

Run:  python peerlink/demo_engine_net.py [--ticks 108] [--lobby-port 42621]
"""
import argparse
import json
import multiprocessing as mp
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from peerlink import FriendMatchSession, LobbyServer            # noqa: E402
from peerlink.lockstep import INPUT_INTS, CHECKSUM_EVERY         # noqa: E402

RESULTS = "/tmp/enginenet"


def scripted_inputs(frame):
    """Deterministic recorded-controller stand-in (same as the twin-run)."""
    s = (frame * 2654435761) & 0xFFFFFFFF
    out = []
    for _ in range(INPUT_INTS):
        s ^= (s << 13) & 0xFFFFFFFF
        s ^= s >> 17
        s ^= (s << 5) & 0xFFFFFFFF
        out.append(s & 0xFF)
    out[2] = 1 if (frame % 13) < 3 else 0          # periodic shoot presses
    return out


def peer_process(role, lobby_port, code_q, result_q, ticks, seed):
    """One friend-match peer running the REAL engine."""
    from peerlink.engine_sim import EngineSim
    tag = f"[{role}]"
    print(f"{tag} booting engine (libUE4.so under Unicorn)...", flush=True)
    t_boot = time.time()
    try:
        sim = EngineSim(seed=seed, verbose=False)
        print(f"{tag} engine booted in {time.time() - t_boot:.1f}s "
              f"(kicks armed)", flush=True)
        sess = FriendMatchSession(sim, lobby_addr=("127.0.0.1", lobby_port),
                                   name=role)
        if role == "host":
            code = sess.create(timeout=10.0)
            code_q.put(code)                    # one for the monitor
            code_q.put(code)                    # one for the guest peer
            print(f"{tag} waiting for guest...", flush=True)
            sess.wait_for_guest(timeout=120.0)
            print(f"{tag} guest attached", flush=True)
        else:
            code = code_q.get(timeout=60.0)
            print(f"{tag} joining room {code}...", flush=True)
            sess.join(code, timeout=10.0)
            print(f"{tag} joined, host attached", flush=True)

        frame = 0
        t0 = time.time()
        while sess.tick < ticks and not sess.diverged:
            sess.frame(scripted_inputs(frame if role == "host"
                                        else frame + 1000))
            frame += 1
            if frame % 10 == 0:
                print(f"{tag} frame {frame} tick {sess.tick}", flush=True)
        dur = time.time() - t0

        # drain trailing checksum exchanges
        for _ in range(20):
            if sess.peer:
                sess.peer.pump(0.02)
        p, v = sim.pos_vel()
        result_q.put({
            "role": role, "ticks": sess.tick, "frames": frame,
            "duration_s": round(dur, 2),
            "final_cs": f"{sim.state_checksum():016x}",
            "pos": list(p), "vel": list(v),
            "kicks": sim.kicks_installed,
            "checksum_matches": sess.peer.stats.get("checksum_matches", 0),
            "checksum_exchanges": sess.peer.stats.get("checksum_exchanges",
                                                      0),
            "retransmits": sess.peer.stats.get("retransmits", 0),
            "diverged": bool(sess.diverged),
        })
        sess.close()
    except Exception as e:
        import traceback
        result_q.put({"role": role, "error": f"{type(e).__name__}: {e}",
                      "tb": traceback.format_exc()})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ticks", type=int, default=108)
    ap.add_argument("--lobby-port", type=int, default=42621)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    print("=== PeerLink FULL-STACK: real engine over UDP lockstep ===")
    lobby = LobbyServer(bind=("127.0.0.1", args.lobby_port)).start()
    time.sleep(0.2)

    code_q = mp.Queue()
    result_q = mp.Queue()
    host = mp.Process(target=peer_process,
                     args=("host", args.lobby_port, code_q, result_q,
                           args.ticks, args.seed))
    guest = mp.Process(target=peer_process,
                        args=("guest", args.lobby_port, code_q, result_q,
                              args.ticks, args.seed))
    host.start()
    t0 = time.time()
    code = code_q.get(timeout=120)               # host created the room
    print(f"[host] room created: code = {code}")
    guest.start()

    results = {}
    while len(results) < 2 and time.time() - t0 < 600:
        try:
            r = result_q.get(timeout=5)
        except Exception:
            if not host.is_alive() and not guest.is_alive():
                break
            continue
        results[r["role"]] = r
        if "error" in r:
            print(f"[{r['role']}] ERROR: {r['error']}")
            print(r.get("tb", "")[-1500:])
        else:
            print(f"[{r['role']}] ticks={r['ticks']} frames={r['frames']} "
                  f"dur={r['duration_s']}s kicks={r['kicks']} "
                  f"cs_matches={r['checksum_matches']}/"
                  f"{r['checksum_exchanges']} final={r['final_cs']}")
    host.join(timeout=30)
    guest.join(timeout=30)
    lobby.stop()

    with open(f"{RESULTS}_{args.ticks}.json", "w") as f:
        json.dump({"ticks": args.ticks, "results": results}, f, indent=1)

    if len(results) < 2 or any("error" in r for r in results.values()):
        print("\n*** FULL-STACK DEMO: ERROR (see above) ***")
        return 1
    h, g = results["host"], results["guest"]
    ok_ticks = h["ticks"] == g["ticks"] == args.ticks
    ok_cs = h["checksum_matches"] == g["checksum_matches"] \
        and h["checksum_matches"] >= (args.ticks // CHECKSUM_EVERY) - 1
    ok_final = h["final_cs"] == g["final_cs"]
    ok_pos = h["pos"] == g["pos"]
    ok_div = not h["diverged"] and not g["diverged"]
    print(f"\nCHECKS: {args.ticks}/{args.ticks} ticks: "
          f"{'PASS' if ok_ticks else 'FAIL'}"
          f" | checksum stream: {'PASS' if ok_cs else 'FAIL'}"
          f" | final cs identical: {'PASS' if ok_final else 'FAIL'}"
          f" | pos bit-exact: {'PASS' if ok_pos else 'FAIL'}"
          f" | divergence: {'NONE' if ok_div else 'DETECTED!'}")
    print(f"[host]  pos={tuple(round(x, 4) for x in h['pos'])}")
    print(f"[guest] pos={tuple(round(x, 4) for x in g['pos'])}")
    if all((ok_ticks, ok_cs, ok_final, ok_pos, ok_div)):
        print(f"\n*** FULL-STACK PASS: the ORIGINAL eFootball engine, run "
              f"twice over a real UDP friend-match, agreed on all "
              f"{args.ticks} ticks — bit-exact ***")
        return 0
    print("\n*** FAILED ***")
    return 1


if __name__ == "__main__":
    sys.exit(main())
