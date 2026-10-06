#!/usr/bin/env python3
"""TWIN-RUN: the engine-level lockstep determinism proof.

Two INDEPENDENT processes each build their own EngineSim (own Unicorn
instance, own 160 MB libUE4.so mapping, own ball module built by the
game's own ctors) and run the SAME scripted input sequence. Per-tick
FNV-1a checksums are recorded; the harness runs this twice and compares.

If the two checksum STREAMS match tick-for-tick, the engine satisfies
exactly the property the lockstep needs:

    same binary + same initial state + same inputs => same state,
    proven per-tick, across independent instances.

Usage:
    python engine_twinrun.py --ticks 60 --out /tmp/twin_A.json
    python engine_twinrun.py --ticks 60 --out /tmp/twin_B.json
    python engine_twinrun.py --compare /tmp/twin_A.json /tmp/twin_B.json
"""
import argparse
import json
import struct
import sys
import time

sys.path.insert(0, "/home/z/my-project")
from peerlink.engine_sim import EngineSim, fnv1a      # noqa: E402
from peerlink.lockstep import INPUT_INTS              # noqa: E402


def scripted_inputs(frame):
    """Deterministic 'recorded match' — the .trep stand-in: analog swirl
    + periodic shoot presses, identical on every run."""
    s = (frame * 2654435761) & 0xFFFFFFFF
    out = []
    for _ in range(INPUT_INTS):
        s ^= (s << 13) & 0xFFFFFFFF
        s ^= s >> 17
        s ^= (s << 5) & 0xFFFFFFFF
        out.append(s & 0xFF)
    # press shoot every 13 frames for 3 frames (rising edges -> kicks)
    out[2] = 1 if (frame % 13) < 3 else 0
    return out


def run(ticks, out_path):
    events = []
    sim = EngineSim(seed=7, verbose=False,
                    on_event=lambda k, **kw: events.append(k))
    t0 = time.time()
    recs = []
    host_in = [0] * INPUT_INTS
    guest_in = [0] * INPUT_INTS
    for t in range(ticks):
        fi = (t * 3) // 3                      # 1 frame = 3 ticks
        host_in = scripted_inputs(fi)
        guest_in = scripted_inputs(fi + 1000)
        sim.tick(host_in, guest_in)
        p, v = sim.pos_vel()
        recs.append({"t": t,
                     "cs": f"{sim.state_checksum():016x}",
                     "pos": list(p), "vel": list(v)})
    dur = time.time() - t0
    doc = {"ticks": ticks, "seed": 7, "duration_s": round(dur, 2),
           "kicks_installed": sim.kicks_installed, "events": events,
           "final_cs": f"{sim.state_checksum():016x}", "trace": recs}
    with open(out_path, "w") as f:
        json.dump(doc, f)
    moved = recs[-1]["pos"] != recs[0]["pos"]
    print(f"[twinrun] ticks={ticks} dur={dur:.1f}s "
          f"kicks={sim.kicks_installed} moved={moved} "
          f"final_cs={doc['final_cs']}")
    print(f"[twinrun] trace -> {out_path}")
    first, last = recs[0], recs[-1]
    print(f"[twinrun] pos[0]={tuple(round(x, 4) for x in first['pos'])} "
          f"pos[-1]={tuple(round(x, 4) for x in last['pos'])}")


def compare(a_path, b_path):
    a = json.load(open(a_path))
    b = json.load(open(b_path))
    ok = True
    print(f"[compare] A: ticks={a['ticks']} final={a['final_cs']}")
    print(f"[compare] B: ticks={b['ticks']} final={b['final_cs']}")
    if a["ticks"] != b["ticks"]:
        print("[compare] FAIL: tick counts differ")
        return 1
    bad = 0
    for ra, rb in zip(a["trace"], b["trace"]):
        if ra["cs"] != rb["cs"] or ra["pos"] != rb["pos"]:
            bad += 1
            if bad <= 5:
                print(f"[compare]   MISMATCH t={ra['t']}: "
                      f"A cs={ra['cs']} B cs={rb['cs']}")
    n = a["ticks"]
    print(f"[compare] per-tick mismatches: {bad}/{n}")
    same_final = a["final_cs"] == b["final_cs"]
    print(f"[compare] final checksum identical: "
          f"{'PASS' if same_final else 'FAIL'}")
    if bad == 0 and same_final:
        print("\n*** ENGINE TWIN-RUN: PASS — the original-code engine is "
              "deterministic across independent instances, tick-for-tick "
              "***")
        return 0
    print("\n*** ENGINE TWIN-RUN: FAIL ***")
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ticks", type=int, default=60)
    ap.add_argument("--out", default="/tmp/twin.json")
    ap.add_argument("--compare", nargs=2, metavar=("A", "B"))
    args = ap.parse_args()
    if args.compare:
        return compare(args.compare[0], args.compare[1])
    run(args.ticks, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
