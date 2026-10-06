#!/usr/bin/env python3
"""Smoke test: does the original-code engine still boot and tick?

Loads libUE4.so under Unicorn via the M2 machinery (BallWorld), constructs
the ball module with the game's own ctors, sets a state, and runs 3 native
ticks (ball_update_entry 0x6e938a0, dt = 1/27 s). Prints the state vector
after each tick + a per-tick FNV-1a checksum of the 0x128 state bytes.
"""
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ball_object_run import BallWorld, rd_state, STATE_SZ, A_TICK


def fnv1a(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def main():
    t0 = time.time()
    world = BallWorld(verbose=False)
    world.construct()
    print(f"[boot] ball module constructed in {time.time() - t0:.1f}s")
    world.set_state((0.0, 0.0, 0.1086859330534935),
                   vel=(11.0, 3.0, 14.0), state_idx=8)
    for i in range(3):
        t1 = time.time()
        st = world.tick_feedback()          # native tick + the game's own
        # output->input mirror handshake (F3-proven cadence)
        pos = struct.unpack_from('<3f', st, 0)
        vel = struct.unpack_from('<3f', st, 0x0C)
        cs = fnv1a(st)
        print(f"[tick {i}] {time.time() - t1:.2f}s pos={pos} vel={vel} "
              f"cs={cs:016x}")
    print("[smoke] OK — engine boots and ticks on original code")


if __name__ == "__main__":
    main()
