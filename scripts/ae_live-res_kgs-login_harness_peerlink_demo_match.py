#!/usr/bin/env python3
"""PeerLink end-to-end demo / integration test.

Runs a REAL friend match over UDP on localhost:
  1. a LobbyServer (rendezvous + relay)
  2. HOST creates a room -> gets a numeric Match ID (6 digits)
  3. GUEST joins with the code
  4. both punch + attach (direct + relay fallback active)
  5. 400 display frames run the lockstep; the deterministic mini-sim
     integrates the proven ball-flight model (dt = 1/27 s, drag + Magnus)
     driven by both peers' recorded controller streams
  6. checksums compared every simulated second; final state compared

PASS criteria: both peers finish 1200 ticks with identical state
checksums and identical final ball position (bit-exact).
"""
import math
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from peerlink import (FriendMatchSession, LobbyServer, room_code,
                      code_from_id, id_from_code, fnv1a)
from peerlink.lockstep import INPUT_INTS, CHECKSUM_EVERY

DT = 1.0 / 27.0          # the game's physics tick (proven in M4)


class BallSim:
    """Deterministic 3-DOF ball flight — the same shape as the R0-R3 proof:
    gravity, linear drag, Magnus lift; fixed-point-free IEEE math is
    identical on both peers by construction (same Python build).

    The controller inputs (56 ints) map to a small thruster on the ball
    just to make inputs MATTER for the state (in the real engine these
    are the .trep fields feeding the original game code).
    """

    def __init__(self, seed=1):
        self.t = 0.0
        self.n = 0
        s = seed & 0xFFFFFFFF
        # xorshift32 - deterministic seed expansion
        def rnd():
            nonlocal s
            s ^= (s << 13) & 0xFFFFFFFF
            s ^= s >> 17
            s ^= (s << 5) & 0xFFFFFFFF
            return s
        self.p = [rnd() / 0xFFFFFFFF * 40.0 - 20.0 for _ in range(3)]
        self.p[2] = 0.5                       # start at half a meter
        self.v = [rnd() / 0xFFFFFFFF * 8.0 - 4.0 for _ in range(3)]
        self.v[2] = 9.0                        # a nice loft
        self.spin = 0.35
        self.log = []

    def tick(self, host_ints, guest_ints):
        # CANONICAL ORDER: host's input is always the first argument on
        # BOTH peers (the net layer guarantees it) — asymmetric weights
        # are fine as long as they see the same (host, guest) pairing.
        ax = ((host_ints[0] & 0xFF) - 128) * 0.01 + \
             ((guest_ints[0] & 0xFF) - 128) * 0.005
        ay = ((host_ints[1] & 0xFF) - 128) * 0.01 + \
             ((guest_ints[1] & 0xFF) - 128) * 0.005
        kick = 1.0
        if (host_ints[2] & 1) and (guest_ints[2] & 1):
            kick = 1.05                         # both pressing "shoot"
        # gravity
        az = -9.80665
        # drag + magnus (fixed coefficients)
        speed = math.sqrt(self.v[0] ** 2 + self.v[1] ** 2 + self.v[2] ** 2)
        drag = 0.006 * speed
        magnus = 0.0022 * self.spin
        self.v[0] += (ax - drag * self.v[0] - magnus * self.v[1]) * DT * kick
        self.v[1] += (ay - drag * self.v[1] + magnus * self.v[0]) * DT * kick
        self.v[2] += (az - drag * self.v[2]) * DT * kick
        # integrate
        for i in range(3):
            self.p[i] += self.v[i] * DT
        # ground bounce (restitution 0.62 - like the real ball)
        if self.p[2] < 0.11 and self.v[2] < 0:
            self.p[2] = 0.11
            self.v[2] = -self.v[2] * 0.62
            self.v[0] *= 0.985
            self.v[1] *= 0.985
        self.t += DT
        self.n += 1

    def state_bytes(self):
        return struct.pack("<Ifffffff", self.n, *self.p, *self.v, self.spin)

    def state_checksum(self):
        return fnv1a(self.state_bytes())


def recorded_inputs(peer_idx, frame):
    """Synthetic recorded controller streams (stand-in for the .trep
    decode): 56 ints, deterministic per (peer, frame)."""
    s = (peer_idx * 7919 + frame * 104729) & 0xFFFFFFFF
    out = []
    for _ in range(INPUT_INTS):
        s ^= (s << 13) & 0xFFFFFFFF
        s ^= s >> 17
        s ^= (s << 5) & 0xFFFFFFFF
        out.append(s & 0xFF)
    return out


def main():
    print("=== PeerLink end-to-end friend match ===")
    lobby = LobbyServer(bind=("127.0.0.1", 42620)).start()
    time.sleep(0.1)

    host_sim = BallSim(seed=1)
    guest_sim = BallSim(seed=1)               # SAME SEED = same initial world

    host = FriendMatchSession(host_sim, lobby_addr=("127.0.0.1", 42620),
                              name="host")
    guest = FriendMatchSession(guest_sim, lobby_addr=("127.0.0.1", 42620),
                              name="guest")

    t0 = time.time()
    # --- room flow: create -> code -> join -------------------------------
    code_holder = {}

    import threading

    def host_thread():
        code = host.create(timeout=3.0)
        code_holder["code"] = code
        host.wait_for_guest(timeout=30)

    ht = threading.Thread(target=host_thread, daemon=True)
    ht.start()
    for _ in range(100):                       # wait for create() to land
        if host.code:
            break
        time.sleep(0.05)
    code = host.code
    assert code, "host.create() did not return a code"
    print(f"[host] room created: code = {code}")
    guest.join(code, timeout=5.0)
    print(f"[guest] joined room {code}")
    ht.join(timeout=31)
    assert host.peer and guest.peer, "peers not attached"
    print(f"[net] peers attached: host={host.t.local} guest={guest.t.local}")

    # --- the match: 400 frames, ~3 ticks each = 1200 ticks -----------------
    total_host = 0
    total_guest = 0
    N_FRAMES = 400
    stop = {"host": False, "guest": False}

    def run_peer(sess, peer_idx, which):
        frame = 0
        while sess.tick < 1200 and not sess.peer.closed:
            sess.frame(recorded_inputs(peer_idx, frame))
            frame += 1
        stop[which] = True

    t1 = time.time()
    th = threading.Thread(target=run_peer, args=(host, 0, "host"), daemon=True)
    tg = threading.Thread(target=run_peer, args=(guest, 1, "guest"), daemon=True)
    th.start()
    tg.start()
    last = 0
    while (host.tick < 1200 or guest.tick < 1200) and time.time() - t1 < 90:
        time.sleep(0.5)
        if host.tick != last:
            print(f"  t={time.time() - t1:5.1f}s host ticks={host.tick} "
                  f"guest ticks={guest.tick}")
            last = host.tick
    stop["host"] = stop["guest"] = True
    time.sleep(0.3)
    dur = time.time() - t1

    # let trailing acks/checksums drain so the final exchanges compare
    for _ in range(10):
        host.peer.pump(0.02)
        guest.peer.pump(0.02)

    print(f"\n[match] frames={N_FRAMES} in {dur:.2f}s "
          f"({N_FRAMES / max(dur, 1e-9):.1f} f/s)")
    print(f"[host]  ticks={host.tick} stats={host.peer.stats}")
    print(f"[guest] ticks={guest.tick} stats={guest.peer.stats}")

    hp, gp = host_sim.p, guest_sim.p
    print(f"[host]  ball=({hp[0]:.9f}, {hp[1]:.9f}, {hp[2]:.9f}) n={host_sim.n}")
    print(f"[guest] ball=({gp[0]:.9f}, {gp[1]:.9f}, {gp[2]:.9f}) n={guest_sim.n}")

    host_cs = host_sim.state_checksum()
    guest_cs = guest_sim.state_checksum()
    print(f"[host]  checksum={host_cs:016x}")
    print(f"[guest] checksum={guest_cs:016x}")

    ok_ticks = (host.tick == guest.tick == 1200)
    ok_state = (host_cs == guest_cs)
    ok_ball = all(abs(a - b) < 1e-15 for a, b in zip(hp, gp))
    diverged = host.diverged or guest.diverged
    print(f"\nCHECKS: 1200/1200 ticks: {'PASS' if ok_ticks else 'FAIL'}"
          f" | checksum identical: {'PASS' if ok_state else 'FAIL'}"
          f" | ball bit-exact: {'PASS' if ok_ball else 'FAIL'}"
          f" | divergence: {'NONE' if not diverged else 'DETECTED!'}")

    host.close()
    guest.close()
    lobby.stop()

    if ok_ticks and ok_state and ok_ball and not diverged:
        print("\n*** PEERLINK FRIEND MATCH: PASS (bit-exact 1200/1200) ***")
        return 0
    print("\n*** FAILED ***")
    return 1


if __name__ == "__main__":
    sys.exit(main())
