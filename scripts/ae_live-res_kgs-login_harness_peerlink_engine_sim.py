"""EngineSim — binds the headless original-code engine to the lockstep.

The FriendMatchSession `sim` interface is two methods:

    tick(host_ints, guest_ints)   advance one 1/27 s physics tick
    state_checksum() -> int       FNV-1a of the whole sim state

This adapter implements BOTH on top of the real engine: a Unicorn-mapped
libUE4.so (the untouched 160 MB original), the game's own ball-module
ctors, the game's own kick installer, and the game's own physics kernel
(ball_update_entry 0x6e938a0 -> 0x6ea0958). No game code is rewritten.

Determinism contract (what lockstep needs):
  * the initial state is a pure function of `seed`
  * each tick consumes exactly (host_ints, guest_ints) in canonical order
  * the kernel persistent context is reset before each tick (the F2
    validation cadence), so state(t+1) = f(state(t), inputs) only
  * every float operation happens inside the original ARM64 code — same
    binary, same inputs => same f32 results on both peers.

Input semantics (56-int packets, the decoded .trep field layout):
  * ints[0]  analog X   (-128..127)
  * ints[1]  analog Y   (-128..127)
  * ints[2]  bit0 = shoot button
  A rising shoot edge from EITHER player installs a kick through the
  game's own installer: substate 7 (KICKED), pos, quaternion; the kick
  VELOCITY is derived from the analog deflection and installed at the
  module input state — the documented stand-in for the player-action
  paramsB path (.trep analog burst -> kick speed), which is the known
  remaining integration gap (FINDINGS 10.3 / m8).

Everything else (flight, gravity, drag, Magnus, bounce, restitution) is
computed by the original kernel alone.
"""
import math
import os
import struct
import sys

# the engine machinery lives in scripts/ (sibling of this package)
_HERE = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS = os.path.join(os.path.dirname(_HERE), "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

# lazily imported so the net layer itself stays dependency-free
_ball_object_run = None

A_KICK_INSTALL = 0x6e93aec          # the game's kick installer (m8-proven)
A_CONT_TICK = 0x6e92ce8             # module continuous tick (m8 flight path)

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3


def fnv1a(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


def _f32(x):
    return struct.unpack("<f", struct.pack("<f", x))[0]


class EngineSim:
    """One deterministic original-code simulation instance."""

    def __init__(self, seed=1, verbose=False, on_event=None):
        global _ball_object_run
        if _ball_object_run is None:
            import ball_object_run as m
            _ball_object_run = m
        bo = _ball_object_run

        self.on_event = on_event
        self.seed = seed
        self.n = 0

        self.world = bo.BallWorld(verbose=verbose)
        self.world.construct()
        self.core = self.world.core
        self.ball = self.world.ball
        self.world.set_N(3)                       # 3 substeps/tick (game's)

        # initial state: pure function of the seed (kickoff-like launch)
        s = seed & 0xFFFFFFFF
        def rnd():
            nonlocal s
            s ^= (s << 13) & 0xFFFFFFFF
            s ^= s >> 17
            s ^= (s << 5) & 0xFFFFFFFF
            return s
        pos = (_f32((rnd() / 0xFFFFFFFF) * 6.0 - 3.0),
               bo.RADIUS,
               _f32((rnd() / 0xFFFFFFFF) * 6.0 - 3.0))
        vel = (_f32((rnd() / 0xFFFFFFFF) * 8.0 - 4.0),
               _f32(6.0 + (rnd() / 0xFFFFFFFF) * 6.0),
               _f32((rnd() / 0xFFFFFFFF) * 8.0 - 4.0))
        self.world.set_state(pos, vel=vel, phys=1, sub=6)   # flight state
        self._state = self.world.get_state(0x30)

        # per-player button edge memory (canonical: host first)
        self._btn = [0, 0]
        self.kicks_installed = 0

    # ------------------------------------------------------------ helpers
    def _kick_velocity(self, sx, sy):
        """Analog deflection -> kick velocity (paramsB stand-in, documented)."""
        mag = math.sqrt(sx * sx + sy * sy)
        mag = min(1.0, mag)
        speed = 8.0 + 12.0 * mag                     # 8..20 m/s
        up = 3.0 + 6.0 * mag                          # elevation
        if mag > 1e-6:
            hx, hz = sx / mag, sy / mag
        else:
            hx, hz = 1.0, 0.0
        return (_f32(hx * speed), _f32(up), _f32(hz * speed))

    def _install_kick(self, sx, sy, quat=(1.0, 0.0, 0.0, 0.0)):
        """Install a kick with the game's own installer (0x6e93aec)."""
        bo = _ball_object_run
        st = self._state
        pos = struct.unpack_from("<3f", st, 0)
        # src = {f32 x, y, z} (the position the installer reads)
        src = self.core.alloc(16, struct.pack("<3f", *pos), name="kick_src")
        qbuf = self.core.alloc(16, struct.pack("<4f", *quat), name="kick_q")
        r = self.core.call(A_KICK_INSTALL, x0=self.ball, x1=src, x2=qbuf)
        if r["error"]:
            if self.on_event:
                self.on_event("kick_install_error", detail=str(r))
            return False
        # velocity: written at the input state (documented gap — the real
        # source is the paramsB player-action path)
        vel = self._kick_velocity(sx, sy)
        out = bytearray(bo.STATE_SZ)
        struct.pack_into("<3f", out, 0x000, *pos)
        struct.pack_into("<3f", out, 0x00C, *vel)
        struct.pack_into("<4f", out, 0x098, *quat)
        self.core.uc.mem_write(self.ball + 0x30, bytes(out))
        self.kicks_installed += 1
        return True

    # ------------------------------------------------- the lockstep iface
    def tick(self, host_ints, guest_ints):
        """Advance one 1/27 s tick of the original physics kernel."""
        bo = _ball_object_run
        # canonical order: host is always slot 0 on BOTH peers
        for slot, ints in enumerate((host_ints, guest_ints)):
            btn = ints[2] & 1
            if btn and not self._btn[slot]:          # rising shoot edge
                sx = ((ints[0] & 0xFF) - 128) / 127.0
                sy = ((ints[1] & 0xFF) - 128) / 127.0
                self._install_kick(sx, sy)
            self._btn[slot] = btn
        # F2 cadence: reset kernel persistent ctx, then native tick +
        # the game's own output->input mirror handshake
        self.world.reset_kernel_ctx()
        self._state = self.world.tick_feedback()
        self.n += 1
        return self._state

    def state_bytes(self):
        return bytes(self._state)

    def state_checksum(self):
        return fnv1a(self.state_bytes())

    def pos_vel(self):
        p = struct.unpack_from("<3f", self._state, 0)
        v = struct.unpack_from("<3f", self._state, 0x0C)
        return p, v
