"""The deterministic lockstep protocol.

Both peers advance the SAME original-code simulation one tick at a time.
A tick advances only when the inputs for that tick are present from BOTH
sides. Inputs are idempotent, retransmitted until acked, and carried in
fixed 56-int32 packets (the decoded .trep field layout).

Divergence handling: every CHECKSUM_EVERY ticks both peers exchange an
FNV-1a hash of their whole simulation state, tagged with the tick it
was computed AT. Checksums are stored per-tick and compared only when
both sides hold the value for the SAME tick — this makes the comparison
timing-independent (a peer may be a few ticks ahead when the remote's
checksum arrives). Any mismatch aborts the match immediately — PeerLink
never resynchronizes diverged state, it restarts the match (same seed)
instead. That is what makes replays bit-exact: same code + same inputs
+ same seed => same state, proven per-tick.

Timings (the real game's cadence, from the dt decode):
    physics tick = 1/27 s  (~37.04 ms)
    lockstep frame budget = 3 ticks (~111 ms) of input latency tolerance
"""
import struct
import time
import os

from .transport import Transport, pack, unpack, TransportError

PT_HELLO = 1
PT_INPUT = 2
PT_INPUT_ACK = 3
PT_CHECKSUM = 4
PT_PING = 5
PT_BYE = 6

INPUT_INTS = 56
INPUT_BYTES = INPUT_INTS * 4
CHECKSUM_EVERY = 27          # once per simulated second
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3


def fnv1a(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


class InputPacket:
    __slots__ = ("tick", "ints")

    def __init__(self, tick, ints):
        self.tick = tick
        self.ints = list(ints)
        if len(self.ints) != INPUT_INTS:
            raise ValueError(f"input packet must have {INPUT_INTS} ints, "
                             f"got {len(self.ints)}")

    def pack(self, peer, room):
        return pack(PT_INPUT, room, peer, self.tick, 0,
                    struct.pack(f"<{INPUT_INTS}i", *self.ints))

    @classmethod
    def unpack(cls, payload):
        if len(payload) < INPUT_BYTES:
            raise ValueError("short input payload")
        ints = struct.unpack_from(f"<{INPUT_INTS}i", payload, 0)
        return ints


class LockstepPeer:
    """One side of a friend match.

    sim: an object with
        tick(local_ints, remote_ints)   -> advance one tick (both inputs)
        state_checksum() -> int         -> hash of the whole sim state
        on_event(kind, **kw)             -> optional logging hook
    """

    def __init__(self, sim, transport, remote, room, peer_id=None,
                 is_host=True):
        self.sim = sim
        self.t = transport
        self.remote = remote            # (ip, port) or None (relay-only)
        self.room = room
        self.peer_id = peer_id or transport.peer_id
        self.is_host = is_host
        self.tick = 0
        self.remote_tick = 0            # last tick the remote has confirmed
        self.pending_local = {}         # tick -> InputPacket (unacked)
        self.acked_local = set()          # ticks the remote explicitly ACKed
        self.remote_inputs = {}         # tick -> ints
        self.local_inputs = {}         # tick -> ints
        self.local_checksums = {}       # tick -> cs we computed at that tick
        self.remote_checksums = {}      # tick -> cs received from the peer
        self.diverged = False
        self.closed = False
        self._last_retx = 0.0
        self.stats = {"ticks": 0, "retransmits": 0, "relay_frames": 0,
                      "direct_frames": 0, "checksum_matches": 0}

    # ---------------------------------------------------------- sending
    def _send(self, data):
        if self.remote:
            try:
                self.t.send(self.remote, data)
                self.stats["direct_frames"] += 1
            except TransportError:
                pass
        try:
            self.t.send_via_relay(data)
            self.stats["relay_frames"] += 1
        except TransportError:
            pass

    def send_input(self, ints):
        p = InputPacket(self.tick, ints)
        self.pending_local[self.tick] = p
        self.local_inputs[self.tick] = list(ints)
        self._send(p.pack(self.peer_id, self.room))
        return p

    # ---------------------------------------------------------- receiving
    def pump(self, timeout=0.0):
        """Drain the socket; feed the protocol machine."""
        frames = self.t.recv(timeout=timeout)
        for (src, ptype, room, peer, tick, payload) in frames:
            if room and room != self.room:
                continue
            if ptype == 0xFFFF:
                # relayed frame: inner packet
                try:
                    ptype, room2, peer2, tick2, flags2, inner = unpack(payload)
                except TransportError:
                    continue
                self._dispatch(ptype, peer2, tick2, inner)
            else:
                self._dispatch(ptype, peer, tick, payload)
        # retransmit unacked local inputs (throttled)
        now = time.time()
        if now - self._last_retx >= 0.04:
            self._last_retx = now
            for tk in list(self.pending_local):
                if tk in self.acked_local:
                    del self.pending_local[tk]          # explicitly acked
                else:
                    p = self.pending_local[tk]
                    self._send(p.pack(self.peer_id, self.room))
                    self.stats["retransmits"] += 1

    def _dispatch(self, ptype, peer, tick, payload):
        if ptype == PT_INPUT:
            ints = InputPacket.unpack(payload)
            self.remote_inputs[tick] = ints
            # ack
            self._send(pack(PT_INPUT_ACK, self.room, self.peer_id, tick, 0))
        elif ptype == PT_INPUT_ACK:
            # per-tick ack tracking: NEVER infer earlier ticks from a
            # later ack (a gap means an input was lost — it must keep
            # retransmitting, or the lockstep deadlocks forever)
            self.acked_local.add(tick)
            self.remote_tick = max(self.remote_tick, tick)
            self.pending_local.pop(tick, None)
        elif ptype == PT_CHECKSUM:
            if len(payload) < 8:
                return
            (cs,) = struct.unpack_from("<Q", payload, 0)
            # store BY TICK; compare only when we have our own value for
            # the same tick (the remote may be behind/ahead of us)
            self.remote_checksums[tick] = cs
            self._compare_checksums()
        elif ptype == PT_BYE:
            self.closed = True

    def _compare_checksums(self):
        """Match up per-tick checksums both sides hold. Idempotent:
        compared pairs are dropped, so duplicate/retransmitted checksum
        frames never double-count or re-fire."""
        for tk in sorted(set(self.local_checksums)
                          & set(self.remote_checksums)):
            if self.local_checksums[tk] != self.remote_checksums[tk]:
                self.diverged = True
                if getattr(self.sim, "on_event", None):
                    self.sim.on_event("divergence", tick=tk)
                return
            self.stats["checksum_matches"] += 1
            del self.local_checksums[tk]
            del self.remote_checksums[tk]

    # ---------------------------------------------------------- stepping
    def can_step(self):
        return (self.tick in self.local_inputs
                and self.tick in self.remote_inputs)

    def step(self):
        """Advance one tick. Returns True if advanced.

        CRITICAL DETERMINISM RULE: inputs are handed to the sim in
        CANONICAL order (host's input first, guest's second) — never
        local/remote order, which differs between the two peers and
        would silently fork the two worlds. The net layer maps the
        transport slots to sim slots exactly once, here."""
        if not self.can_step():
            return False
        if self.is_host:
            host_in = self.local_inputs[self.tick]
            guest_in = self.remote_inputs[self.tick]
        else:
            host_in = self.remote_inputs[self.tick]
            guest_in = self.local_inputs[self.tick]
        self.sim.tick(host_in, guest_in)
        self.stats["ticks"] += 1
        self.tick += 1
        # periodic checksum exchange, tagged with the tick it was taken at
        if self.tick % CHECKSUM_EVERY == 0:
            cs = self.sim.state_checksum()
            self.local_checksums[self.tick] = cs
            self._send(pack(PT_CHECKSUM, self.room, self.peer_id,
                           self.tick, 0, struct.pack("<Q", cs)))
            self.stats["checksum_exchanges"] = \
                self.stats.get("checksum_exchanges", 0) + 1
            self._compare_checksums()
        # input housekeeping
        for d in (self.local_inputs, self.remote_inputs):
            for tk in [k for k in d if k < self.tick - 8]:
                del d[tk]
        return True

    def run_frame(self, local_ints, frame_budget_s=0.111):
        """One lockstep frame: send our input, wait for the remote input,
        advance up to 3 ticks. Returns the number of ticks advanced.

        The local controller state is sampled ONCE per display frame and
        reused for every tick inside the frame (the real game polls the
        pad once per frame too) — each tick still gets its own input
        packet, sequenced by tick number."""
        deadline = time.time() + frame_budget_s
        advanced = 0
        while advanced < 3:
            self.send_input(local_ints)          # input for CURRENT tick
            while not self.can_step() and time.time() < deadline:
                self.pump(timeout=0.005)
            if not self.can_step():
                break
            if not self.step():
                break
            advanced += 1
        self.pump(timeout=0.0)                   # drain acks/checksums
        return advanced

    def close(self):
        try:
            self._send(pack(PT_BYE, self.room, self.peer_id, self.tick, 0))
        except Exception:
            pass
        self.closed = True
