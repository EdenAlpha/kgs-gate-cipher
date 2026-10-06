"""UDP transport with direct / hole-punch / relay fallback modes.

Usage:
    t = Transport(bind=("0.0.0.0", 0))
    t.send((ip, port), data)
    for (src, data) in t.recv(timeout=0.1): ...
    # relay mode:
    t.attach_relay(relay_addr, token)

Relay protocol (tiny, JSON-free, binary):
    -> RGN (register): [b"RGN", peer_id(4), room(8)]
    <- ROK:            [b"ROK", assigned_slot(1)]
    -> RFW (forward):  [b"RFW", room(8), payload...]
    <- RFW (from peer):[b"RFW", room(8), payload...]
The relay is stateless besides the room->peers table and never inspects
the payload — the lockstep protocol rides on top unchanged.
"""
import socket
import struct
import threading
import time
import os

MAGIC = 0x504C4B
HEADER = struct.Struct("<IHHI I I")     # magic, ver, room(16b...) -- see pack()
# We use a fixed 24-byte header for everything:
#   magic u32 | version u16 | ptype u16 | room u64 | peer u32 | tick u32 = 24
PKT_HEADER = struct.Struct("<IHH Q I I")  # 4+2+2(+2 pad)+8+4+4 = 28 actually
# keep it simple and explicit:
PKT_HEADER = struct.Struct("<IHHIQII")    # magic, ver, ptype, room, peer, tick, flags = 32


class TransportError(Exception):
    pass


def pack(ptype, room, peer, tick, flags, payload=b""):
    return PKT_HEADER.pack(MAGIC, 1, ptype, room, peer, tick, flags) + payload


def unpack(data):
    if len(data) < PKT_HEADER.size:
        raise TransportError("short packet")
    magic, ver, ptype, room, peer, tick, flags = PKT_HEADER.unpack_from(data, 0)
    if magic != MAGIC:
        raise TransportError("bad magic")
    return ptype, room, peer, tick, flags, data[PKT_HEADER.size:]


class Transport:
    """A UDP socket wrapper: direct sends, punch bursts, and optional
    relay attachment. Thread-safe recv loop via a queue."""

    def __init__(self, bind=("0.0.0.0", 0)):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(bind)
        self.sock.setblocking(False)
        self.local = self.sock.getsockname()
        self.peer_id = struct.unpack("<I", os.urandom(4))[0] or 1
        # relay state
        self._relay = None           # (host, port)
        self._relay_room = 0
        self._relay_lock = threading.Lock()
        self._keepalive_t = 0.0
        # pushback queue: frames read too early (e.g. peer traffic that
        # arrives while the owner is still waiting for a lobby reply) —
        # recv() delivers them FIRST so nothing is ever dropped on the
        # floor between protocol phases
        self._backlog = []

    # ------------------------------------------------------------- direct
    def send(self, dest, data):
        """dest = (ip, port); data already packed via pack()."""
        try:
            self.sock.sendto(data, dest)
        except OSError as e:
            raise TransportError(str(e))

    def pushback(self, frames):
        """Re-queue frames that were drained before their consumer
        existed (see wait_for_guest). They are delivered by the next
        recv() BEFORE any newly-read socket traffic."""
        self._backlog.extend(frames)

    def recv(self, timeout=0.0):
        """Yield (src, ptype, room, peer, tick, flags, payload) tuples.
        Relay frames are unwrapped transparently.

        Drains EVERYTHING currently readable each time select() fires
        (capped at 256 frames) — a slow caller must never leave frames
        buffered or the lockstep stalls under the dual direct+relay send.
        Backlogged (pushed-back) frames are returned first, immediately.
        """
        import select
        out = []
        if self._backlog:
            out.extend(self._backlog)
            self._backlog = []
            timeout = 0.0               # deliver now; also drain the socket
        deadline = time.time() + timeout
        while True:
            now = time.time()
            wait = max(0.0, deadline - now)
            r, _, _ = select.select([self.sock], [], [], wait)
            if not r:
                break
            n = 0
            while n < 256:
                try:
                    data, src = self.sock.recvfrom(65535)
                except BlockingIOError:
                    break
                n += 1
                frame = self._frame_in(src, data)
                if frame:
                    out.append(frame)
            if time.time() >= deadline:
                break
        return out

    def _frame_in(self, src, data):
        # relay frames
        if data[:3] == b"RFW" and len(data) > 11:
            room = struct.unpack_from("<Q", data, 3)[0]
            return (src, 0xFFFF, room, 0, 0, data[11:])
        try:
            ptype, room, peer, tick, flags, payload = unpack(data)
        except TransportError:
            # raw lobby protocol frames (PLP/PLK/PLH/...) pass through
            # with the special ptype 0xFFFE and the full payload
            return (src, 0xFFFE, 0, 0, 0, data)
        return (src, ptype, room, peer, tick, payload)

    # -------------------------------------------------------- hole punch
    def punch(self, dest, room, n=24, interval=0.25):
        """Simultaneous-open burst: send PT_PINGs so both NATs map the flow."""
        for i in range(n):
            self.send(dest, pack(5, room, self.peer_id, 0, 0,
                                 struct.pack("<I", i)))
            time.sleep(interval)

    # -------------------------------------------------------------- relay
    def attach_relay(self, relay_addr, room):
        with self._relay_lock:
            self._relay = relay_addr
            self._relay_room = room
        # register
        msg = b"RGN" + struct.pack("<I", self.peer_id) + struct.pack("<Q", room)
        try:
            self.sock.sendto(msg, relay_addr)
        except OSError as e:
            raise TransportError(str(e))

    def send_via_relay(self, data):
        with self._relay_lock:
            relay, room = self._relay, self._relay_room
        if not relay:
            raise TransportError("no relay attached")
        msg = b"RFW" + struct.pack("<Q", room) + data
        try:
            self.sock.sendto(msg, relay)
        except OSError as e:
            raise TransportError(str(e))

    def send_auto(self, dest, data):
        """Direct first; if a relay is attached and direct is not confirmed,
        mirror via relay. Caller handles the confirmation logic."""
        if dest:
            try:
                self.send(dest, data)
            except TransportError:
                pass
        try:
            self.send_via_relay(data)
        except TransportError:
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
