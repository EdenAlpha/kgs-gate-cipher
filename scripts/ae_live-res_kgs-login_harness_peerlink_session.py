"""FriendMatchSession — the product-level API.

The friend-match room flow:
    host   = FriendMatchSession.create(lobby_addr)      -> a numeric Match ID like 482913
    friend = FriendMatchSession.join(code, lobby_addr)
    ... both call .frame(local_input_ints) once per display frame;
        the session runs the lockstep and returns how many sim ticks ran.

The session owns: transport, lobby handshake, hole punching, relay
fallback, and the LockstepPeer. The simulation itself is injected as a
`sim` object (for the headless engine, an adapter that ticks the
original eFootball code; for tests, any deterministic object).
"""
import threading
import time

from .transport import Transport
from .rooms import LobbyClient, LobbyServer, room_code, code_from_id
from .lockstep import LockstepPeer, INPUT_INTS


class SessionRole:
    HOST = "host"
    GUEST = "guest"


class FriendMatchSession:
    def __init__(self, sim, lobby_addr=("127.0.0.1", 42620),
                 bind=("0.0.0.0", 0), name="player"):
        self.sim = sim
        self.lobby_addr = lobby_addr
        self.t = Transport(bind=bind)
        self.lobby = LobbyClient(self.t, lobby_addr, name=name)
        self.peer = None
        self.room = None
        self.code = None
        self.role = None
        self._hb = None

    # ------------------------------------------------------ room flow
    def create(self, timeout=5.0):
        """Create a room. Returns the human room code immediately;
        the friend joins later — call wait_for_guest() to block until
        they connect."""
        rid, code = self.lobby.create_room(timeout=timeout)
        self.room = rid
        self.code = code
        self.role = SessionRole.HOST
        return code

    def wait_for_guest(self, timeout=120.0):
        """After create(); block until the friend joins. Returns the code.

        Frames that arrive while we are still waiting (the guest's punch
        pings, early input packets) are PUSHED BACK onto the transport so
        the LockstepPeer consumes them once attached — nothing read from
        the socket is ever dropped between protocol phases."""
        peer_addr = None
        deadline = time.time() + timeout
        while time.time() < deadline and not peer_addr:
            frames = self.t.recv(timeout=0.2)
            for i, (src, ptype, pr, rk, tick, payload) in enumerate(frames):
                if payload[:3] == b"PLP":
                    addr = self._parse_peerinfo(payload)
                    if addr:
                        peer_addr = addr
                        # requeue everything else we drained (peer traffic!)
                        self.t.pushback(frames[:i] + frames[i + 1:])
                        break
            if not peer_addr:
                # keep the lobby room alive
                self.lobby.heartbeat(self.room)
        if not peer_addr:
            raise TimeoutError("guest did not join")
        self._attach_peer(peer_addr)
        return self.code

    def join(self, code, timeout=5.0):
        rid, peer_addr = self.lobby.join_room(code, timeout=timeout)
        self.room = rid
        self.code = code
        self.role = SessionRole.GUEST
        self._attach_peer(peer_addr)
        return rid

    def _parse_peerinfo(self, payload):
        # PEERINFO: b"PLP" + peer(4) + ip(4) + port(2)
        import socket as _s
        import struct as _st
        if payload[:3] != b"PLP":
            return None
        ip = _s.inet_ntoa(payload[7:11])
        port = _st.unpack_from("<H", payload, 11)[0]
        return (ip, port)

    def _attach_peer(self, peer_addr):
        # relay fallback registration + hole punch in the background
        self.t.attach_relay(self.lobby_addr, self.room)
        puncher = threading.Thread(target=self.t.punch,
                                   args=(peer_addr, self.room),
                                   daemon=True)
        puncher.start()
        self.peer = LockstepPeer(self.sim, self.t, peer_addr, self.room,
                                 is_host=(self.role == SessionRole.HOST))
        # heartbeat keeper
        self._hb = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._hb.start()

    def _heartbeat_loop(self):
        while not self.peer or not self.peer.closed:
            try:
                self.lobby.heartbeat(self.room)
            except Exception:
                pass
            time.sleep(10.0)

    # ------------------------------------------------------ match flow
    def frame(self, local_ints):
        """One display frame. Feed the local controller state (56 ints),
        run the lockstep. Returns ticks advanced (0..3)."""
        if not self.peer:
            raise RuntimeError("session not attached to a peer")
        return self.peer.run_frame(local_ints)

    @property
    def diverged(self):
        return bool(self.peer and self.peer.diverged)

    @property
    def tick(self):
        return self.peer.tick if self.peer else 0

    def close(self):
        if self.peer:
            self.peer.close()
        self.t.close()
