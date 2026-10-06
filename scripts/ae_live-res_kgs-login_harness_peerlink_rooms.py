"""Rooms and numeric match IDs.

A room is a u64 id on the wire. The human-facing ID is a plain NUMBER
(like the real game's friend-match Match ID):
    code_from_id(room_id) -> "482913"
    id_from_code("482913") -> room_id

IDs are 6 digits (100000-999999, no leading zeros so nobody argues
about typing them).

Lobby (rendezvous) protocol — binary over UDP:
    client -> LOBBY_CREATE  [b"PLC", peer(4), name_len(1), name...]
    lobby  -> LOBBY_CREATED [b"PLK", room(8)]
    client -> LOBBY_JOIN    [b"PLJ", peer(4), room(8), name_len(1), name...]
    lobby  -> LOBBY_PEER     [b"PLP", peer(4), ip(4), port(2)]   (the OTHER peer)
    lobby  -> LOBBY_ERR      [b"PLE", reason(1)]
The lobby only ever tells each peer the other peer's public endpoint;
after the exchange both sides punch and talk directly (or via relay).
"""
import os
import socket
import struct
import threading
import time

CODE_DIGITS = 6                      # eFootball-style numeric match id
CODE_MIN = 10 ** (CODE_DIGITS - 1)   # 100000
CODE_MAX = 10 ** CODE_DIGITS - 1     # 999999


def code_from_id(room_id):
    """Room id -> the numeric string a human types."""
    n = room_id % (10 ** CODE_DIGITS)
    if n < CODE_MIN:
        n += CODE_MIN                   # always 6 digits, no leading zeros
    return str(n)


def id_from_code(code):
    """Numeric string -> room id. Digits only, like the real game."""
    code = code.strip()
    if not code.isdigit():
        raise ValueError(f"match id must be a number, got {code!r}")
    return int(code)


def room_code():
    """A fresh random room id/code pair."""
    rid = struct.unpack("<Q", os.urandom(8))[0]
    rid = CODE_MIN + rid % (CODE_MAX - CODE_MIN + 1)
    return rid, code_from_id(rid)


# ------------------------------------------------------------------ lobby

CREATE = b"PLC"
CREATED = b"PLK"
JOIN = b"PLJ"
PEERINFO = b"PLP"
ERR = b"PLE"
HEARTBEAT = b"PLH"


class LobbyServer:
    """Tiny UDP lobby + optional relay. Run one on any public host.

    rooms: {room_id: {peer_id: (ip, port, last_seen)}}
    The lobby relays nothing by default; attach_relay clients register
    separately. Keep-alive: peers heartbeat every 10s; rooms expire
    after 120s without heartbeats.
    """

    def __init__(self, bind=("0.0.0.0", 42620)):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(bind)
        self.addr = self.sock.getsockname()
        self.rooms = {}
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def start(self, daemon=True):
        self._thread = threading.Thread(target=self._run, daemon=daemon)
        self._thread.start()
        return self

    def _run(self):
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data, src = self.sock.recvfrom(65535)
            except socket.timeout:
                self._sweep()
                continue
            try:
                self._handle(src, data)
            except Exception:
                pass

    def _handle(self, src, data):
        tag = data[:3]
        if tag == CREATE:
            peer = struct.unpack_from("<I", data, 3)[0]
            with self.lock:
                rid = None
                for _ in range(64):
                    cand = struct.unpack("<Q", os.urandom(8))[0]
                    cand = CODE_MIN + cand % (CODE_MAX - CODE_MIN + 1)
                    if cand not in self.rooms:
                        rid = cand
                        break
                if rid is None:
                    self.sock.sendto(ERR + b"\x01", src)
                    return
                self.rooms[rid] = {peer: (src[0], src[1], time.time())}
            self.sock.sendto(CREATED + struct.pack("<Q", rid), src)
        elif tag == JOIN:
            peer = struct.unpack_from("<I", data, 3)[0]
            rid = struct.unpack_from("<Q", data, 7)[0]
            with self.lock:
                room = self.rooms.get(rid)
                if not room or len(room) >= 2:
                    self.sock.sendto(ERR + b"\x02", src)
                    return
                room[peer] = (src[0], src[1], time.time())
                others = [(pid, info) for pid, info in room.items()
                          if pid != peer]
            if others:
                pid, (ip, port, _t) = others[0]
                self._send_peerinfo(src, pid, ip, port)
                # tell the creator too
                with self.lock:
                    room = self.rooms.get(rid) or {}
                for pid2, (ip2, port2, _t) in room.items():
                    if pid2 != peer:
                        self._send_peerinfo((ip2, port2), peer,
                                            src[0], src[1])
        elif tag == HEARTBEAT:
            peer = struct.unpack_from("<I", data, 3)[0]
            rid = struct.unpack_from("<Q", data, 7)[0]
            with self.lock:
                room = self.rooms.get(rid)
                if room and peer in room:
                    ip, port, _t = room[peer]
                    room[peer] = (ip, port, time.time())
        elif tag == b"RFW":
            # relay mode: forward to the other peer(s) in the room
            rid = struct.unpack_from("<Q", data, 3)[0]
            with self.lock:
                room = self.rooms.get(rid) or {}
                targets = [(ip, port) for pid, (ip, port, _t) in room.items()
                           if (ip, port) != src]
            for dst in targets:
                self.sock.sendto(data, dst)

    def _send_peerinfo(self, dst, peer_id, ip, port):
        ipb = socket.inet_aton(ip)
        self.sock.sendto(PEERINFO + struct.pack("<I", peer_id) + ipb +
                         struct.pack("<H", port), dst)

    def _sweep(self):
        now = time.time()
        with self.lock:
            for rid in list(self.rooms):
                room = self.rooms[rid]
                room = {pid: info for pid, info in room.items()
                        if now - info[2] < 120.0}
                if room:
                    self.rooms[rid] = room
                else:
                    del self.rooms[rid]

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self.sock.close()


class LobbyClient:
    """Client side of the lobby protocol."""

    def __init__(self, transport, lobby_addr, name="player"):
        self.t = transport
        self.lobby = lobby_addr
        self.name = name

    def create_room(self, timeout=5.0):
        msg = CREATE + struct.pack("<I", self.t.peer_id) + \
            bytes([len(self.name)]) + self.name.encode()
        deadline = time.time() + timeout
        self.t.sock.sendto(msg, self.lobby)
        while time.time() < deadline:
            try:
                data, src = self.t.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except BlockingIOError:
                time.sleep(0.01)
                continue
            if data[:3] == CREATED and src == self.lobby:
                rid = struct.unpack_from("<Q", data, 3)[0]
                return rid, code_from_id(rid)
            if data[:3] == ERR:
                raise TransportLookupError("lobby refused create")
        raise TransportLookupError("lobby create timeout")

    def join_room(self, code, timeout=5.0):
        rid = id_from_code(code)
        msg = JOIN + struct.pack("<I", self.t.peer_id) + \
            struct.pack("<Q", rid) + bytes([len(self.name)]) + self.name.encode()
        deadline = time.time() + timeout
        self.t.sock.sendto(msg, self.lobby)
        while time.time() < deadline:
            try:
                data, src = self.t.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except BlockingIOError:
                time.sleep(0.01)
                continue
            if data[:3] == PEERINFO and src == self.lobby:
                _peer = struct.unpack_from("<I", data, 3)[0]
                ip = socket.inet_ntoa(data[7:11])
                port = struct.unpack_from("<H", data, 11)[0]
                return rid, (ip, port)
            if data[:3] == ERR:
                raise TransportLookupError("lobby refused join")
        raise TransportLookupError("lobby join timeout")

    def heartbeat(self, rid):
        msg = HEARTBEAT + struct.pack("<I", self.t.peer_id) + \
            struct.pack("<Q", rid)
        self.t.sock.sendto(msg, self.lobby)


class TransportLookupError(Exception):
    pass
