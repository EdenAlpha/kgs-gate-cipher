"""PeerLink — deterministic P2P friend-match networking for the exact
eFootball simulation engine.

Architecture (photocopy principle: the net layer transports INPUTS and
verifies checksums only — every simulated byte is produced by the original
game code running identically on both peers):

    you (engine A)                         friend (engine B)
        |  input packet (tick N)                 |
        +--------------------------------------->|   UDP (direct / punched /
        |<---------------------------------------+        relay fallback)
        |  input packet (tick N)                 |
        v                                        v
     lockstep gate: advance tick N only when BOTH inputs are present
        |                                        |
     identical original-code tick                identical
        |                                        |
     checksum exchange (FNV-1a of state)   ==    checksum
        (divergence = abort, never resync)

Packet format (little-endian):
    magic     u32   0x504C4B   ("PLK")
    version   u16   1
    ptype     u16   packet type (see PT_*)
    room      u64   room id (derived from the human room code)
    peer_id   u32   random per-session id
    tick      u32   lockstep tick number
    flags     u32
    payload   ...   (input packet: 56 x i32 = 224 bytes, the recorded
                     .trep field decode; checksum packet: u64 FNV-1a)
"""

from .transport import Transport, TransportError
from .rooms import LobbyServer, LobbyClient, room_code, code_from_id, id_from_code
from .lockstep import (LockstepPeer, InputPacket, fnv1a, PT_HELLO,
                        PT_INPUT, PT_INPUT_ACK, PT_CHECKSUM, PT_PING, PT_BYE)
from .session import FriendMatchSession, SessionRole

__version__ = "1.0.0"
