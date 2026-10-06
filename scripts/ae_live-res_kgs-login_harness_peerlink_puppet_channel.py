"""peerlink puppet coordination channel (M18/M19 shared).

Carries the room code + match lifecycle between the puppet host and the
friend's side. This is NOT the game transport — the genuine app does all
game networking on its own stack; this channel only delivers the
6-digit Match ID and status so a friend on a stock app can join.
"""
from __future__ import annotations

import json
import socket
import sys
import time

MSG_HELLO = "hello"
MSG_HOST_ANNOUNCE = "host_announce"   # {match_id}
MSG_JOIN_ACK = "join_ack"
MSG_MATCH_START = "match_start"
MSG_MATCH_END = "match_end"          # {score?}
MSG_ABORT = "abort"                  # {reason}


class ConsoleChannel:
    def send(self, mtype: str, **fields) -> None:
        print(f"[peerlink-channel] {mtype} {json.dumps(fields, ensure_ascii=False)}",
              flush=True)


class UdpChannel:
    """Plain JSON datagrams (default port 42621 — 42620 is the lockstep
    lobby of the engine path). Wire to whatever rendezvous you like."""

    def __init__(self, addr: tuple[str, int]):
        self.addr = addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, mtype: str, **fields) -> None:
        msg = {"type": mtype, "ts": time.time(), **fields}
        try:
            self.sock.sendto(json.dumps(msg).encode(), self.addr)
        except OSError as e:  # never let the notifier kill the bot
            print(f"[channel] send failed: {e}", file=sys.stderr, flush=True)


def make_channel(cfg: dict):
    ch = cfg.get("channel", {})
    if ch.get("mode") == "udp":
        return UdpChannel((ch.get("udp", {}).get("host") or "127.0.0.1",
                           int(ch.get("udp", {}).get("port", 42621))))
    return ConsoleChannel()
