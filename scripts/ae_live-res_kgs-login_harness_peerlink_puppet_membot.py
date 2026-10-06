#!/usr/bin/env python3
"""membot — the non-UI puppet controller (M19).

Replaces every vision/OCR/adb-tap mechanism of roombot with process-level
instrumentation of the genuine app, via the frida agent:

    UI element (M18)              ->  M19 replacement
    ------------------------------    ------------------------------------
    screen identification (phash)    the KGS msgid stream IS the state
                                     machine: CmdCreatejoinRoom ->
                                     CmdGetRoomInfo polling -> ready ->
                                     CmdStartGame -> result. No pixels.
    room-code OCR                    response document reconstruction:
                                     the map/string/int variant hooks
                                     rebuild every KGS response; the
                                     CreatejoinRoom doc carries the
                                     6-digit room code. First run PINS
                                     the exact field name (discovery).
    guest-join detection             GetRoomInfo response member list
                                     changes — no screen watching.
    in-match state                   MatchMain state byte [obj+0x139]
                                     (state machine 0x69917d8).
    input injection (adb taps)       the input bank singleton
                                     *(0xa417188): .trep-format records
                                     written at engine level — the same
                                     bank the game's own controller
                                     layer feeds. Write slot pinned by
                                     the bank-hunt diff tooling.

The app remains the ONLY network client (frida reads/calls in-process;
it never crafts or signs traffic). Private friendly rooms only.

SUBCOMMANDS
  observe    discovery/first run: attach, log the full KGS flow + docs +
             state candidates. Run this through one whole
             login->room->match->result cycle; it pins: room-code field,
             live MatchMain singleton, flow transitions. SAFE: read-only.
  host       the live puppet: phase machine + room-code announce on the
             peerlink channel + (post-discovery) input injection.
  bank-hunt  input-bank write-point hunt: dump/diff loop while a human
             plays on the device; the churning region = the live write
             slot; feeds agent.bankWrite().

USAGE (on the machine with the emulator; needs frida-server running on
the device and `pip install frida-tools`):
  python -m peerlink.puppet.membot observe
  python -m peerlink.puppet.membot host --serial emulator-5554
  python -m peerlink.puppet.membot bank-hunt

Menu navigation honesty: the menu taps to CREATE the room are the one
remaining UI dependency (the OnlineModeTask* activation climb is the
permanent fix; it is next in the RE queue). `host --menu-taps` will use
the M18-calibrated action points for those 4-5 taps if present —
everything after "Create Room" is fully non-UI.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

import yaml

from .channel import (MSG_HELLO, MSG_HOST_ANNOUNCE, MSG_MATCH_START,
                      MSG_MATCH_END, MSG_ABORT, make_channel)
from .roombot import AdbDevice, load_config, DEFAULT_CONFIG

AGENT = Path(__file__).resolve().parent / "frida_agent.js"
PACKAGE = "jp.konami.pesam"

# phase machine: msgid -> phase. Order matters; polls repeat.
FLOW = {
    "CmdLogin.php": "login",
    "CmdGetSessionId.php": "session",
    "CmdCreateUser.php": "account_create",
    "CmdCreatejoinRoom.php": "room_created",
    "CmdGetRoomInfo.php": "room_poll",
    "CmdSendJoinRoomRequest.php": "join_request",
    "CmdSetRoomSettings.php": "room_settings",
    "CmdSetRoomMatchReady.php": "ready",
    "CmdStartGame.php": "match_starting",
    "CmdGetTurnAddressData.php": "turn_handoff",
    "CmdGetGameSession.php": "in_match",
    "CmdCheckGameResult.php": "result_check",
    "CmdSetGameResult.php": "result_report",
    "CmdGetMatchingResult.php": "matching",
}
# docs that may carry the room code / member state
ROOM_DOCS = ("CmdCreatejoinRoom.php", "CmdGetRoomInfo.php")

ROOM_CODE_INT = re.compile(r"^\d{6}$")


def find_room_code(doc: dict):
    """Heuristic: 6-digit int or 6-digit string in a CreatejoinRoom doc.
    After the discovery run, pin the literal field name here."""
    for k, v in doc.items():
        if isinstance(v, int) and 100000 <= v <= 999999:
            return k, str(v)
        if isinstance(v, str) and ROOM_CODE_INT.match(v.strip()):
            return k, v.strip()
    return None, None


class MemBot:
    def __init__(self, channel=None, quiet=False):
        import frida  # deferred: only needed on the operator machine
        self.frida = frida
        self.channel = channel
        self.quiet = quiet
        self.phase = "boot"
        self.room_code = None
        self.room_field = None
        self.docs = []          # discovery log (observe mode)
        self.state_votes = {}   # singleton -> last state byte
        self.match_started = False

    def log(self, msg: str) -> None:
        if not self.quiet:
            print(f"[membot {time.strftime('%H:%M:%S')}] {msg}", flush=True)

    # ------------------------------------------------------------------
    def attach(self, serial: str = None):
        if serial:
            dev = self.frida.get_device(serial)
        else:
            dev = self.frida.get_usb_device(timeout=5)
        try:
            session = dev.attach(PACKAGE)
            self.log(f"attached to {PACKAGE}")
        except self.frida.ProcessNotFoundError:
            self.log("app not running — starting it via adb")
            adb = AdbDevice("emulator-5554")
            adb.launch(PACKAGE)
            time.sleep(8.0)
            session = dev.attach(PACKAGE)
            self.log("attached after launch")
        src = AGENT.read_text(encoding="utf-8")
        script = session.create_script(src)
        script.on("message", self.on_message)
        script.load()
        time.sleep(1.0)
        info = script.exports_sync.ping()
        self.log(f"agent up: {info}")
        self.script = script
        return script

    # ------------------------------------------------------------------
    def on_message(self, message, data):
        if message.get("type") == "error":
            self.log(f"AGENT ERROR: {message.get('description')}")
            return
        payload = message.get("payload") or {}
        mtype = payload.get("type")
        if mtype == "log":
            self.log(f"[agent] {payload['msg']}")
        elif mtype == "kgs_req":
            self.on_req(payload["msgid"])
        elif mtype == "kgs_doc":
            self.on_doc(payload["msgid"], payload["doc"])
        elif mtype == "state":
            prev = self.state_votes.get(payload["singleton"])
            if prev != payload["value"]:
                self.state_votes[payload["singleton"]] = payload["value"]
                self.log(f"MatchMain[{payload['singleton']}] state -> "
                         f"{payload['value']}")

    def on_req(self, msgid: str) -> None:
        phase = FLOW.get(msgid)
        if phase and phase != self.phase:
            self.log(f"flow: {msgid} -> {phase}")
            self.phase = phase
            self.on_phase(phase)

    def on_doc(self, msgid: str, doc: dict) -> None:
        self.docs.append({"msgid": msgid, "doc": doc})
        if msgid in ROOM_DOCS:
            if self.room_code is None:
                field, code = find_room_code(doc)
                if code:
                    self.room_code = code
                    self.room_field = field
                    self.log(f"ROOM CODE: {code} (field {field!r})")
                    if self.channel:
                        self.channel.send(MSG_HOST_ANNOUNCE, match_id=code)
                elif not self.quiet:
                    self.log(f"[discovery] {msgid} doc: "
                             f"{json.dumps(doc)[:300]}")
            else:
                # room poll: watch member list for the friend joining
                if self.channel and not self.match_started:
                    joined = self.doc_shows_guest(doc)
                    if joined:
                        self.match_started = True
                        self.log("GUEST JOINED (room doc change)")
                        self.channel.send(MSG_MATCH_START)
        elif not self.quiet and msgid in ("CmdSetGameResult.php",
                                           "CmdCheckGameResult.php"):
            self.log(f"[discovery] {msgid}: {json.dumps(doc)[:300]}")
            if self.channel:
                self.channel.send(MSG_MATCH_END, doc=json.dumps(doc)[:200])

    @staticmethod
    def doc_shows_guest(doc: dict) -> bool:
        """Member-count heuristics; pin the exact field after discovery."""
        for k, v in doc.items():
            lk = k.lower()
            if isinstance(v, int) and ("member" in lk or "player" in lk
                                      or "guest" in lk or "num" in lk):
                if v >= 2:
                    return True
            if isinstance(v, str) and lk.endswith("name") and v \
                    and v not in ("", "0"):
                # second non-empty name field = second member (heuristic)
                pass
        return False

    def on_phase(self, phase: str) -> None:
        if phase == "result_report" and self.channel:
            self.channel.send(MSG_MATCH_END)

    # ------------------------------------------------------------------
    def run_observe(self) -> None:
        self.log("OBSERVE mode — walk the app through one full cycle "
                 "(login -> create room -> friend joins -> match -> result)")
        self.log("Everything seen here pins the remaining fields; "
                 "the session log IS the discovery record.")
        self.channel = None  # observe = read-only, no announcements
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            self.dump_discovery()

    def run_host(self, menu_taps: bool = False, cfg: dict = None) -> None:
        self.log("HOST mode — phase machine live")
        if menu_taps:
            self.log("menu-taps fallback ENABLED (M18 calibrated points) "
                     "for the create-room taps only; everything after is "
                     "instrumentation-driven")
            self.menu_nav(cfg or {})
        try:
            while True:
                if self.phase == "result_report":
                    self.log("match over — host flow complete")
                    break
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.dump_discovery()

    def menu_nav(self, cfg: dict) -> None:
        """The honest gap: menu taps to reach 'Create Room'. Uses M18
        calibrated action points if they exist; owner can also just tap
        create-room themselves and the controller takes over from the
        CmdCreatejoinRoom msgid."""
        acts = (cfg.get("actions") or {}).get("friendly_menu") or {}
        if not acts:
            self.log("no calibrated menu points — OWNER: tap 'Friendly "
                     "Match' -> 'Create Room' on the device; the "
                     "controller picks up from the msgid stream")
            return
        adb = AdbDevice(cfg.get("device", {}).get("serial", "emulator-5554"))
        for name in ("create_room",):
            pt = acts.get(name)
            if pt:
                self.log(f"menu tap {name} @ {pt}")
                adb.tap(*pt)

    def dump_discovery(self) -> None:
        out = Path("/home/z/my-project/download/membot_discovery.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({
            "room_code": self.room_code, "room_field": self.room_field,
            "state_candidates": self.state_votes, "docs": self.docs[-80:],
        }, indent=1), encoding="utf-8")
        self.log(f"discovery record -> {out}")

    # ------------------------------------------------------------------
    def run_bank_hunt(self, interval: float = 0.25, span: int = 0x400) -> None:
        """Input-bank write-point hunt: while a HUMAN plays on the device,
        dump the bank head and diff. The churning region is the live
        write slot; report slot list + churn ranking."""
        self.log("BANK-HUNT — play on the device now (move, pass, shoot); "
                 f"diffing every {interval}s over first {span:#x} bytes")
        self.script.exports_sync.bank_watch_config(span, 8)
        prev = None
        churn: dict[int, int] = {}
        try:
            while True:
                cur = self.script.exports_sync.bank_watch_dump()
                if cur is not None:
                    cur = bytes(cur)
                    if prev is not None and len(cur) == len(prev):
                        for i in range(0, len(cur) - 8, 8):
                            if cur[i:i + 8] != prev[i:i + 8]:
                                churn[i] = churn.get(i, 0) + 1
                    prev = cur
                time.sleep(interval)
        except KeyboardInterrupt:
            pass
        top = sorted(churn.items(), key=lambda kv: -kv[1])[:20]
        print(f"\n[bank-hunt] top churn offsets (bank-relative):")
        for off, n in top:
            print(f"  +0x{off:05x}  changed {n} times")
        if top:
            print(f"\n[bank-hunt] suggested write slot: +0x{top[0][0]:05x}")
        print("[bank-hunt] feed the chosen offset to agent.bankWrite()")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="peerlink memory-path controller")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("observe", help="read-only discovery run")
    p_host = sub.add_parser("host", help="live puppet host")
    p_host.add_argument("--serial", default=None)
    p_host.add_argument("--menu-taps", action="store_true",
                        help="use M18 calibrated taps for create-room only")
    p_host.add_argument("--config", default=str(DEFAULT_CONFIG))
    p_host.add_argument("--channel", choices=["console", "udp"], default=None)
    p_host.add_argument("--udp-host", default=None)
    p_host.add_argument("--udp-port", type=int, default=42621)
    p_bank = sub.add_parser("bank-hunt", help="input-bank write-point hunt")
    p_bank.add_argument("--serial", default=None)
    p_bank.add_argument("--interval", type=float, default=0.25)
    p_bank.add_argument("--span", type=int, default=0x400)
    args = ap.parse_args(argv)

    cfg = load_config(Path(args.config)) if hasattr(args, "config") else {}
    if getattr(args, "channel", None):
        cfg.setdefault("channel", {})["mode"] = args.channel
    if getattr(args, "udp_host", None):
        cfg.setdefault("channel", {}).setdefault("udp", {})
        cfg["channel"]["udp"]["host"] = args.udp_host
        cfg["channel"]["udp"]["port"] = args.udp_port

    bot = MemBot(channel=make_channel(cfg) if args.cmd == "host" else None)
    bot.attach(getattr(args, "serial", None))
    if args.cmd == "observe":
        bot.run_observe()
    elif args.cmd == "host":
        bot.run_host(menu_taps=args.menu_taps, cfg=cfg)
    elif args.cmd == "bank-hunt":
        bot.run_bank_hunt(interval=args.interval, span=args.span)
    return 0


if __name__ == "__main__":
    sys.exit(main())
