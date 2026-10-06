#!/usr/bin/env python3
"""roombot — the real-client puppet harness (M18, the app path).

WHY THIS EXISTS
  The peerlink lockstep stack (transport/rooms/lockstep/session) runs the
  original eFootball engine headless under Unicorn and is proven bit-exact
  (proofs 1-6). But a stock eFootball app cannot talk to peerlink. So for
  matches against friends on their own normal apps, the bridge is the
  app itself:

    * the GENUINE eFootball app (jp.konami.pesam v11.0.1, the exact build
      our RE tree maps) runs in an Android emulator / adb device
    * its owner logs into a second/throwaway account interactively once —
      the harness never sees, types, or stores credentials
    * the app performs ALL authentication, room creation and match traffic
      on its own genuine network stack
    * this harness only (a) reads the screen, (b) injects input events,
      (c) reads the 6-digit friend-match room code off the lobby screen
      and announces it on the peerlink channel so the friend can join
    * the friend plays on their own unmodified app and account, joined by
      invitation only

STANDING CONSTRAINTS (spec, not suggestions)
  1. The genuine app is the only network client. This harness never
     crafts, signs, or replays requests to Konami services (the old M17
     headless-client path in peerlink/kgs.py is retired from the live
     flow and kept as wire-format reference only).
  2. The puppet account only ever enters private friendly rooms it
     hosts, joined by invited participants. It never queues into public
     matchmaking.
  3. Automation only: no anti-cheat / detection-evasion tooling lives
     here. Ban risk on the throwaway account is accepted by design.

DESIGN NOTES
  * Unity exposes ~nothing to uiautomator, so screen identification is
    vision: perceptual-hash reference matching, with OCR text-marker
    fallback (refs built by calibrate.py from YOUR device).
  * adb screencap costs ~0.3-0.8 s/frame — fine for menus/lobby. For
    high-rate in-match control, swap the frame source for a scrcpy/
    minicap video feed (same FrameSource interface), or better: bind a
    MemoryStateSource to the emulator process — we already hold the
    libUE4.so struct maps (ball/kick/installer addresses) from M2-M14.
  * The in-match control seam is three interfaces:
        MatchStateSource.poll() -> state dict
        Policy.decide(state, frame) -> [InputEvent]
        InputSink.apply(event)
    IdlePolicy ships first (the bot stands still) — milestone #1 is a
    friend completing a full match against it; the engine plugs in after.

RUN (after calibrate.py has built the reference set)
  python -m peerlink.puppet.roombot --serial emulator-5554
  python -m peerlink.puppet.roombot --serial X --channel udp --udp-host <friend-ip>

REQUIREMENTS: python3.10+, adb on PATH, opencv-python, numpy, pillow,
pytesseract + the tesseract-ocr binary, PyYAML.
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol

import cv2
import numpy as np
import yaml
from PIL import Image

from .channel import make_channel  # noqa: F401  (used below)

try:
    import pytesseract
except ImportError:  # marker fallback disabled; phash still works
    pytesseract = None

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "config" / "efootball.yaml"
DEFAULT_REFS = HERE / "refs"
DEFAULT_ARTIFACTS = HERE / "artifacts"

# ---------------------------------------------------------------------------
# device I/O


class AdbDevice:
    """Thin, honest adb wrapper: screencap (binary-safe), input, launch."""

    def __init__(self, serial: str):
        self.serial = serial

    def _run(self, *args: str, binary: bool = False, timeout: int = 20):
        cmd = ["adb", "-s", self.serial, *args]
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if r.returncode != 0:
            raise RuntimeError(f"adb {' '.join(args)} failed: "
                               f"{r.stderr.decode(errors='replace').strip()}")
        return r.stdout if binary else r.stdout.decode(errors="replace")

    def shell(self, cmd: str) -> str:
        return self._run("shell", cmd)

    def wake(self) -> None:
        self._run("shell", "input keyevent KEYCODE_WAKEUP")

    def launch(self, package: str) -> None:
        # monkey-launch: works without knowing the launcher activity name
        self._run("shell", f"monkey -p {package} -c "
                           f"android.intent.category.LAUNCHER 1")

    def tap(self, x: int, y: int) -> None:
        self._run("shell", f"input tap {int(x)} {int(y)}")

    def swipe(self, x1: int, y1: int, x2: int, y2: int, ms: int = 250) -> None:
        self._run("shell", f"input swipe {int(x1)} {int(y1)} "
                           f"{int(x2)} {int(y2)} {int(ms)}")

    def key(self, code: str) -> None:
        self._run("shell", f"input keyevent {code}")

    def screencap(self) -> np.ndarray:
        raw = self._run("exec-out", "screencap -p", binary=True)
        frame = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
        if frame is None:
            raise RuntimeError("screencap decode failed (device offline?)")
        return frame


# ---------------------------------------------------------------------------
# vision


def phash_bits(frame: np.ndarray) -> int:
    """64-bit DCT perceptual hash."""
    g = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    g = cv2.resize(g, (32, 32), interpolation=cv2.INTER_AREA)
    d = cv2.dct(g.astype(np.float32))[:8, :8]
    med = float(np.median(d))
    h = 0
    for bit in (d > med).flatten():
        h = (h << 1) | int(bit)
    return h


class Vision:
    """Screen identification: phash reference match + OCR marker fallback."""

    def __init__(self, refs_dir: Path, cfg: dict):
        self.threshold = float(cfg.get("identify", {}).get("phash_threshold", 0.80))
        self.marker_fallback = bool(cfg.get("identify", {}).get("marker_fallback", True))
        self.ocr_lang = cfg.get("ocr", {}).get("lang", "eng")
        self.refs: dict[str, list[int]] = {}
        self.markers: dict[str, list[str]] = {}
        self._load_refs(refs_dir)
        self._load_markers(cfg.get("states", {}))
        if not self.refs:
            raise RuntimeError(
                f"no reference screens under {refs_dir} — run calibrate.py first")

    def _load_refs(self, refs_dir: Path) -> None:
        if not refs_dir.exists():
            return
        for state_dir in sorted(refs_dir.iterdir()):
            if not state_dir.is_dir():
                continue
            for png in sorted(state_dir.glob("*.png")):
                img = cv2.imread(str(png))
                if img is None:
                    continue
                self.refs.setdefault(state_dir.name, []).append(phash_bits(img))

    def _load_markers(self, states_cfg: dict) -> None:
        for label, spec in (states_cfg or {}).items():
            mk = (spec or {}).get("markers") or []
            if mk:
                self.markers[label] = [str(m) for m in mk]

    def identify(self, frame: np.ndarray) -> tuple[Optional[str], float]:
        h = phash_bits(frame)
        best_state, best_conf = None, 0.0
        for state, hashes in self.refs.items():
            for rh in hashes:
                conf = 1.0 - (h ^ rh).bit_count() / 64.0
                if conf > best_conf:
                    best_state, best_conf = state, conf
        if best_conf >= self.threshold:
            return best_state, best_conf
        if self.marker_fallback and pytesseract is not None:
            text = self.ocr(frame).lower()
            for state, marks in self.markers.items():
                if marks and all(m.lower() in text for m in marks):
                    return state, 0.50  # marker-level confidence
        return None, best_conf

    def ocr(self, frame: np.ndarray, region: Optional[list] = None,
            whitelist: Optional[str] = None, psm: int = 6) -> str:
        if pytesseract is None:
            return ""
        img = frame
        if region:
            x, y, w, hgt = region
            img = frame[y:y + hgt, x:x + w]
        pil = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
        cfg = f"--psm {psm}"
        if whitelist:
            cfg += f" -c tessedit_char_whitelist={whitelist}"
        return pytesseract.image_to_string(pil, lang=self.ocr_lang, config=cfg)

    def extract_room_code(self, frame: np.ndarray, region: Optional[list]) -> Optional[str]:
        """6-digit friend-match room code (the game's own UX is numeric)."""
        if region:
            text = self.ocr(frame, region=region, whitelist="0123456789", psm=7)
        else:
            text = self.ocr(frame, whitelist="0123456789")
        m = re.search(r"\d{6}", text.replace(" ", "").replace("\n", ""))
        return m.group(0) if m else None


# ---------------------------------------------------------------------------
# peerlink coordination channel (shared with membot — see channel.py)

from .channel import (  # noqa: F401  (re-exported; roombot keeps them)
    MSG_HELLO, MSG_HOST_ANNOUNCE, MSG_JOIN_ACK, MSG_MATCH_START,
    MSG_MATCH_END, MSG_ABORT, ConsoleChannel, UdpChannel, make_channel,
)


# ---------------------------------------------------------------------------
# in-match control seam — the engine plugs in here


@dataclass
class InputEvent:
    kind: str                 # "tap" | "swipe"
    x: int = 0
    y: int = 0
    x2: int = 0
    y2: int = 0
    ms: int = 250


class MatchStateSource(Protocol):
    def poll(self, bot: "RoomBot", frame: np.ndarray) -> dict: ...


class Policy(Protocol):
    def decide(self, state: dict, frame: np.ndarray) -> list[InputEvent]: ...


class InputSink(Protocol):
    def apply(self, bot: "RoomBot", ev: InputEvent) -> None: ...


class VisionStateSource:
    """Minimal source: what the screen-identifier already knows.
    TODO: MemoryStateSource — read match state straight out of the emulator
    process (we hold the libUE4.so struct maps: ball, kick installer,
    setup sequencer). Same interface, ~1000x the signal."""

    def poll(self, bot: "RoomBot", frame: np.ndarray) -> dict:
        return {"screen": bot.last_state, "conf": bot.last_conf,
                "frame_w": frame.shape[1], "frame_h": frame.shape[0]}


class IdlePolicy:
    """Milestone #1 policy: the bot stands still. Proves the whole pipe —
    friend joins, match runs, full 90', result, exit. Then we plug the
    engine in and it actually plays."""

    def decide(self, state: dict, frame: np.ndarray) -> list[InputEvent]:
        return []


class AdbInputSink:
    def apply(self, bot: "RoomBot", ev: InputEvent) -> None:
        if ev.kind == "tap":
            bot.adb.tap(ev.x, ev.y)
        elif ev.kind == "swipe":
            bot.adb.swipe(ev.x, ev.y, ev.x2, ev.y2, ev.ms)


# ---------------------------------------------------------------------------
# the bot


class BotAbort(Exception):
    pass


class BotDone(Exception):
    pass


class RoomBot:
    def __init__(self, cfg: dict, serial: str,
                 refs_dir: Path = DEFAULT_REFS):
        self.cfg = cfg
        self.adb = AdbDevice(serial)
        self.vision = Vision(refs_dir, cfg)
        self.channel = make_channel(cfg)
        self.state_source: MatchStateSource = VisionStateSource()
        self.policy: Policy = IdlePolicy()
        self.input_sink: InputSink = AdbInputSink()
        self.last_state: Optional[str] = None
        self.last_conf: float = 0.0
        self._room_code: Optional[str] = None
        self._cooldown: dict[tuple, float] = {}
        self.handlers = {
            "title": self.on_title,
            "login_dialog": self.on_login_dialog,
            "data_download": self.on_data_download,
            "tutorial": self.on_tutorial,
            "main_menu": self.on_main_menu,
            "friendly_menu": self.on_friendly_menu,
            "room_lobby": self.on_room_lobby,
            "match_setup": self.on_match_setup,
            "in_match": self.on_in_match,
            "match_end": self.on_match_end,
            "error_dialog": self.on_error_dialog,
        }

    # ---- helpers ---------------------------------------------------------

    def log(self, msg: str) -> None:
        print(f"[roombot {time.strftime('%H:%M:%S')}] {msg}", flush=True)

    def fire(self, state: str, action: str, min_gap: float = 3.0) -> bool:
        """Tap a calibrated action point, rate-limited so transitions
        never trigger double-taps."""
        pt = (self.cfg.get("actions", {}).get(state, {}) or {}).get(action)
        if not pt:
            self.log(f"no calibrated action '{state}.{action}' — "
                     f"run calibrate.py to record it")
            return False
        now = time.time()
        key = (state, action)
        if now - self._cooldown.get(key, 0.0) < min_gap:
            return False
        self._cooldown[key] = now
        self.adb.tap(pt[0], pt[1])
        self.log(f"tap {state}.{action} @ {pt}")
        return True

    def artifact(self, frame: np.ndarray, tag: str) -> Path:
        DEFAULT_ARTIFACTS.mkdir(parents=True, exist_ok=True)
        p = DEFAULT_ARTIFACTS / f"{tag}_{int(time.time())}.png"
        cv2.imwrite(str(p), frame)
        return p

    def abort(self, reason: str, frame: Optional[np.ndarray] = None) -> None:
        if frame is not None:
            self.artifact(frame, "abort")
        self.channel.send(MSG_ABORT, reason=reason)
        raise BotAbort(reason)

    # ---- screen handlers (identify-driven: each reacts to the NOW screen)

    def on_title(self, frame) -> None:
        if not self.fire("title", "start"):
            h, w = frame.shape[:2]
            self.adb.tap(w // 2, int(h * 0.85))

    def on_login_dialog(self, frame) -> None:
        # CONSTRAINT: the owner logs in interactively. The harness never
        # types or stores credentials — not once, not ever.
        self.log("login screen — owner: log into the throwaway account on "
                 "the device. Harness waits.")

    def on_data_download(self, frame) -> None:
        self.log("asset download in progress — waiting")
        self.fire("data_download", "ok", min_gap=10.0)

    def on_tutorial(self, frame) -> None:
        mode = self.cfg.get("first_run", {}).get("tutorial", "manual")
        if mode == "auto":
            # scripted tap-through (best effort; the tutorial is once per
            # account and forgiving — owner can also just play it once)
            if not self.fire("tutorial", "skip", min_gap=2.0):
                if not self.fire("tutorial", "next", min_gap=2.0):
                    h, w = frame.shape[:2]
                    self.adb.tap(w // 2, int(h * 0.85))
        else:
            self.log("onboarding/tutorial — owner: finish it once on the "
                     "throwaway; harness waits (or set tutorial: auto)")

    def on_main_menu(self, frame) -> None:
        self.fire("main_menu", "friendly")

    def on_friendly_menu(self, frame) -> None:
        self.fire("friendly_menu", "create_room")

    def on_room_lobby(self, frame) -> None:
        # 1) room code (once; the ID is on screen the whole lobby phase)
        if self._room_code is None:
            for attempt in range(5):
                # fresh frame each attempt — the screen may have settled
                code = self.vision.extract_room_code(
                    self.adb.screencap(),
                    self.cfg.get("regions", {}).get("room_code"))
                if code:
                    self._room_code = code
                    self.log(f"FRIENDLY ROOM OPEN — MATCH ID: {code}")
                    self.channel.send(MSG_HOST_ANNOUNCE, match_id=code)
                    break
                self.log(f"room-code OCR miss ({attempt + 1}/5) — "
                         f"tune regions.room_code in the config")
                time.sleep(1.5)
            if self._room_code is None:
                self.artifact(frame, "roomcode_miss")
        else:
            self.channel.send(MSG_HOST_ANNOUNCE, match_id=self._room_code)

        # 2) wait for the invited friend to join (screen changes)
        deadline = time.time() + float(self.cfg.get("flow", {})
                                       .get("join_timeout_s", 600))
        reannounce = time.time() + 10.0
        while time.time() < deadline:
            frame = self.adb.screencap()
            state, conf = self.vision.identify(frame)
            if state in ("match_setup", "in_match"):
                self.log(f"friend joined (screen -> {state})")
                self.channel.send(MSG_MATCH_START)
                return
            if state == "error_dialog":
                self.abort("error dialog while waiting for guest", frame)
            if time.time() >= reannounce and self._room_code:
                self.channel.send(MSG_HOST_ANNOUNCE, match_id=self._room_code)
                reannounce = time.time() + 10.0
            time.sleep(2.0)
        self.abort("join timeout — nobody entered the match id", None)

    def on_match_setup(self, frame) -> None:
        self.fire("match_setup", "start")
        time.sleep(2.0)   # let the kickoff transition settle

    def on_in_match(self, frame) -> None:
        hz = float(self.cfg.get("match", {}).get("poll_hz", 2.0))
        self.log("match live — control seam engaged "
                 f"({self.policy.__class__.__name__})")
        idle_ticks = 0
        while True:
            frame = self.adb.screencap()
            state, conf = self.vision.identify(frame)
            if state != "in_match":
                self.log(f"leaving in_match -> {state}")
                return
            sim_state = self.state_source.poll(self, frame)
            for ev in self.policy.decide(sim_state, frame):
                self.input_sink.apply(self, ev)
            idle_ticks += 1
            if idle_ticks % 30 == 0:
                self.log(f"still in match ({idle_ticks} frames)")
            time.sleep(1.0 / hz)

    def on_match_end(self, frame) -> None:
        text = self.vision.ocr(frame)
        self.log("match finished")
        self.channel.send(MSG_MATCH_END, ocr=text.strip()[:120])
        self.fire("match_end", "continue")
        if not self.cfg.get("flow", {}).get("rematch", False):
            raise BotDone("friendly match complete")
        # else: fall through; the machine re-routes to room_lobby

    def on_error_dialog(self, frame) -> None:
        text = self.vision.ocr(frame)
        self.artifact(frame, "error_dialog")
        self.abort(f"error dialog: {text.strip()[:120]!r}", None)

    # ---- main loop -------------------------------------------------------

    def run(self, max_runtime_s: float = 7200.0) -> None:
        ident = self.cfg.get("identify", {})
        poll = float(ident.get("poll_interval", 0.7))
        miss_max = int(ident.get("miss_max", 6))
        back_after = int(ident.get("back_recovery", 3))
        self.adb.wake()
        self.adb.launch(self.cfg.get("app", {}).get("package", "jp.konami.pesam"))
        self.log("app launched — puppet harness running")
        self.channel.send(MSG_HELLO, who="roombot")
        misses = 0
        t_end = time.time() + max_runtime_s
        while time.time() < t_end:
            try:
                frame = self.adb.screencap()
            except RuntimeError as e:
                self.log(f"screencap failed: {e} — retrying")
                time.sleep(2.0)
                continue
            state, conf = self.vision.identify(frame)
            self.last_state, self.last_conf = state, conf
            if state is None:
                misses += 1
                self.log(f"screen unrecognized (conf={conf:.2f}, miss {misses})")
                if misses == back_after:
                    self.log("recovery: BACK key")
                    self.adb.key("KEYCODE_BACK")
                if misses >= miss_max:
                    p = self.artifact(frame, "unknown_screen")
                    self.abort(f"lost the thread after {miss_max} misses "
                               f"(artifact: {p.name})", None)
                time.sleep(poll)
                continue
            misses = 0
            self.log(f"screen={state} conf={conf:.2f}")
            handler = self.handlers.get(state)
            if handler is None:
                self.log(f"no handler for '{state}' (reference-only label) — waiting")
            else:
                handler(frame)
            time.sleep(poll)
        self.abort("max runtime reached", None)


# ---------------------------------------------------------------------------


def load_config(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    return cfg


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="peerlink puppet harness")
    ap.add_argument("--serial", default=None, help="adb device serial")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--refs", default=str(DEFAULT_REFS))
    ap.add_argument("--channel", choices=["console", "udp"], default=None)
    ap.add_argument("--udp-host", default=None, help="friend's peerlink addr")
    ap.add_argument("--udp-port", type=int, default=42621)
    ap.add_argument("--max-runtime", type=float, default=7200.0)
    args = ap.parse_args(argv)

    cfg = load_config(Path(args.config))
    if args.serial:
        cfg.setdefault("device", {})["serial"] = args.serial
    if args.channel:
        cfg.setdefault("channel", {})["mode"] = args.channel
    if args.udp_host:
        cfg.setdefault("channel", {}).setdefault("udp", {})
        cfg["channel"]["udp"]["host"] = args.udp_host
        cfg["channel"]["udp"]["port"] = args.udp_port

    serial = cfg.get("device", {}).get("serial", "emulator-5554")
    bot = RoomBot(cfg, serial, refs_dir=Path(args.refs))
    try:
        bot.run(max_runtime_s=args.max_runtime)
    except BotDone as e:
        print(f"[roombot] DONE: {e}", flush=True)
        return 0
    except BotAbort as e:
        print(f"[roombot] ABORT: {e}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
