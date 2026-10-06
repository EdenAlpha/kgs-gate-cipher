#!/usr/bin/env python3
"""engine_binding — M20: the engine <-> app input bridge.

Closes the loop between the three proven layers:

  .trep (the game's own per-frame input stream, FINDINGS 14.2)
      the app's input bank consumes these records; the 21 tutorial
      replays in the APK give us 25,200 real samples (21 x 1,200) as
      byte-exact templates and validation oracles.

  56-int lockstep packets (peerlink/lockstep.py + engine_sim.py)
      ints[0]/ints[1] analog X/Y (-128..127), ints[2] bit0 = shoot.

  the input bank singleton *(0xa417188) in the live app (FINDINGS 14.1)
      structured write path: message queue bank+0x1BFE0 -> pump
      0x6a075b8 -> per-entity register 0x6a07d68 -> dispatcher 0x6a00e50.

This module provides:
  TrepSample        byte-exact 844-byte sample codec (parse/patch/serialize)
  TrepFile          whole-file reader (12B header + 1200 samples)
  Action synthesis  idle / move(angle, charge) / press(button) — built on
                    REAL game templates, so every other byte in the
                    record is game-authoritative
  to_engine_ints()  sample -> the 56-int lockstep packet
  from_engine_ints() 56-int packet -> sample patch
  EnginePolicy      the in-match decision loop for membot: reads a match
                    state snapshot, asks an optional predictor (the
                    Unicorn EngineSim, same original code) to score
                    candidate action sequences, emits synthesized samples
  BankWriter        pushes samples into the live app's input bank via
                    the frida agent (structured queue path preferred,
                    raw-slot fallback after bank-hunt)

Determinism contract kept: synthesis only patches the documented input
windows; everything else is copied verbatim from a real game sample, so
the record stays byte-valid for the game's own parser.
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol

# ---------------------------------------------------------------------------
# format constants (FINDINGS 14.2, verified against tutorial_replay_*.trep)

TREP_FILE_HEADER = struct.Struct("<III")     # {id, 12, 828}
N_SAMPLES = 1200
SAMPLE_HDR = 16                              # f32 1.0 time scale + 12B zeros
PAYLOAD = 828
SAMPLE = SAMPLE_HDR + PAYLOAD                # 844

# payload-relative windows (offsets inside the 828-byte payload)
W_ANALOG = 0x90                              # +144
OFF_CHARGE = 144                             # f32 0..0.644
OFF_ANGLE = 148                              # f32 0..358.067
OFF_DRIFT_A = 152                             # f32 drifting pair
OFF_SLOT_A = 156                              # u16 countdown
OFF_SLOT_B = 158                              # u16 countdown
OFF_DRIFT_B = 160                             # f32 drifting pair
OFF_BTN_STATE = 200                           # byte 0/1 PRESS
OFF_BTN_LATCH = 201                           # byte 0/1
OFF_BTN_CMD = 204                             # 4B command header (A3 00 18 00 held)
W_CAMERA = 0xD0                               # 9 floats: pos, target, fov pair
N_CAMERA = 9

DEFAULT_TUTORIALS = Path(
    "/home/z/my-project/apk_lab/cpk/dt270_out/common/match/tutorial_replay")

# the engine's 56-int packet semantics (engine_sim.py)
ENG_AX, ENG_AY, ENG_BUTTONS = 0, 1, 2
BTN_SHOOT = 1 << 0


def _f32(x: float) -> float:
    return struct.unpack("<f", struct.pack("<f", x))[0]


# ---------------------------------------------------------------------------
# sample codec


@dataclass
class TrepSample:
    raw: bytes                                          # full 844 bytes

    # ---- parsed views (payload-relative offsets above)
    @property
    def time_scale(self) -> float:
        return struct.unpack_from("<f", self.raw, 0)[0]

    @property
    def charge(self) -> float:
        return struct.unpack_from("<f", self.raw, SAMPLE_HDR + OFF_CHARGE)[0]

    @property
    def angle(self) -> float:
        return struct.unpack_from("<f", self.raw, SAMPLE_HDR + OFF_ANGLE)[0]

    @property
    def button(self) -> int:
        return self.raw[SAMPLE_HDR + OFF_BTN_STATE]

    @property
    def button_cmd(self) -> bytes:
        return self.raw[SAMPLE_HDR + OFF_BTN_CMD: SAMPLE_HDR + OFF_BTN_CMD + 4]

    @property
    def camera(self) -> tuple:
        return struct.unpack_from(f"<{N_CAMERA}f", self.raw,
                                   SAMPLE_HDR + W_CAMERA)

    # ---- construction
    @classmethod
    def from_bytes(cls, raw: bytes) -> "TrepSample":
        if len(raw) != SAMPLE:
            raise ValueError(f"sample must be {SAMPLE} bytes, got {len(raw)}")
        ts = struct.unpack_from("<f", raw, 0)[0]
        # 1.0 = normal, 0.0 = paused (switch_sides_01 uses 433 of them);
        # anything else (NaN/huge) = not a sample boundary
        if not (0.0 <= ts <= 10.0):
            raise ValueError(f"bad sample header (time scale {ts!r})")
        return cls(raw=bytes(raw))

    def to_bytes(self) -> bytes:
        return self.raw

    # ---- patching (returns a NEW sample; never mutates)
    def with_analog(self, charge: float, angle_deg: float) -> "TrepSample":
        b = bytearray(self.raw)
        struct.pack_into("<f", b, SAMPLE_HDR + OFF_CHARGE, _f32(charge))
        struct.pack_into("<f", b, SAMPLE_HDR + OFF_ANGLE, _f32(angle_deg))
        return TrepSample(bytes(b))

    def with_button(self, pressed: bool, cmd: Optional[bytes] = None) -> "TrepSample":
        b = bytearray(self.raw)
        b[SAMPLE_HDR + OFF_BTN_STATE] = 1 if pressed else 0
        b[SAMPLE_HDR + OFF_BTN_LATCH] = 1 if pressed else 0
        if pressed:
            b[SAMPLE_HDR + OFF_BTN_CMD: SAMPLE_HDR + OFF_BTN_CMD + 4] = \
                cmd or b"\xa3\x00\x18\x00"
        else:
            b[SAMPLE_HDR + OFF_BTN_CMD: SAMPLE_HDR + OFF_BTN_CMD + 4] = b"\x00" * 4
        return TrepSample(bytes(b))

    def with_camera(self, cam: tuple) -> "TrepSample":
        if len(cam) != N_CAMERA:
            raise ValueError("camera tuple must have 9 floats")
        b = bytearray(self.raw)
        struct.pack_into(f"<{N_CAMERA}f", b, SAMPLE_HDR + W_CAMERA,
                         *(_f32(v) for v in cam))
        return TrepSample(bytes(b))

    # ---- the engine bridge (56-int lockstep packet)
    def to_engine_ints(self) -> list:
        """The fields EngineSim consumes: analog X/Y from charge+angle,
        shoot bit from the button lane."""
        c = max(0.0, min(1.0, self.charge / 0.644))       # normalize to 0..1
        a = math.radians(self.angle)
        ints = [0] * 56
        ints[ENG_AX] = int(round(127.0 * c * math.cos(a)))
        ints[ENG_AY] = int(round(127.0 * c * math.sin(a)))
        if self.button:
            ints[ENG_BUTTONS] |= BTN_SHOOT
        return ints

    @classmethod
    def from_engine_ints(cls, template: "TrepSample", ints: list) -> "TrepSample":
        """Inverse: a 56-int packet patched onto a real template sample."""
        if len(ints) < 3:
            raise ValueError("engine packet needs >= 3 ints")
        ax, ay = ints[ENG_AX], ints[ENG_AY]
        mag = math.hypot(ax, ay) / 127.0
        ang = math.degrees(math.atan2(ay, ax)) % 360.0
        s = template.with_analog(_f32(mag * 0.644), _f32(ang))
        return s.with_button(bool(ints[ENG_BUTTONS] & BTN_SHOOT))


class TrepFile:
    """A whole .trep: 12B header {id, 12, 828} + 1200 x 844B samples."""

    def __init__(self, file_id: int, samples: list):
        self.file_id = file_id
        self.samples = samples

    @classmethod
    def read(cls, path) -> "TrepFile":
        d = Path(path).read_bytes()
        if len(d) != TREP_FILE_HEADER.size + N_SAMPLES * SAMPLE:
            raise ValueError(f"{path}: size {len(d)} is not the expected "
                             f"{TREP_FILE_HEADER.size + N_SAMPLES * SAMPLE}")
        fid, a, b = TREP_FILE_HEADER.unpack_from(d, 0)
        if (a, b) != (12, 828):
            raise ValueError(f"{path}: unexpected header {fid, a, b}")
        samples = [TrepSample.from_bytes(d[TREP_FILE_HEADER.size + i * SAMPLE:
                                           TREP_FILE_HEADER.size + (i + 1) * SAMPLE])
                   for i in range(N_SAMPLES)]
        return cls(fid, samples)

    def idle_template(self) -> TrepSample:
        """First fully-idle sample (analog+button zeroed) — the synthesis
        base. Falls back to sample 0."""
        for s in self.samples:
            if s.charge == 0.0 and s.angle == 0.0 and s.button == 0:
                return s
        return self.samples[0]


# ---------------------------------------------------------------------------
# action synthesis (on a real game template)


@dataclass
class Action:
    kind: str                                  # idle | move | shoot | pass
    angle_deg: float = 0.0                     # movement direction
    charge: float = 0.0                         # 0..1 (scaled to 0..0.644)
    frames: int = 1                             # how many samples to emit

    def render(self, template: TrepSample) -> list:
        if self.kind == "idle":
            return [template] * self.frames
        if self.kind == "move":
            s = template.with_analog(_f32(self.charge * 0.644),
                                     _f32(self.angle_deg % 360.0))
            return [s] * self.frames
        if self.kind == "shoot":
            # charge up (analog burst), then the button press on the last frame
            seq = []
            for i in range(max(1, self.frames - 1)):
                seq.append(template.with_analog(_f32(self.charge * 0.644),
                                                _f32(self.angle_deg % 360.0)))
            seq.append(template.with_analog(_f32(self.charge * 0.644),
                                             _f32(self.angle_deg % 360.0))
                        .with_button(True))
            return seq
        if self.kind == "pass":
            s = template.with_button(True, cmd=b"\x00\x00\x18\x00")
            return [s] * self.frames
        raise ValueError(f"unknown action kind {self.kind!r}")


def render_plan(template: TrepSample, actions: list) -> list:
    out: list = []
    for a in actions:
        out.extend(a.render(template))
    return out


# ---------------------------------------------------------------------------
# the in-match policy


@dataclass
class MatchSnapshot:
    """One observation of the live app's match state (from the frida
    reader once discovery pins the ball/player offsets; fields the
    engine predictor needs)."""
    tick: int = 0
    ball_pos: tuple = (0.0, 0.0, 0.0)
    own_pos: tuple = (0.0, 0.0, 0.0)
    possessing: bool = False
    score_own: int = 0
    score_opp: int = 0


class Predictor(Protocol):
    """Optional: the Unicorn EngineSim as an action scorer. Interface:
    score(snapshot, action_seq) -> float (higher = better predicted
    outcome). Implementations wrap scripts/engine_twinrun-style runs."""
    def score(self, snapshot: "MatchSnapshot", actions: list) -> float: ...


class EnginePolicy:
    """membot's in-match brain.

    Without a predictor: a safe heuristic fallback (hold possession,
    clear under pressure, shoot inside range) — keeps the loop running
    end-to-end before the engine predictor is attached.
    With a predictor: candidate action sequences are scored by the
    ORIGINAL code (the same engine the match runs), best sequence wins.
    """

    SHOOT_RANGE = 25.0          # meters, heuristic
    CLEAR_RANGE = 70.0

    def __init__(self, template: TrepSample, predictor=None):
        self.template = template
        self.predictor = predictor

    def decide(self, snap: MatchSnapshot) -> list:
        if self.predictor is not None:
            return self._search(snap)
        return self._heuristic(snap)

    # -- heuristic fallback -------------------------------------------------
    def _heuristic(self, s: MatchSnapshot) -> list:
        if not s.possessing:
            return [Action("idle", frames=3)]
        dist = math.hypot(s.own_pos[0] - s.ball_pos[0],
                          s.own_pos[1] - s.ball_pos[1])
        if dist < self.SHOOT_RANGE:
            ang = math.degrees(math.atan2(-s.own_pos[1], -s.own_pos[0])) % 360
            return [Action("shoot", angle_deg=ang, charge=0.9, frames=10)]
        ang = math.degrees(math.atan2(-s.own_pos[1], -s.own_pos[0])) % 360
        return [Action("move", angle_deg=ang, charge=0.8, frames=6)]

    # -- engine-scored search -------------------------------------------------
    CANDIDATES = (
        [Action("idle", frames=3)],
        [Action("move", 0.0, 0.8, 6)],
        [Action("move", 90.0, 0.8, 6)],
        [Action("move", 180.0, 0.8, 6)],
        [Action("move", 270.0, 0.8, 6)],
        [Action("shoot", 315.0, 0.9, 10)],
        [Action("shoot", 0.0, 0.9, 10)],
        [Action("shoot", 45.0, 0.9, 10)],
        [Action("pass", frames=2)],
    )

    def _search(self, s: MatchSnapshot) -> list:
        best, best_score = self.CANDIDATES[0], -1e18
        for cand in self.CANDIDATES:
            sc = self.predictor.score(s, cand)
            if sc > best_score:
                best, best_score = cand, sc
        return best


# ---------------------------------------------------------------------------
# the app-side writer


class BankWriter:
    """Pushes synthesized samples into the live app's input bank.

    Two paths (both go through the frida agent):
      queue (preferred, FINDINGS 15.3): the bank message queue at
        bank+0x1BFE0 -> pump 0x6a075b8 -> per-entity register ->
        dispatcher 0x6a00e50. Needs the wrap format pinned by the
        discovery run (observe a real controller message first).
      slot (fallback): raw write at a bank-relative offset found by
        bank-hunt. Works, but bypasses the game's own queue plumbing.
    """

    def __init__(self, script):
        self.script = script                # frida script handle
        self.mode = "slot"                   # upgraded to "queue" post-discovery
        self.slot_off = None                 # from bank-hunt
        self.queue_off = 0x1BFE0

    def configure(self, mode: str, slot_off: Optional[int] = None) -> None:
        if mode not in ("slot", "queue"):
            raise ValueError(mode)
        self.mode, self.slot_off = mode, slot_off

    def write_sample(self, sample: TrepSample) -> bool:
        raw = sample.to_bytes()
        if self.mode == "slot":
            if self.slot_off is None:
                raise RuntimeError("slot mode needs a bank-hunt offset")
            return self.script.exports_sync.bank_write(
                self.slot_off, raw.hex())
        return self.script.exports_sync.bank_write(
            self.queue_off, raw.hex())

    def write_plan(self, plan: list) -> int:
        n = 0
        for s in plan:
            if self.write_sample(s):
                n += 1
        return n


# ---------------------------------------------------------------------------
# validation


def validate_corpus(root: Path = DEFAULT_TUTORIALS) -> dict:
    """Structure + semantic checks over all 21 tutorial .trep files.
    Reproduces the FINDINGS 14.2 timing claim (shooting_02: analog burst
    before the ball launches) as an offset-oracle."""
    root = Path(root)
    files = sorted(root.glob("*.trep"))
    out = {"files": len(files), "ok": 0, "timing_oracle": None, "errors": []}
    for p in files:
        try:
            tf = TrepFile.read(p)
            # plausible time scales only (1.0 normal, 0.0 paused)
            scales = {s.time_scale for s in tf.samples}
            assert scales <= {0.0, 1.0}, f"unexpected time scales {scales}"
            active = [i for i, s in enumerate(tf.samples)
                      if s.charge > 0.0 or s.button != 0]
            if p.stem.endswith("shooting_02"):
                out["timing_oracle"] = {
                    "analog_first": active[0] if active else None,
                    "button_first": next((i for i, s in
                                          enumerate(tf.samples)
                                          if s.button != 0), None),
                    "claim": "FINDINGS 14.2: analog burst 37-49, "
                            "button 42-49, launch at .rep frame 48",
                }
            out["ok"] += 1
        except Exception as e:
            out["errors"].append(f"{p.name}: {e}")
    return out


if __name__ == "__main__":
    import json
    report = validate_corpus()
    print(json.dumps(report, indent=1))
