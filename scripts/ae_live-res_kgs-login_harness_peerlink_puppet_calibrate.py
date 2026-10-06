#!/usr/bin/env python3
"""calibrate — build the reference set roombot identifies screens by.

Run this while manually walking the app through every phase on YOUR
device (labels in brackets are the ones roombot's handlers route on):

    [title]  ->  [login_dialog] (log the throwaway in)  ->  [data_download]
    ->  [tutorial] (finish onboarding once)  ->  [main_menu]
    ->  [friendly_menu]  ->  create room  ->  [room_lobby]  (Match ID visible)
    ->  [match_setup]  ->  [in_match]  ->  [match_end]
    (also capture any [error_dialog] / popup you encounter)

Per screen you record:
  * the reference frame itself      refs/<label>/<n>.png
  * optional OCR text markers        states.<label>.markers   (identification aid)
  * action tap points                actions.<label>.<name>   (what roombot taps)
  * optional regions                 regions.<name> = [x,y,w,h] (room_code!)

Then VERIFY live:
    python -m peerlink.puppet.calibrate --serial X --verify
  flip through the same screens and watch the identifier track them.

TIP: capture 2-3 refs per screen (animations shift the hash slightly);
keep the device in ONE orientation; re-run if you change resolution.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import cv2
import yaml

try:
    import pytesseract
    from PIL import Image
except ImportError:
    pytesseract = None

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))  # peerlink_restored/ on sys.path

from peerlink.puppet.roombot import (  # noqa: E402
    AdbDevice, Vision, DEFAULT_CONFIG, DEFAULT_REFS,
)

STATE_LABELS = (
    "title", "login_dialog", "data_download", "tutorial",
    "main_menu", "friendly_menu", "room_lobby",
    "match_setup", "in_match", "match_end", "error_dialog",
)


def load_or_default(config_path: Path) -> dict:
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {"app": {"package": "jp.konami.pesam"}}


def save_config(config_path: Path, cfg: dict) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=True)
    print(f"[calibrate] config saved -> {config_path}")


def capture_mode(adb: AdbDevice, refs_dir: Path, cfg: dict) -> None:
    print("\n=== capture mode ===")
    print("walk the app on the device; here, label each screen you park on.")
    print(f"labels roombot routes on: {', '.join(STATE_LABELS)}\n")
    while True:
        try:
            label = input("state label ('quit' to finish): ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not label or label == "quit":
            break
        if label not in STATE_LABELS:
            print(f"  note: '{label}' is not a handler label — captured "
                  f"anyway (usable for future handlers)")
        frame = adb.screencap()
        state_dir = refs_dir / label
        state_dir.mkdir(parents=True, exist_ok=True)
        n = len(list(state_dir.glob("*.png"))) + 1
        out = state_dir / f"{n}.png"
        cv2.imwrite(str(out), frame)
        print(f"  saved {out}")

        # OCR preview so picking text markers is easy
        if pytesseract is not None:
            try:
                pil = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
                text = " ".join(pytesseract.image_to_string(pil).split())[:160]
                print(f"  OCR preview: {text!r}")
            except Exception as e:
                print(f"  (ocr preview failed: {e})")
        else:
            print("  (tesseract not installed — markers unavailable)")

        mk = input("  text markers, comma-sep (blank = none): ").strip()
        if mk:
            cfg.setdefault("states", {}).setdefault(label, {})["markers"] = [
                m.strip() for m in mk.split(",") if m.strip()]

        while True:
            ap = input("  action 'name=x,y' (blank = done): ").strip()
            if not ap:
                break
            try:
                name, xy = ap.split("=")
                x, y = (int(v) for v in xy.split(","))
                cfg.setdefault("actions", {}).setdefault(label, {})[name.strip()] = [x, y]
                print(f"    recorded actions.{label}.{name.strip()} = [{x}, {y}]")
            except ValueError:
                print("    parse error — format is name=x,y")

        rg = input("  region 'name=x,y,w,h' (blank = none): ").strip()
        if rg:
            try:
                name, xywh = rg.split("=")
                box = [int(v) for v in xywh.split(",")]
                if len(box) == 4:
                    cfg.setdefault("regions", {})[name.strip()] = box
                    print(f"    recorded regions.{name.strip()} = {box}")
            except ValueError:
                print("    parse error — format is name=x,y,w,h")

        save_config(DEFAULT_CONFIG, cfg)


def verify_mode(adb: AdbDevice, refs_dir: Path, cfg: dict) -> None:
    print("\n=== verify mode — flip through screens, Ctrl-C to stop ===")
    vis = Vision(refs_dir, cfg)
    while True:
        frame = adb.screencap()
        state, conf = vis.identify(frame)
        if state is None:
            code = vis.extract_room_code(frame, cfg.get("regions", {}).get("room_code"))
            extra = f"  room-code OCR: {code}" if code else ""
            print(f"  UNRECOGNIZED conf={conf:.2f}{extra}", flush=True)
        else:
            print(f"  {state:16s} conf={conf:.2f}", flush=True)
        time.sleep(1.0)


def main() -> int:
    ap = argparse.ArgumentParser(description="roombot calibration tool")
    ap.add_argument("--serial", default="emulator-5554")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--refs", default=str(DEFAULT_REFS))
    ap.add_argument("--verify", action="store_true",
                    help="live identification check instead of capture")
    args = ap.parse_args()

    adb = AdbDevice(args.serial)
    refs_dir = Path(args.refs)
    cfg = load_or_default(Path(args.config))
    refs_dir.mkdir(parents=True, exist_ok=True)

    if args.verify:
        verify_mode(adb, refs_dir, cfg)
    else:
        capture_mode(adb, refs_dir, cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
