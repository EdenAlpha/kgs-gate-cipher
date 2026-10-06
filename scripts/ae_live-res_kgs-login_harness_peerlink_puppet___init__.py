"""PeerLink puppet path — drive the untouched eFootball app.

See roombot.py for the harness, calibrate.py for the reference-capture
tool, config/efootball.yaml for the per-device configuration.
"""
from .roombot import (  # noqa: F401
    AdbDevice, Vision, RoomBot, BotAbort, BotDone,
    ConsoleChannel, UdpChannel, IdlePolicy, VisionStateSource, AdbInputSink,
)
