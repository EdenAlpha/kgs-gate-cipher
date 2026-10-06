#!/usr/bin/env python3
"""Read the game's gRPC commands by trusting our own certificate.

Why the memory scan had to be abandoned, in numbers. Reading works -- 2 GB was
pulled cleanly from the live process with no injection -- but the pass cost is
dominated by transferring the bytes, not by parsing them:

    pass 1: read 715.9 MB, rescanned 715.94 MB in 36.10s
    pass 2: read 715.9 MB, rescanned  10.03 MB in 30.22s
    ...
    8 pass(es) over 300s, no CommandRequest found

Dirty-page tracking did what it was built to do: an unchanged pass re-examines
10 MB instead of 2 GB. But only 8 passes fit in the window, and the serialised
request lives for roughly a microsecond between the game building it and
handing it to TLS. Eight samples of a microsecond is not a search. Making the
scanner faster cannot fix that, because the ceiling is how fast memory can be
copied, and a microsecond is far below any sampling interval. The approach was
wrong, not the implementation.

So read the traffic instead. The game sends every command to Konami over TLS,
and TLS is only opaque because the game trusts a certificate authority it was
built to trust. Give the virtual phone a certificate authority of our own, put
it where Android keeps the system-trusted set, and the game will complete the
handshake with us -- sending the whole conversation in the clear, with the
command names in it.

This is the standard way to inspect an app's traffic, and here it needs no
injection, no patching, and no hooking of the game's own code. It also removes
the sampling problem entirely: a command that goes out over the wire is
captured whole, at full speed, every single time one is sent.

The route table is the goal, and this gets it directly: each request is an
HTTP/2 DATA frame carrying a CommandRequest, whose field 4 is the route.

Not implemented here: the CA install, the redirect, and the proxy. This module
is the decode half -- given the frames, hand back the command routes -- so the
capture side can be fixed independently and the parsing stays testable.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from analyse_capture import (  # noqa: E402
    PREFACE, decode_command_request, pb_fields, walk_h2,
)

__all__ = ["PREFACE", "decode_command_request", "pb_fields", "walk_h2"]


if __name__ == "__main__":
    # Reuse the existing, self-tested frame walker so there is exactly one
    # implementation of the h2 -> gRPC -> CommandRequest decode.
    print(__doc__)
    raise SystemExit(0)
