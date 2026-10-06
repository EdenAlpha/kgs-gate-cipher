#!/usr/bin/env python3
"""Find gRPC metadata / header key strings in libUE4.so.

The game's gRPC client attaches metadata (header names) to every call. If the
ALB routes on one of those, missing it explains a uniform 502 while the phone
works. Print header-like strings with their file offsets, plus any that look
konami/efootball specific.
"""
from __future__ import annotations

import re
import sys

SO = (r"C:\Users\Administrator\Documents\Default Project"
      r"\peerlink-efootball-disconnects\efootball-apk\native\lib\arm64-v8a"
      r"\libUE4.so")

# header-ish: lowercase, digits, dashes, 3..30 chars, contains a dash
HDR = re.compile(rb"\b([a-z][a-z0-9]*(?:-[a-z0-9]+){1,5})\b\x00")
# things that are clearly not headers
NOT = re.compile(
    r"(__(c|py|init|main)|"
    r"(utf|ascii|latin|iso-|sha|md5|aes|rsa|ecdsa|pbkdf|"
    r"coop|multiplayer|single|master|"
    r"gamepad|joystick|keyboard|mouse|"
    r"default|custom|random|global|"
    r"true|false|null|none|void|auto|new|delete|"
    r"\.so$|\.cpp$|\.h$|\.java$|\.kt$|\.php$|\.xml$|\.png$))",
    re.I)
ALLOW_EXPLICIT = re.compile(
    r"^(te|grpc-[a-z-]+|grpc|accept|content-type|content-length|user-agent|"
    r"authorization|x-[a-z0-9-]+|host|connection|keep-alive|"
    r"device|platform|region|locale|country|title|version|session|token|"
    r"uid|user-id|client|api|env|trace|request-id|x_|[a-z]+_id)$", re.I)


def main() -> int:
    data = open(SO, "rb").read()
    seen = {}
    for m in HDR.finditer(data):
        s = m.group(1).decode()
        if NOT.search(s):
            continue
        if not (ALLOW_EXPLICIT.match(s) or "-" in s):
            continue
        seen.setdefault(s, m.start())

    print("total header-like strings:", len(seen))
    # group: explicit protocol headers first
    proto = [s for s in seen if s.startswith(("grpc", "te", "content-", "user-",
                                              "accept", "authoriz", "host"))]
    xhdr = [s for s in seen if s.startswith("x-")]
    print("\n== protocol headers ==")
    for s in sorted(proto):
        print("   %-34s @%#x" % (s, seen[s]))
    print("\n== x- headers (%d) ==" % len(xhdr))
    for s in sorted(xhdr):
        print("   %-34s @%#x" % (s, seen[s]))
    print("\n== dashed, non-protocol, plausible metadata (%d) ==" % len(seen))
    rest = [s for s in seen if s not in proto and s not in xhdr]
    for s in sorted(rest):
        if any(k in s for k in ("id", "token", "key", "auth", "session", "code",
                                "device", "platform", "region", "locale",
                                "version", "title", "env", "trace", "sign",
                                "nonce", "hash")):
            print("   %-44s @%#x" % (s, seen[s]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
