#!/usr/bin/env python3
"""redact.py -- stdin -> stdout with credential-bearing values replaced.

Rebuilt 2026-10-10 (original destroyed by temp cleanup).  Repo is public:
any output that may be pasted into chat, logs or commits must pass through
this.  Values after sensitive keys become <redacted>.

Usage:  python script.py 2>&1 | python redact.py
"""
import re
import sys

KEYS = (
    "user_id", "session_id", "auth_code", "auth_key", "auth_token",
    "account_id", "user_name", "password", "s_keyword", "sign",
)

PAT = re.compile(
    r'(?<![A-Za-z0-9_])("?(' + "|".join(KEYS) + r')"\s*[:=]\s*)'
    r'("[^"]*"|-?\d+|None|true|false)',
    re.I)

# also redact bare "sign=<token>" cookie style and long base64 runs after =
PAT2 = re.compile(r'\b(sign|auth_code|session_id|token)=([^\s;&"\'<>]+)',
                  re.I)


def sub(m):
    return m.group(1) + "<redacted>"


def main():
    for line in sys.stdin:
        line = PAT.sub(sub, line)
        line = PAT2.sub(lambda m: m.group(1) + "=<redacted>", line)
        sys.stdout.write(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
