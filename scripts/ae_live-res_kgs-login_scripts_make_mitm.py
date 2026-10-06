#!/usr/bin/env python3
"""Generate the CA + a mitmproxy addon that logs eFootball's gRPC traffic.

Once the game trusts our CA (see trust_our_ca.js), mitmproxy terminates TLS
and we see the exact request. This script writes:

    ca.crt / ca.key   our root CA (also mitmproxy's own CA, reused)
    addon.py          an addon that dumps the decoded request/response bodies

mitmproxy's own CA is the one to trust: the game will validate the
certificate it MINTs for pes22-game.cs.konami.net against the CA we hand
it, and that CA is mitmproxy's ~/.mitmproxy/mitmproxy-ca-cert.pem.
"""
from __future__ import annotations

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "mitm")


ADDON = r'''
"""mitmproxy addon: dump eFootball's plaintext gRPC frames."""
import os
from mitmproxy import http

OUT = os.environ.get("KGS_DUMP", "/root/kgs-dump")
os.makedirs(OUT, exist_ok=True)

INTEREST = ("pes22-game", "konami")


def _hexdump(b, n=512):
    return b[:n].hex()


class Dump(http.HTTPFlow):
    def request(self, flow):
        host = flow.request.pretty_host or ""
        if not any(k in host for k in INTEREST):
            return
        n = len(flow.request.raw_content or b"")
        print("[KGS] REQ  %s %s  hdrs=%s  body=%dB"
              % (flow.request.method, flow.request.path,
                 dict(flow.request.headers), n), flush=True)
        if n:
            print("[KGS] REQBODY %s" % _hexdump(flow.request.raw_content),
                  flush=True)
            with open(os.path.join(OUT, "req.bin"), "wb") as f:
                f.write(flow.request.raw_content)
        with open(os.path.join(OUT, "req_meta.txt"), "w") as f:
            f.write("%s %s %s\n%s\n" % (flow.request.method,
                                        flow.request.pretty_host,
                                        flow.request.path,
                                        flow.request.http_version))

    def response(self, flow):
        host = flow.request.pretty_host or ""
        if not any(k in host for k in INTEREST):
            return
        n = len(flow.response.raw_content or b"")
        print("[KGS] RESP %s  hdrs=%s  body=%dB"
              % (flow.response.status_code,
                 dict(flow.response.headers), n), flush=True)
        if n:
            print("[KGS] RESPBODY %s" % _hexdump(flow.response.raw_content),
                  flush=True)
            with open(os.path.join(OUT, "resp.bin"), "wb") as f:
                f.write(flow.response.raw_content)
'''


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "addon.py"), "w") as f:
        f.write(ADDON)
    print("wrote", os.path.join(OUT, "addon.py"))
    print("\nRun:")
    print("  mitmdump -p 8080 -s %s --set "
          "confdir=%s/.mitmproxy" % (os.path.join(OUT, "addon.py"), OUT))
    print("\nThe game must be pointed at the proxy AND trust mitmproxy's CA:")
    print("  ~/.mitmproxy/mitmproxy-ca-cert.pem  ->  copy to the device as")
    print("  /data/local/tmp/mitm-ca.pem (that is what trust_our_ca.js points")
    print("  the game's Def_Online_gRPC_debug_root_ca at).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
