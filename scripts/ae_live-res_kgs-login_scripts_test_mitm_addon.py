#!/usr/bin/env python3
"""Self-test mitm_addon.py with fake flows (no mitmproxy needed).

The addon only touches five attributes, so fakes are faithful: pretty_host,
method, path, content, and response.status_code. What must hold:

  * ADDON-READY is written on load -- without it, an empty log later is
    ambiguous between "addon never loaded" and "no traffic".
  * a Konami request AND its response are dumped as hex, complete.
  * a non-Konami host is recorded as HOST-SEEN but its body is NOT dumped.
  * a broken flow (content raises) is recorded as ADDON-ERROR and does not
    kill the addon -- the next flow still logs.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TMP = tempfile.mkdtemp(prefix="addontest_")
os.environ["FLOWS_LOG"] = os.path.join(TMP, "flows.log")

import mitm_addon as A  # noqa: E402


class Req:
    def __init__(self, host, method="POST", path="/x", body=b""):
        self.pretty_host = host
        self.method = method
        self.path = path
        self.content = body


class Resp:
    def __init__(self, status=200, body=b""):
        self.status_code = status
        self.content = body


class Flow:
    def __init__(self, req, resp=None):
        self.request = req
        self.response = resp


class BadReq:
    # Fails AFTER the target check (pretty_host is fine, content explodes),
    # which is the only way the error path can trigger -- _host() already
    # swallows failures from pretty_host itself.
    pretty_host = "pes22-game.cs.konami.net"
    method = "POST"
    path = "/z"

    @property
    def content(self):
        raise RuntimeError("boom")


def fire(fn, flow):
    """Mirror mitmproxy's event order: headers first, then request/response."""
    if fn in (A.request, A.response):
        A.requestheaders(flow)
    fn(flow)


def main() -> int:
    A.load(None)

    body = b"\x00\x00\x00\x05hello"
    fire(A.request, Flow(Req("pes22-game.cs.konami.net",
                           path="/command_service.CommandService/CommandStream",
                           body=body)))
    fire(A.response, Flow(Req("pes22-game.cs.konami.net",
                           path="/command_service.CommandService/CommandStream"),
                        Resp(200, b"\x00\x00\x00\x03bye")))
    fire(A.request, Flow(Req("connectivitycheck.gstatic.com",
                             path="/generate_204")))
    fire(A.request, Flow(Req("pes22-game.cs.konami.net", path="/x")))
    fire(A.request, Flow(Req("pes22-game.cs.konami.net", path="/y")))
    # poison the request object, then confirm the addon survives it
    f = Flow(BadReq())
    fire(A.request, f)
    fire(A.request, Flow(Req("pes22-game.cs.konami.net", path="/after",
                           body=b"\x00")))

    text = open(os.environ["FLOWS_LOG"], encoding="utf-8").read()
    print(text)

    checks = [
        ("ADDON-READY", "ADDON-READY" in text),
        ("REQ line", "### REQ POST /command_service.CommandService/CommandStream"
         in text),
        ("REQHEX complete", "REQHEX: " + body.hex() in text),
        ("RESP line", "### RESP POST /command_service.CommandService/CommandStream -> 200"
         in text),
        ("RESPHEX complete", "RESPHEX: 00000003627965" in text),
        ("non-target host seen", "HOST-SEEN: connectivitycheck.gstatic.com"
         in text),
        ("non-target body absent", "generate_204" not in
         text.replace("HOST-SEEN: connectivitycheck.gstatic.com", "")),
        ("ADDON-ERROR recorded", "ADDON-ERROR request:" in text),
        ("survived the poison", "/after" in text),
    ]
    fail = 0
    for name, ok in checks:
        print("  %-22s %s" % (name, "ok" if ok else "FAIL"))
        fail += 0 if ok else 1
    print("\nSELF-TEST: %s" % ("PASS" if fail == 0 else "FAIL (%d)" % fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
