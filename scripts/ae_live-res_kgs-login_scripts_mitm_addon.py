"""mitmproxy addon: dump decrypted Konami traffic to a log.

Runs inside mitmdump on the HOST. The phone's port-443 traffic is DNATed here;
mitmproxy terminates TLS with our CA (installed in the phone's SYSTEM store)
and re-encrypts upstream to real Konami. Every request and response involving
a Konami host is appended to $FLOWS_LOG as hex, so the run can decode
CommandRequest.path offline with the existing, self-tested decoder.

Fail-loud, never fail-silent:

  * startup writes ADDON-READY. A flows.log with no ADDON-READY means the
    addon never loaded -- do not read anything else in the file as a result.
  * HOST-SEEN lines record every hostname the game contacts, bodies or not.
    If Konami hosts appear here but no ### lines follow, the TLS handshake
    failed (pinning or trust) -- which is different from "the game sent
    nothing".
  * any exception is written as ADDON-ERROR, never swallowed. The proxy must
    not die because logging did.
"""
import os
import traceback

LOG = os.environ.get("FLOWS_LOG", "/tmp/kgs/flows.log")
TARGET_SUFFIXES = ("konami.net", "konami.jp")


def _log(line):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _host(flow):
    try:
        return (flow.request.pretty_host or "").lower().split(":")[0]
    except Exception:
        return ""


def _is_target(host):
    return any(host == s or host.endswith("." + s) for s in TARGET_SUFFIXES)


SEEN = set()


def load(entry):
    _log("ADDON-READY targets=%s" % (",".join(TARGET_SUFFIXES),))


def requestheaders(flow):
    # Fires before the body arrives. Records WHERE the game talks even if the
    # handshake or the body later fails -- destination without content is
    # still evidence of an attempt.
    try:
        host = _host(flow)
        if host and host not in SEEN:
            SEEN.add(host)
            _log("HOST-SEEN: %s" % host)
    except Exception:
        pass


def request(flow):
    try:
        host = _host(flow)
        if not _is_target(host):
            return
        body = bytes(flow.request.content or b"")
        _log("### REQ %s %s" % (flow.request.method, flow.request.path))
        _log("HOST: %s" % host)
        _log("REQLEN: %d" % len(body))
        _log("REQHEX: " + body.hex())
    except Exception:
        _log("ADDON-ERROR request: "
             + traceback.format_exc(limit=3).replace("\n", " | "))


def response(flow):
    try:
        host = _host(flow)
        if not _is_target(host):
            return
        body = bytes(flow.response.content or b"")
        _log("### RESP %s %s -> %d"
             % (flow.request.method, flow.request.path,
                flow.response.status_code))
        _log("RESPLEN: %d" % len(body))
        _log("RESPHEX: " + body.hex())
    except Exception:
        _log("ADDON-ERROR response: "
             + traceback.format_exc(limit=3).replace("\n", " | "))
