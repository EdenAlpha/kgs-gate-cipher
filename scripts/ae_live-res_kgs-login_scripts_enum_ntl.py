"""Enumerate the LIVE Apache script tree under ntl.service.konami.net.

Oracle on this host:
    <dir>/  -> 403  directory exists (no index, autoindex off)
              -> 200 directory exists (has index)
              -> 404 directory does NOT exist
    <file>  -> 403  file exists, forbidden
              -> 200 script/file exists and ran
              -> 404 no such file
"""
import socket
import ssl
import sys
import time

HOST = "ntl.service.konami.net"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

_cache = {}


def get(path, timeout=10, raw=None):
    if path in _cache:
        return _cache[path]
    try:
        s = socket.create_connection((HOST, 443), timeout=timeout)
        ss = ctx.wrap_socket(s, server_hostname=HOST)
        method = raw is not None and "POST" or "GET"
        req = (f"{method} {path} HTTP/1.1\r\nHost: {HOST}\r\n"
               f"User-Agent: PES/1.0\r\nAccept: */*\r\n"
               f"Connection: close\r\n")
        body = b""
        if raw is not None:
            body = raw
            req += f"Content-Type: application/x-www-form-urlencoded\r\n" \
                   f"Content-Length: {len(body)}\r\n"
        ss.sendall(req.encode() + b"\r\n" + body)
        data = b""
        while True:
            ch = ss.recv(65536)
            if not ch:
                break
            data += ch
            if len(data) > 60000:
                break
        ss.close()
        line = data.split(b"\r\n")[0].decode("utf-8", "replace")
        code = line.split(" ")[1] if " " in line else "?"
        bdy = data.partition(b"\r\n\r\n")[2]
        out = (code, bdy, data)
    except Exception as e:
        out = (f"ERR", str(e).encode(), b"")
    _cache[path] = out
    return out


DIRS = [
    "general", "PES2022", "pes22", "pes", "pes2022", "matching", "match",
    "kgs", "login", "auth", "room", "rooms", "game", "games", "cmd",
    "cmds", "api2", "service", "gateway", "gate", "common", "util",
    "log", "logs", "report", "news", "ranking", "rank", "shop", "myclub",
    "tour", "event", "events", "config", "conf", "env", "info",
    "efootball", "online", "server", "servers", "p2p", "turn", "stun",
    "session", "user", "users", "account", "notice", "bulletin",
    "asset", "assets", "version", "ver", "check", "stat", "status",
    "XWW020-E1", "xww020-e1", "dt270", "v11", "intl", "us", "eu", "jp",
    "mobile", "android", "pc", "steam", "console", "ps", "xbox",
    "general/PES2022", "general/pes22", "general/common",
]

CMD_NAMES = [
    "GateInfo.php", "ReportLog.php",
    "CmdLogin.php", "CmdGetKgsGuestLoginToken.php", "CmdCreateUser.php",
    "CmdGetSessionId.php", "CmdCreatejoinRoom.php", "CmdGetRoomInfo.php",
    "CmdSendJoinRoomRequest.php", "CmdSetRoomSettings.php",
    "CmdSetRoomMatchReady.php", "CmdStartGame.php",
    "CmdGetTurnAddressData.php", "CmdGetGameSession.php",
    "CmdCheckGameResult.php", "CmdSetGameResult.php",
    "CmdGetMatchingResult.php", "CmdGetMyclubTutorial.php",
    "CmdSetMyclubTutorial.php", "CmdGetServerEnv.php", "CmdLogout.php",
    "CmdRenew.php", "CmdHeartBeat.php", "CmdSearch.php",
]


def main():
    print("=" * 70)
    print(f"DIRECTORY ENUMERATION  (host {HOST})")
    print("=" * 70)
    alive = []
    for d in sorted(set(DIRS)):
        code, bdy, _ = get(f"/ntl/api/{d}/")
        if code in ("200", "403"):
            alive.append(d)
            print(f"  {code}  /ntl/api/{d}/   <<< EXISTS")

    print(f"\n  live directories: {len(alive)}")

    # add the ones we know exist
    for d in ("", "PES2022", "general"):
        if d and d not in alive:
            alive.append(d)

    print("\n" + "=" * 70)
    print("SCRIPT SWEEP across live directories")
    print("=" * 70)
    hits = []
    for d in sorted(set(alive)):
        base = f"/ntl/api/{d}/" if d else "/ntl/api/"
        for n in CMD_NAMES:
            code, bdy, raw = get(base + n)
            if code in ("200", "403"):
                hits.append(base + n)
                print(f"  {code}  {base + n}   body={bdy[:200]!r}")
    print(f"\n  hits: {len(hits)}")
    for h in hits:
        print("   ", h)

    # also: does the ReportLog endpoint accept a POST?
    print("\n" + "=" * 70)
    print("POST sanity check to the confirmed live script")
    print("=" * 70)
    code, bdy, _ = get("/ntl/api/general/ReportLog.php",
                       raw=b"a=b")
    print(f"  POST /ntl/api/general/ReportLog.php -> {code} {bdy[:300]!r}")
    code, bdy, _ = get("/ntl/api/general/ReportLog.php")
    print(f"  GET  /ntl/api/general/ReportLog.php -> {code} {bdy[:300]!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
