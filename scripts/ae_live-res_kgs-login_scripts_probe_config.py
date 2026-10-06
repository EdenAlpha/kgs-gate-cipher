"""1. Confirm what server the CS host actually is (oracle validity).
2. Sweep the newly-found live /ntl/api/config/ directory.
3. Mirror the same directory sweep on the CS host."""
import socket
import ssl
import sys

CS = "pes22-game.cs.konami.net"
NTL = "ntl.service.konami.net"

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


def req(host, path, method="GET", body=None, timeout=12):
    try:
        s = socket.create_connection((host, 443), timeout=timeout)
        ss = _ctx.wrap_socket(s, server_hostname=host)
        h = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
             f"User-Agent: PES/1.0\r\nAccept: */*\r\n"
             f"Connection: close\r\n")
        b = body or b""
        if b:
            h += (f"Content-Type: application/x-www-form-urlencoded\r\n"
                  f"Content-Length: {len(b)}\r\n")
        ss.sendall(h.encode() + b"\r\n" + b)
        data = b""
        while True:
            ch = ss.recv(65536)
            if not ch:
                break
            data += ch
            if len(data) > 40000:
                break
        ss.close()
        head, _, bdy = data.partition(b"\r\n\r\n")
        line = head.split(b"\r\n")[0].decode("utf-8", "replace")
        code = line.split(" ")[1] if " " in line else "?"
        srv = ""
        for l in head.split(b"\r\n")[1:]:
            if l.lower().startswith(b"server:"):
                srv = l.decode("utf-8", "replace")
        return code, srv, bdy
    except Exception as e:
        return "ERR", str(e), b""


def main():
    print("=" * 70)
    print("CS HOST — server identity / oracle check")
    print("=" * 70)
    for p in ("/", "/pes22/", "/pes22/", "/pes22/CmdLogin.php",
              "/pes22/config/", "/pes22/api/", "/pes22/kgs/",
              "/pes22/general/", "/config/", "/api/"):
        code, srv, bdy = req(CS, p)
        print(f"  {code:5}  {p:34} {srv}")
        if bdy and len(bdy) < 400:
            print(f"         body={bdy[:200]!r}")

    print("\n" + "=" * 70)
    print("NTL /ntl/api/config/ — file sweep")
    print("=" * 70)
    stems = ["config", "server", "servers", "env", "gate", "info", "api",
             "version", "ver", "setting", "settings", "conf", "option",
             "options", "menu", "notice", "news", "title", "titles",
             "pes22", "PES2022", "efootball", "match", "matching",
             "login", "auth", "kgs", "common", "client", "list",
             "GateInfo", "ReportLog", "index", "default", "main"]
    exts = [".php", ".json", ".xml", ".txt", ".ini", ".conf", ".yml",
            ".cfg", ".js", ".html", ".htm", ""]
    hits = []
    for s in stems:
        for e in exts:
            code, srv, bdy = req(NTL, f"/ntl/api/config/{s}{e}")
            if code in ("200", "403"):
                hits.append((f"/ntl/api/config/{s}{e}", code, bdy[:200]))
                print(f"  {code}  /ntl/api/config/{s}{e}  {bdy[:160]!r}")
    # subdirectories
    for s in stems:
        code, srv, bdy = req(NTL, f"/ntl/api/config/{s}/")
        if code in ("200", "403"):
            hits.append((f"/ntl/api/config/{s}/", code, b""))
            print(f"  {code}  /ntl/api/config/{s}/   <<< DIR")
    print(f"\n  hits: {len(hits)}")

    # the other two live dirs, same sweep
    for base in ("/ntl/api/general/", "/ntl/api/PES2022/"):
        print(f"\n  --- {base}")
        for s in ["config", "server", "servers", "env", "gate", "info",
                  "version", "list", "index", "default"]:
            for e in [".php", ".json", ".xml", ".txt", ".html", ""]:
                code, srv, bdy = req(NTL, base + s + e)
                if code in ("200", "403"):
                    print(f"    {code}  {base}{s}{e}  {bdy[:140]!r}")

    print("\n" + "=" * 70)
    print("CS HOST — directory sweep with trailing slash (403 = exists)")
    print("=" * 70)
    cands = ["config", "api", "kgs", "general", "common", "cmd", "cmds",
             "matching", "match", "room", "rooms", "game", "auth", "login",
             "p2p", "turn", "info", "env", "gate", "service", "v2", "v1",
             "intl", "mobile", "android", "online", "user", "session"]
    for d in cands:
        code, srv, bdy = req(CS, f"/pes22/{d}/")
        if code in ("200", "403"):
            print(f"  {code}  /pes22/{d}/   <<< EXISTS")
        code, srv, bdy = req(CS, f"/{d}/")
        if code in ("200", "403"):
            print(f"  {code}  /{d}/   <<< EXISTS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
