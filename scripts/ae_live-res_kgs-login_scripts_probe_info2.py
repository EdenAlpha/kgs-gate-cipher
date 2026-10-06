"""Sweep the ONLY other hardcoded API base in the binary:
    https://info.service.konami.net/XWW020-E1/info/

Oracle (Apache): 403 dir exists / 404 missing / 200 exists & ran.
Any body that is NOT the Apache 404 page means the file is there.
"""
import socket
import ssl
import sys

HOST = "info.service.konami.net"
BASE = "/XWW020-E1/info/"
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


def req(path, method="GET", body=None, timeout=12):
    try:
        s = socket.create_connection((HOST, 443), timeout=timeout)
        ss = _ctx.wrap_socket(s, server_hostname=HOST)
        h = (f"{method} {path} HTTP/1.1\r\nHost: {HOST}\r\n"
             f"User-Agent: PES/1.0\r\nAccept: */*\r\n"
             f"Connection: close\r\n")
        b = body or b""
        if b:
            h += (f"Content-Type: application/octet-stream\r\n"
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
                srv = l.decode("utf-8", "replace").split(":", 1)[1].strip()
        return code, srv, bdy
    except Exception as e:
        return "ERR", "", str(e).encode()


def apache404(bdy):
    return b"<h1>404 Not Found</h1>" in bdy or b"404 Not Found" in bdy[:400]


def main():
    print("=" * 70)
    print("1. base path + directory tree")
    print("=" * 70)
    for p in ("/", "/XWW020-E1/", "/XWW020-E1/info/",
              "/XWW020-E1/info/index.html", "/XWW020-E1/info/index.php"):
        code, srv, bdy = req(p)
        print(f"  {code:5}  {p:34} {srv:10} {bdy[:90]!r}")

    from peerlink import kgs
    names = sorted(set(kgs.CMD.values())) + [
        "gate.php", "GateInfo.php", "ReportLog.php", "CmdGetServerEnv.php",
        "CmdLogin.php", "CmdLogout.php", "CmdRenew.php", "CmdHeartBeat.php",
        "CmdSearch.php", "CmdCheck.php", "index.php", "config.php",
        "server.php", "env.php", "info.php", "version.php",
    ]

    stems = ["gate", "config", "server", "servers", "env", "info",
             "version", "ver", "list", "title", "titles", "pes22",
             "PES2022", "efootball", "dt270", "match", "matching",
             "login", "kgs", "common", "notice", "news", "ranking",
             "index", "default", "main", "menu", "setting", "settings"]

    exts = [".json", ".txt", ".xml", ".ini", ".conf", ".yml", ".cfg",
            ".js", ".html", ".php", ""]

    print("\n" + "=" * 70)
    print("2. script names directly under the hardcoded base")
    print("=" * 70)
    hits = []
    for n in names:
        code, srv, bdy = req(BASE + n)
        interesting = (code in ("200", "403") or
                       (code == "404" and not apache404(bdy)) or
                       (bdy and not apache404(bdy) and code != "404"))
        if interesting:
            hits.append(BASE + n)
            print(f"  {code}  {BASE + n}  {srv}  body={bdy[:220]!r}")
        else:
            print(f"  {code}  {BASE + n}")

    print("\n" + "=" * 70)
    print("3. stem x extension sweep (config-file shapes)")
    print("=" * 70)
    for s in stems:
        for e in exts:
            code, srv, bdy = req(BASE + s + e)
            if code in ("200", "403") or \
               (code == "404" and not apache404(bdy)) or \
               (bdy and not apache404(bdy)):
                hits.append(BASE + s + e)
                print(f"  {code}  {BASE}{s}{e}  body={bdy[:240]!r}")

    print("\n" + "=" * 70)
    print(f"4. POST real msgpack to any hit  ({len(hits)} hits)")
    print("=" * 70)
    for h in hits:
        body = kgs.build_request(kgs.CMD["login"])
        code, srv, bdy = req(h, method="POST", body=body)
        print(f"  POST {h}\n       -> {code}  {bdy[:400]!r}")
        body = kgs.login_request()
        code, srv, bdy = req(h, method="POST", body=body)
        print(f"  POST {h} (23-field login body)\n       -> {code}  {bdy[:400]!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
