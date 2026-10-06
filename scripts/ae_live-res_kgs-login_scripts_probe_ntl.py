"""Read the bodies that came back 200 on the NTL host, then sweep the live
script directory for the real command names."""
import socket
import ssl
import sys

HOST = "ntl.service.konami.net"


def req(path, host=HOST, body=None, method=None, timeout=15, show=2400):
    if body is None:
        method = method or "GET"
        payload = b""
    else:
        method = method or "POST"
        payload = body
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = socket.create_connection((host, 443), timeout=timeout)
    ss = ctx.wrap_socket(s, server_hostname=host)
    hdr = (f"{method} {path} HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"User-Agent: PES/1.0\r\n"
           f"Accept: */*\r\n"
           f"Connection: close\r\n")
    if payload:
        hdr += (f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {len(payload)}\r\n")
    ss.sendall(hdr.encode() + b"\r\n" + payload)
    data = b""
    try:
        while True:
            ch = ss.recv(65536)
            if not ch:
                break
            data += ch
            if len(data) > 200000:
                break
    except Exception:
        pass
    ss.close()
    head, _, bdy = data.partition(b"\r\n\r\n")
    line = head.split(b"\r\n")[0].decode("utf-8", "replace")
    return line, head, bdy


def show(label, line, head, bdy):
    print(f"\n--- {label}")
    print(f"    {line}")
    keys = [l for l in head.split(b"\r\n")[1:]
            if l.lower().startswith(
                (b"content-type", b"content-length", b"location",
                 b"server", b"allow"))]
    for k in keys:
        print(f"    {k.decode('utf-8','replace')}")
    txt = bdy[:900].decode("utf-8", "replace")
    print("    BODY:")
    for ln in txt.splitlines()[:34]:
        print(f"      {ln}")


def main():
    # 1. the live directories
    for p in ("/", "/ntl/", "/ntl/api/", "/ntl/api/PES2022/",
              "/ntl/api/index.html", "/ntl/api/PES2022/index.html",
              "/ntl/api/index.php"):
        try:
            show(f"GET {p}", *req(p)[:3])
        except Exception as e:
            print(f"\n--- GET {p}\n    ERR {e}")

    # 2. command names under the live NTL script dir
    names = ["GateInfo.php", "CmdLogin.php", "CmdAuth.php",
             "CmdGetServerEnv.php", "CmdCheck.php", "CmdMatchOff.php",
             "CmdRegist.php", "CmdRenew.php", "CmdLogout.php",
             "CmdSession.php", "CmdHeartBeat.php", "CmdSearch.php",
             "Login.php", "auth.php", "index.php"]
    bases = ["/ntl/api/", "/ntl/api/PES2022/"]
    print("\n" + "=" * 64)
    print("SWEEP: script names on the LIVE NTL host")
    print("=" * 64)
    for b in bases:
        for n in names:
            try:
                line, head, bdy = req(b + n, show=0)
                code = line.split(" ")[1] if " " in line else "?"
                note = ""
                if code == "200":
                    note = "  <<< 200"
                elif b"File not found" in bdy:
                    note = "  (php-fpm: script missing)"
                elif code == "404":
                    note = "  (nginx 404)"
                print(f"  {code}  {b + n}{note}")
                if code == "200":
                    show(f"GET {b + n}", line, head, bdy)
            except Exception as e:
                print(f"  ERR {b + n}: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
