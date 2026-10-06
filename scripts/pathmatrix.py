import socket, ssl, sys
HOST="pes22-game.cs.konami.net"
def go(path, alpn, label):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=True
    ctx.verify_mode=ssl.CERT_REQUIRED; ctx.load_default_certs()
    ctx.minimum_version=ssl.TLSVersion.TLSv1_2; ctx.maximum_version=ssl.TLSVersion.TLSv1_2
    if alpn: ctx.set_alpn_protocols(alpn)
    try:
        s=ctx.wrap_socket(socket.create_connection((HOST,443),timeout=12),server_hostname=HOST)
        req=("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: probe\r\nConnection: close\r\n\r\n"%(path,HOST)).encode()
        s.sendall(req); s.settimeout(6); buf=b""
        try:
            while len(buf)<2048:
                c=s.recv(2048)
                if not c: break
                buf+=c
        except socket.timeout: pass
        s.close()
        first=buf.split(b"\r\n",1)[0].decode("latin1","replace")
        srv=""
        for ln in buf.split(b"\r\n"):
            if ln.lower().startswith(b"server:"): srv=ln.decode("latin1","replace")
        print("  %-46s -> %-28s %s  (%dB)" % (label, first, srv, len(buf)))
    except Exception as e:
        print("  %-46s -> ERROR %s: %s" % (label, type(e).__name__, e))
print("HTTP/1.1 GET, ALPN http/1.1:")
for p,l in [("/","root /"),
            ("/health","/health"),
            ("/command_service.CommandService/CommandStream","grpc path over http/1.1"),
            ("/nonexistent-xyz","nonexistent path")]:
    go(p,["http/1.1"],l)
print("\nHTTP/2 (ALPN h2), HEADERS-only on each path, no DATA:")
import struct
def ls(x):
    b=x.encode(); return bytes([len(b)])+b
def fr(t,f,s,b): return len(b).to_bytes(3,"big")+bytes([t,f])+(s&0x7fffffff).to_bytes(4,"big")+b
for p,l in [("/","root /"),("/health","/health"),
            ("/command_service.CommandService/CommandStream","grpc path")]:
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=True
    ctx.verify_mode=ssl.CERT_REQUIRED; ctx.load_default_certs()
    ctx.minimum_version=ssl.TLSVersion.TLSv1_2; ctx.maximum_version=ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["h2"])
    try:
        s=ctx.wrap_socket(socket.create_connection((HOST,443),timeout=12),server_hostname=HOST)
        hdrs=b"\x00"+ls(":method")+ls("GET")+b"\x00"+ls(":scheme")+ls("https")+b"\x00"+ls(":path")+ls(p)+b"\x00"+ls(":authority")+ls(HOST)
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"+fr(4,0,0,b"")+fr(1,0x5,1,hdrs))
        s.settimeout(6); buf=b""
        try:
            while len(buf)<4096:
                c=s.recv(4096)
                if not c: break
                buf+=c
        except socket.timeout: pass
        s.close()
        print("  %-46s -> %dB  %s" % (l, len(buf), buf[9:57].hex() if len(buf)>9 else buf.hex()))
    except Exception as e:
        print("  %-46s -> ERROR %s: %s" % (l, type(e).__name__, e))
