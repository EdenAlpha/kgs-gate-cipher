"""Extract every host-like literal in the image, so we know the full set of
servers the client can talk to (not just the one we already tested)."""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "apk_lab", "libUE4.so")

HOST_RE = re.compile(
    rb"(?:[a-z0-9][a-z0-9\-]{0,62}\.)+(?:konami\.(?:net|com)|konami\.ne\.[a-z]{2})"
    rb"|pes22[a-z0-9\-]*\.cs\.konami\.net"
)
URL_RE = re.compile(rb"https?://[a-z0-9\.\-]+[^\x00\s\"'<>]{0,80}")


def main():
    with open(SO, "rb") as f:
        raw = f.read()

    hosts = {}
    for m in HOST_RE.finditer(raw):
        h = m.group().decode("ascii", "replace")
        hosts.setdefault(h, []).append(m.start())

    print("=" * 70)
    print(f"HOSTNAMES in libUE4.so  ({len(hosts)} unique)")
    print("=" * 70)
    for h in sorted(hosts, key=lambda k: hosts[k][0]):
        offs = hosts[h]
        tag = ""
        if len(offs) == 1:
            tag = "   (single occurrence)"
        print(f"  {h:52} x{len(offs):<3} @ {hex(offs[0])}{tag}")

    print("\n" + "=" * 70)
    print("ABSOLUTE URLs")
    print("=" * 70)
    urls = {}
    for m in URL_RE.finditer(raw):
        u = m.group().decode("ascii", "replace").rstrip(".,;)")
        if "konami" in u or "pes" in u or "efootball" in u:
            urls.setdefault(u, []).append(m.start())
    for u in sorted(urls, key=lambda k: urls[k][0]):
        print(f"  {u}   @ {hex(urls[u][0])}")

    # host + extension adjacency (the '.txt' pattern)
    print("\n" + "=" * 70)
    print("literal immediately after each host literal (path/extension hints)")
    print("=" * 70)
    for h, offs in sorted(hosts.items(), key=lambda kv: kv[1][0]):
        for o in offs[:3]:
            seg = raw[o + len(h):o + len(h) + 24]
            nxt = seg.split(b"\x00")[0]
            if nxt and all(32 <= c < 127 for c in nxt):
                print(f"  {h}  ->  adjacent literal {nxt.decode()!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
