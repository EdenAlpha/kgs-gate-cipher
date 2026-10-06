"""netsplice — M21: a real network line for the headless game.

The game's online stack (static libcurl + OpenSSL inside libUE4.so)
talks to the internet through normal libc socket imports. Under our
Unicorn harness those imports are ours to service — so we service them
with REAL Python sockets:

    game's socket()   ->  real Python socket
    game's connect()  ->  real TCP connect to the real host
    game's sendto()   ->  real bytes on the wire
    game's recvfrom() ->  real server response into game memory

The game's own code then does everything else by itself: DNS-shape
handling, TLS handshake + crypto, msgpack bodies, RSA signing, KGS
flow. Nothing is forged, nothing is reimplemented — the same native
code a real app runs, now with a wire.

Self-test (this file's __main__): resolve + connect + HTTP GET to the
NTL host THROUGH the game's own PLT surface, then run the online-config
registrars and dump the live config — everything the game needs to go
online, in one place.

Usage:
    python -m peerlink.netsplice            # full self-test
"""
from __future__ import annotations

import errno as _pyerrno
import os
import select as _pyselect
import socket as _pysock
import struct
import time

from unicorn import UcError
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_PC, UC_ARM64_REG_LR,
    UC_ARM64_REG_SP,
)

# the socket-surface symbols we service with real implementations
NETSYMS = (
    "socket", "connect", "shutdown", "close",
    "sendto", "sendmsg", "recvfrom", "recvmsg",
    "select", "setsockopt", "getsockopt", "fcntl", "ioctl",
    "getaddrinfo", "freeaddrinfo", "gethostbyname", "gethostname",
    "getnameinfo", "bind", "listen", "accept",
    "getsockname", "getpeername",
    "inet_ntop", "inet_pton", "inet_addr",
    "strerror", "gai_strerror",
    "__FD_SET_chk", "__FD_ISSET_chk", "__FD_CLR_chk",
    "open", "read", "write", "fstat",
    "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait",
    "clock_gettime", "gettimeofday",
    "pipe", "eventfd", "nanosleep", "clock_nanosleep",
)

AF_INET, AF_INET6 = 2, 10
SOCK_STREAM, SOCK_DGRAM = 1, 2
SOL_SOCKET, SO_REUSEADDR = 1, 2
F_GETFL, F_SETFL = 3, 4
O_NONBLOCK = 0o4000
FIONBIO = 0x8004667E
CLOCK_REALTIME, CLOCK_MONOTONIC = 0, 1
FD_SETSIZE = 1024
EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD = 1, 2, 3

_ERRNO = _pyerrno


def _rd(uc, r):
    return uc.reg_read(r)


def _ret(uc, val):
    uc.reg_write(UC_ARM64_REG_X0, val & 0xFFFFFFFFFFFFFFFF)
    uc.reg_write(UC_ARM64_REG_PC, _rd(uc, UC_ARM64_REG_LR))


class OnlineCoreMixin:
    """Real-network socket surface for EFootballCoreV2."""

    def install_netsplice(self):
        """Hijack every NETSYM PLT entry to our handlers. Idempotent."""
        if getattr(self, "_net_installed", False):
            return self
        self._net_installed = True
        self._net_socks = {}          # our fd -> python socket
        self._net_files = {}          # our fd -> 'urandom'
        self._net_flags = {}          # our fd -> os flags (O_NONBLOCK)
        self._net_nextfd = 10
        self._net_epolls = {}         # our fd -> {reg_fd: (events, data)}
        self._net_sock_of_fileno = {}
        import json
        plt_path = None
        if hasattr(self, "_AN") and self._AN:
            plt_path = os.path.join(self._AN, "plt_map.json")
        if not plt_path or not os.path.exists(plt_path):
            here = os.path.dirname(os.path.abspath(__file__))
            plt_path = os.path.join(here, "..", "apk_lab", "analysis",
                                    "plt_map.json")
        plt = json.load(open(plt_path))
        wired = []
        for sym in NETSYMS:
            hits = [(int(k, 16), v) for k, v in plt.items()
                    if v["sym"] == sym]
            if not hits:
                continue
            stub = self._get_stub(f"{sym}_h")
            for _plt_addr, info in hits:
                self.write_u64(self.base + info["got"], stub)
            wired.append(sym)
        if getattr(self, "verbose", False):
            print(f"[netsplice] wired {len(wired)} socket imports: "
                  f"{', '.join(wired)}")
        self._net_wired = wired
        return self

    # ------------------------------------------------------------ dispatch
    def _stub_hook(self, uc, addr, size, ud):
        name = self.stub_of.get(addr, "")
        if name.endswith("_h"):
            name = name[:-2]
        h = _HANDLERS.get(name)
        if h is not None:
            self.import_calls[name] = self.import_calls.get(name, 0) + 1
            try:
                h(self, uc)
            except Exception as e:
                self._log.append(f"netsplice {name}: {type(e).__name__}: {e}")
                _ret(uc, -1)
            return
        super()._stub_hook(uc, addr, size, ud)

    # ------------------------------------------------------------ helpers
    def _newfd(self):
        fd = self._net_nextfd
        self._net_nextfd += 1
        return fd

    def _cstr(self, p, cap=512):
        if not p:
            return b""
        return bytes(self.safe_read(p, cap)).split(b"\0")[0]

    def _set_errno(self, e):
        try:
            a = self._errno_addr()
            self.write_u32(a, int(e) & 0xFFFFFFFF)
        except Exception:
            pass

    def _sock_of(self, fd):
        s = self._net_socks.get(fd)
        if s is None:
            raise OSError(_ERRNO.EBADF, "bad fd")
        return s

    def _parse_sockaddr(self, p, _len):
        """-> (family, python address tuple) or None."""
        if not p or _len < 8:
            return None
        fam = struct.unpack_from("<H", self.safe_read(p, 2))[0]
        if fam == AF_INET:
            raw = self.safe_read(p, 16)
            port = struct.unpack(">H", raw[2:4])[0]
            ip = _pysock.inet_ntop(_pysock.AF_INET, raw[4:8])
            return (AF_INET, (ip, port))
        if fam == AF_INET6 and _len >= 28:
            raw = self.safe_read(p, 28)
            port = struct.unpack(">H", raw[2:4])[0]
            ip = _pysock.inet_ntop(_pysock.AF_INET6, raw[8:24])
            return (AF_INET6, (ip, port))
        return None

    def _fdset_read(self, p):
        """bitmap -> set of our fds present."""
        if not p:
            return set()
        raw = bytes(self.safe_read(p, FD_SETSIZE // 8))
        out = set()
        for byte_i in range(len(raw)):
            b = raw[byte_i]
            for bit in range(8):
                if b & (1 << bit):
                    out.add(byte_i * 8 + bit)
        return out

    def _fdset_write(self, p, fds):
        raw = bytearray(FD_SETSIZE // 8)
        for fd in fds:
            if 0 <= fd < FD_SETSIZE:
                raw[fd // 8] |= 1 << (fd % 8)
        self.uc.mem_write(p, bytes(raw))


# ---------------------------------------------------------------- handlers

def _h_socket(core, uc):
    fam, typ, proto = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                       _rd(uc, UC_ARM64_REG_X2))
    # Linux/bionic flag bits folded into `type`:
    #   SOCK_NONBLOCK 00004000 oct = 0x800
    #   SOCK_CLOEXEC  02000000 oct = 0x80000
    # Forgetting SOCK_NONBLOCK is fatal: the caller passes 0x801, which is not
    # == SOCK_STREAM, so the socket silently comes out as UDP and every send
    # disappears while recv blocks forever.
    want_nb = bool(typ & (0x800 | 0x4000))
    typ = typ & 0xF                       # SOCK_STREAM/DGRAM/RAW/SEQPACKET
    py_fam = _pysock.AF_INET if fam == AF_INET else _pysock.AF_INET6 \
        if fam == AF_INET6 else _pysock.AF_INET
    py_typ = _pysock.SOCK_STREAM if typ == SOCK_STREAM else _pysock.SOCK_DGRAM
    s = _pysock.socket(py_fam, py_typ, 0)
    if want_nb:
        s.setblocking(False)
    else:
        s.settimeout(10.0)
    fd = core._newfd()
    core._net_socks[fd] = s
    core._net_flags[fd] = 0x800 if want_nb else 0
    core._log.append(f"net socket(fd={fd}) fam={fam} rawtype={typ} "
                     f"proto={proto} -> {py_typ}"
                     f"{' NB' if want_nb else ''}")
    _ret(uc, fd)


def _h_connect(core, uc):
    fd, sa, salen = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                     _rd(uc, UC_ARM64_REG_X2))
    s = core._sock_of(fd)
    pa = core._parse_sockaddr(sa, salen)
    if pa is None:
        core._set_errno(_ERRNO.EAFNOSUPPORT)
        _ret(uc, -1)
        return
    _fam, addr = pa
    core._log.append(f"net connect(fd={fd}) -> {addr}")
    try:
        s.settimeout(10.0)
        s.connect(addr)
        # restore the caller's blocking mode (curl asks for O_NONBLOCK)
        if core._net_flags.get(fd, 0) & O_NONBLOCK:
            s.settimeout(0.0)
        _ret(uc, 0)
    except BlockingIOError:
        core._set_errno(_ERRNO.EINPROGRESS)
        _ret(uc, -1)
    except OSError as e:
        core._set_errno(e.errno or _ERRNO.ECONNREFUSED)
        _ret(uc, -1)


def _sock_send(core, uc, fd, data):
    s = core._sock_of(fd)
    try:
        n = s.send(data)
        core._log.append(f"net send(fd={fd}, {len(data)}B) -> {n}")
        _ret(uc, n)
    except BlockingIOError:
        core._log.append(f"net send(fd={fd}, {len(data)}B) -> EAGAIN")
        core._set_errno(_ERRNO.EAGAIN)
        _ret(uc, -1)
    except OSError as e:
        core._log.append(f"net send(fd={fd}, {len(data)}B) -> OSError {e}")
        core._set_errno(e.errno or _ERRNO.EPIPE)
        _ret(uc, -1)


def _h_sendto(core, uc):
    fd, buf, n = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                  _rd(uc, UC_ARM64_REG_X2))
    data = bytes(core.safe_read(buf, n)) if buf and n else b""
    _sock_send(core, uc, fd, data)


def _h_sendmsg(core, uc):
    fd, mh = _rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1)
    # struct msghdr: name(8) namelen(4+pad) iov(8) iovlen(8) ctrl(8) ctrllen(8) flags(4)
    raw = core.safe_read(mh, 48)
    iov_ptr = struct.unpack_from("<Q", raw, 16)[0]
    iov_cnt = struct.unpack_from("<Q", raw, 24)[0]
    data = b""
    for i in range(min(iov_cnt, 32)):
        ent = core.safe_read(iov_ptr + i * 16, 16)
        base, ln = struct.unpack("<QQ", ent)
        if ln:
            data += bytes(core.safe_read(base, ln))
    _sock_send(core, uc, fd, data)


def _sock_recv_into(core, uc, fd, buf, n):
    s = core._sock_of(fd)
    try:
        data = s.recv(n)
        if buf and data:
            core.uc.mem_write(buf, data)
        core._log.append(f"net recv(fd={fd},n={n}) -> {len(data)}B "
                         f"{data[:48]!r}")
        _ret(uc, len(data))
    except _pysock.timeout:
        core._log.append(f"net recv(fd={fd},n={n}) -> TIMEOUT")
        core._set_errno(_ERRNO.EAGAIN)
        _ret(uc, -1)
    except BlockingIOError:
        core._log.append(f"net recv(fd={fd},n={n}) -> EAGAIN")
        core._set_errno(_ERRNO.EAGAIN)
        _ret(uc, -1)
    except OSError as e:
        core._log.append(f"net recv(fd={fd},n={n}) -> OSError {e}")
        core._set_errno(e.errno or _ERRNO.ECONNRESET)
        _ret(uc, -1)


def _h_recvfrom(core, uc):
    fd, buf, n = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                  _rd(uc, UC_ARM64_REG_X2))
    _sock_recv_into(core, uc, fd, buf, n)


def _h_recvmsg(core, uc):
    fd, mh = _rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1)
    raw = core.safe_read(mh, 48)
    iov_ptr = struct.unpack_from("<Q", raw, 16)[0]
    iov_cnt = struct.unpack_from("<Q", raw, 24)[0]
    if iov_cnt < 1 or not iov_ptr:
        _sock_recv_into(core, uc, fd, 0, 0)
        return
    ent = core.safe_read(iov_ptr, 16)
    base, ln = struct.unpack("<QQ", ent)
    _sock_recv_into(core, uc, fd, base, min(ln, 0x10000))


def _h_fd_set_chk(core, uc):
    fd = _rd(uc, UC_ARM64_REG_X0)
    p = _rd(uc, UC_ARM64_REG_X1)
    if p and 0 <= fd < 1024:
        word, bit = divmod(fd, 64)
        off = p + word * 8
        cur = struct.unpack('<Q', bytes(core.uc.mem_read(off, 8)))[0]
        core.write_u64(off, (cur | (1 << bit)) & ((1 << 64) - 1))
    _ret(uc, 0)


def _h_fd_clr_chk(core, uc):
    fd = _rd(uc, UC_ARM64_REG_X0)
    p = _rd(uc, UC_ARM64_REG_X1)
    if p and 0 <= fd < 1024:
        word, bit = divmod(fd, 64)
        off = p + word * 8
        cur = struct.unpack('<Q', bytes(core.uc.mem_read(off, 8)))[0]
        core.write_u64(off, cur & ~((1 << bit)) & ((1 << 64) - 1))
    _ret(uc, 0)


def _h_fd_isset_chk(core, uc):
    fd = _rd(uc, UC_ARM64_REG_X0)
    p = _rd(uc, UC_ARM64_REG_X1)
    on = 0
    if p and 0 <= fd < 1024:
        word, bit = divmod(fd, 64)
        off = p + word * 8
        cur = struct.unpack('<Q', bytes(core.uc.mem_read(off, 8)))[0]
        on = 1 if cur & (1 << bit) else 0
    _ret(uc, on)


def _h_select(core, uc):
    nfds = _rd(uc, UC_ARM64_REG_X0)
    rp, wp, ep, tv = (_rd(uc, UC_ARM64_REG_X1), _rd(uc, UC_ARM64_REG_X2),
                      _rd(uc, UC_ARM64_REG_X3), _rd(uc, UC_ARM64_REG_X4))
    rf = core._fdset_read(rp) if rp else set()
    wf = core._fdset_read(wp) if wp else set()
    xf = core._fdset_read(ep) if ep else set()
    timeout = None
    if tv:
        sec, usec = struct.unpack("<qQ", core.safe_read(tv, 16))
        timeout = min(sec + usec / 1e6, 30.0)
    else:
        timeout = 30.0            # NULL timeval == "block"; never forever
    sock_map = {}
    rf2, wf2, xf2 = [], [], []
    import os as _os
    pipes = getattr(core, "_net_pipes", {})
    for fd in sorted(rf | wf | xf):
        s = core._net_socks.get(fd)
        if s is not None:
            sock_map[s.fileno()] = fd
            if fd in rf:
                rf2.append(s)
            if fd in wf:
                wf2.append(s)
            if fd in xf:
                xf2.append(s)
            continue
        p = pipes.get(fd)
        if p is not None:
            try:
                _os.set_blocking(p, False)
            except OSError:
                pass
            sock_map[p] = fd
            if fd in rf:
                rf2.append(p)
            if fd in wf:
                wf2.append(p)
    try:
        rr, rw, rx = _pyselect.select(rf2, wf2, xf2, timeout)
    except (OSError, ValueError):
        rr, rw, rx = [], [], []
    rset = {sock_map[s if isinstance(s, int) else s.fileno()]
            for s in rr if (s if isinstance(s, int) else s.fileno()) in sock_map}
    wset = {sock_map[s if isinstance(s, int) else s.fileno()]
            for s in rw if (s if isinstance(s, int) else s.fileno()) in sock_map}
    xset = {sock_map[s if isinstance(s, int) else s.fileno()]
            for s in rx if (s if isinstance(s, int) else s.fileno()) in sock_map}
    if rp:
        core._fdset_write(rp, rset)
    if wp:
        core._fdset_write(wp, wset)
    if ep:
        core._fdset_write(ep, xset)
    _ret(uc, len(rset | wset | xset))


def _h_setsockopt(core, uc):
    fd, lvl, opt = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                    _rd(uc, UC_ARM64_REG_X2))
    valp, vlen = _rd(uc, UC_ARM64_REG_X3), _rd(uc, UC_ARM64_REG_X4)
    s = core._sock_of(fd)
    try:
        if lvl == SOL_SOCKET and opt == SO_REUSEADDR and valp:
            s.setsockopt(_pysock.SOL_SOCKET, _pysock.SO_REUSEADDR, 1)
        # everything else: accept silently
        _ret(uc, 0)
    except OSError:
        _ret(uc, 0)


def _h_shutdown(core, uc):
    fd, how = _rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1)
    try:
        core._sock_of(fd).shutdown(
            _pysock.SHUT_RDWR if how == 2 else _pysock.SHUT_WR
            if how == 1 else _pysock.SHUT_RD)
    except OSError:
        pass
    _ret(uc, 0)


def _h_close(core, uc):
    fd = _rd(uc, UC_ARM64_REG_X0)
    s = core._net_socks.pop(fd, None)
    if s is not None:
        try:
            s.close()
        except OSError:
            pass
    kind = core._net_files.pop(fd, None)
    if isinstance(kind, tuple) and kind and kind[0] in ("pipe_r", "pipe_w"):
        import os as _os
        try:
            _os.close(kind[1])
        except OSError:
            pass
    core._net_epolls.pop(fd, None)
    _ret(uc, 0)


def _h_fcntl(core, uc):
    fd, cmd, arg = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                    _rd(uc, UC_ARM64_REG_X2))
    if cmd == F_GETFL:
        _ret(uc, core._net_flags.get(fd, 2))
        return
    if cmd == F_SETFL:
        core._net_flags[fd] = arg
        s = core._net_socks.get(fd)
        if s is not None:
            s.setblocking(bool(arg & O_NONBLOCK) is False)
            if arg & O_NONBLOCK:
                s.settimeout(0.0)
            else:
                s.settimeout(10.0)
        _ret(uc, 0)
        return
    _ret(uc, 0)


def _h_ioctl(core, uc):
    fd, req, argp = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                     _rd(uc, UC_ARM64_REG_X2))
    if req == FIONBIO and argp:
        v = struct.unpack("<I", core.safe_read(argp, 4))[0]
        s = core._net_socks.get(fd)
        if s is not None:
            if v:
                s.setblocking(False)
            else:
                s.setblocking(True)
                s.settimeout(10.0)
    _ret(uc, 0)


def _h_getaddrinfo(core, uc):
    nodep, servp, hintsp, resp = (_rd(uc, UC_ARM64_REG_X0),
                                  _rd(uc, UC_ARM64_REG_X1),
                                  _rd(uc, UC_ARM64_REG_X2),
                                  _rd(uc, UC_ARM64_REG_X3))
    node = core._cstr(nodep, 256).decode() if nodep else ""
    serv = core._cstr(servp, 32).decode() if servp else "0"
    fam = _pysock.AF_UNSPEC
    if hintsp:
        h = struct.unpack("<iiii", core.safe_read(hintsp, 16))
        fam = {AF_INET: _pysock.AF_INET, AF_INET6: _pysock.AF_INET6}.get(
            h[1], _pysock.AF_UNSPEC)
    try:
        res = _pysock.getaddrinfo(node, serv, fam, _pysock.SOCK_STREAM)
    except OSError as e:
        core._set_errno(e.errno or _ERRNO.EAI_NONAME)
        _ret(uc, -1)
        return
    head = 0
    prev = 0
    for af, _st, _pr, _cn, sa in res[:8]:
        if af == _pysock.AF_INET:
            sa_raw = struct.pack("<HH", AF_INET, _pysock.htons(sa[1])) \
                + _pysock.inet_aton(sa[0]) + b"\0" * 8
        else:
            continue  # keep v6 out for now
        sa_ptr = core.alloc(len(sa_raw), sa_raw, name="ai_addr")
        canon = core.alloc(len(node) + 1, node.encode() + b"\0",
                           name="ai_canon")
        entry = struct.pack(
            "<iiiiQQQQ",
            0, AF_INET, SOCK_STREAM, 6,     # flags, family, socktype, proto
            len(sa_raw), canon, sa_ptr, 0)  # addrlen, canonname, addr, next
        e_ptr = core.alloc(48, entry, name="addrinfo")
        if prev:
            core.write_u64(prev + 40, e_ptr)   # ai_next
        else:
            head = e_ptr
        prev = e_ptr
    core.write_u64(resp, head)
    _ret(uc, 0)


def _h_freeaddrinfo(core, uc):
    _ret(uc, 0)          # arena is leak-by-design


def _h_gethostbyname(core, uc):
    name = core._cstr(_rd(uc, UC_ARM64_REG_X0), 256).decode()
    try:
        ip = _pysock.gethostbyname(name)
    except OSError:
        _ret(uc, 0)
        return
    name_ptr = core.alloc(len(name) + 1, name.encode() + b"\0", name="he_name")
    aliases = core.alloc(8, b"\0" * 8, name="he_aliases")
    ip_cell = core.alloc(8, _pysock.inet_aton(ip) + b"\0" * 4, name="he_ip")
    addrs = core.alloc(16, struct.pack("<QQ", ip_cell, 0), name="he_list")
    he = core.alloc(32, struct.pack(
        "<QQiiQ", name_ptr, aliases, AF_INET, 4, addrs), name="hostent")
    _ret(uc, he)


def _h_gethostname(core, uc):
    buf, ln = _rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1)
    name = b"localhost\0"[:ln]
    core.uc.mem_write(buf, name)
    _ret(uc, 0)


def _h_open(core, uc):
    path = core._cstr(_rd(uc, UC_ARM64_REG_X0), 128)
    if path == b"/dev/urandom":
        fd = core._newfd()
        core._net_files[fd] = "urandom"
        _ret(uc, fd)
        return
    _ret(uc, -1)          # no other files in the headless world


def _h_read(core, uc):
    fd, buf, n = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                  _rd(uc, UC_ARM64_REG_X2))
    kind = core._net_files.get(fd)
    if isinstance(kind, tuple) and kind and kind[0] == "pipe_r":
        import os as _os
        try:
            _os.set_blocking(kind[1], False)
            data = _os.read(kind[1], min(n, 0x10000))
        except (BlockingIOError, OSError):
            data = b""
        if buf and data:
            core.uc.mem_write(buf, data)
        _ret(uc, len(data))
        return
    if kind == "urandom":
        data = os.urandom(min(n, 0x10000))
        core.uc.mem_write(buf, data)
        _ret(uc, len(data))
        return
    if kind == "eventfd":
        # counter is always 0 -> read would block; report nothing
        _ret(uc, 0)
        return
    if fd in core._net_socks:
        # curl without send/recv reads sockets through read()
        _sock_recv_into(core, uc, fd, buf, n)
        return
    _ret(uc, -1)


def _h_write(core, uc):
    fd, buf, n = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                  _rd(uc, UC_ARM64_REG_X2))
    kind = core._net_files.get(fd)
    if isinstance(kind, tuple) and kind and kind[0] == "pipe_w":
        import os as _os
        data = bytes(core.safe_read(buf, min(n, 0x10000))) if buf and n else b""
        try:
            _os.set_blocking(kind[1], False)
            w = _os.write(kind[1], data)
        except (BlockingIOError, OSError):
            w = 0
        _ret(uc, w)
        return
    if fd in (1, 2):
        data = bytes(core.safe_read(buf, min(n, 4000)))
        tag = "[game-stdout]" if fd == 1 else "[game-stderr]"
        print(f"{tag} {data.decode('utf-8', 'replace').rstrip()}", flush=True)
        _ret(uc, n)
        return
    if fd in core._net_socks:
        # curl without send/recv writes sockets through write()
        data = bytes(core.safe_read(buf, n)) if buf and n else b""
        _sock_send(core, uc, fd, data)
        return
    _ret(uc, n)


def _h_fstat(core, uc):
    fd, st = _rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1)
    core.uc.mem_write(st, b"\0" * 128)
    struct.pack_into("<Q", core.uc.mem_read(st, 8), 0, 0)
    # st_mode = S_IFCHR at offset 24 (stat arm64: dev,ino,nlinks? keep simple)
    core.write_u32(st + 24, 0x2000)     # S_IFCHR
    _ret(uc, 0)


def _epoll_new(core, uc):
    fd = core._newfd()
    core._net_epolls[fd] = {}
    _ret(uc, fd)


def _h_epoll_create(core, uc):
    _epoll_new(core, uc)


def _h_epoll_create1(core, uc):
    _epoll_new(core, uc)


def _h_epoll_ctl(core, uc):
    epfd, op, fd, evp = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                         _rd(uc, UC_ARM64_REG_X2), _rd(uc, UC_ARM64_REG_X3))
    regs = core._net_epolls.get(epfd)
    if regs is None:
        _ret(uc, -1)
        return
    if op == EPOLL_CTL_DEL:
        regs.pop(fd, None)
    else:
        ev = 0
        data = 0
        if evp:
            raw = core.safe_read(evp, 12)
            ev, data = struct.unpack("<IQ", raw + b"\0" * 0)
        regs[fd] = (ev, data)
    _ret(uc, 0)


def _h_epoll_wait(core, uc):
    epfd, events, maxev, to_ms = (_rd(uc, UC_ARM64_REG_X0),
                                  _rd(uc, UC_ARM64_REG_X1),
                                  _rd(uc, UC_ARM64_REG_X2),
                                  _rd(uc, UC_ARM64_REG_X3))
    regs = core._net_epolls.get(epfd)
    if regs is None:
        _ret(uc, -1)
        return
    socks = [core._net_socks[fd] for fd in regs
             if fd in core._net_socks]
    timeout = min(to_ms / 1000.0, 30.0) if to_ms >= 0 else 30.0
    try:
        rr, _rw, _rx = _pyselect.select(socks, [], [], timeout)
    except (OSError, ValueError):
        rr = []
    n = 0
    fileno_to_fd = {s.fileno(): fd for fd, s in core._net_socks.items()}
    for s in rr:
        fd = fileno_to_fd.get(s.fileno())
        if fd is None or fd not in regs or n >= maxev:
            continue
        ev, data = regs[fd]
        core.uc.mem_write(events + n * 12,
                          struct.pack("<IQ", ev | 0x1, data))
        n += 1
    _ret(uc, n)


def _h_clock_gettime(core, uc):
    clk, tsp = _rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1)
    if clk == CLOCK_MONOTONIC:
        t = time.monotonic()
    else:
        t = time.time()
    sec = int(t)
    nsec = int((t - sec) * 1e9)
    if tsp:
        core.uc.mem_write(tsp, struct.pack("<qq", sec, nsec))
    _ret(uc, 0)


def _h_gettimeofday(core, uc):
    tv, tz = _rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1)
    t = time.time()
    if tv:
        core.uc.mem_write(tv, struct.pack("<qq", int(t), int((t % 1) * 1e6)))
    _ret(uc, 0)


def _h_getsockopt(core, uc):
    fd, lvl, opt, valp, lenp = (_rd(uc, UC_ARM64_REG_X0),
                               _rd(uc, UC_ARM64_REG_X1),
                               _rd(uc, UC_ARM64_REG_X2),
                               _rd(uc, UC_ARM64_REG_X3),
                               _rd(uc, UC_ARM64_REG_X4))
    try:
        core._sock_of(fd)
    except OSError:
        core._set_errno(_ERRNO.EBADF)
        _ret(uc, -1)
        return
    # SO_ERROR (SOL_SOCKET/4) -> 0 (we never fail connects asynchronously)
    if lvl == SOL_SOCKET and opt == 4 and valp:
        core.uc.mem_write(valp, struct.pack("<i", 0))
        if lenp:
            core.write_u32(lenp, 4)
    _ret(uc, 0)


def _h_bind(core, uc):
    fd = _rd(uc, UC_ARM64_REG_X0)
    try:
        core._sock_of(fd)
        _ret(uc, 0)
    except OSError:
        core._set_errno(_ERRNO.EBADF)
        _ret(uc, -1)


def _h_listen(core, uc):
    _ret(uc, 0)


def _h_accept(core, uc):
    # headless server side: no inbound connections in this world
    core._set_errno(_ERRNO.EAGAIN)
    _ret(uc, -1)


def _h_getnameinfo(core, uc):
    sa, salen, host, hostlen, serv, servlen, flags = (
        _rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
        _rd(uc, UC_ARM64_REG_X2), _rd(uc, UC_ARM64_REG_X3),
        _rd(uc, UC_ARM64_REG_X4), _rd(uc, UC_ARM64_REG_X5), 0)
    if host and hostlen:
        core.uc.mem_write(host, b"localhost\0")
    if serv and servlen:
        core.uc.mem_write(serv, b"0\0")
    _ret(uc, 0)


def _h_pipe(core, uc):
    fds_p = _rd(uc, UC_ARM64_REG_X0)
    try:
        r, w = _pysock.socketpair() if False else (None, None)
    except Exception:
        r = w = None
    # use os.pipe -- real kernel pipe, selectable through our fd space
    import os as _os
    pr, pw = _os.pipe()
    fr, fw = core._newfd(), core._newfd()
    core._net_files[fr] = ("pipe_r", pr)
    core._net_files[fw] = ("pipe_w", pw)
    core._net_pipes = getattr(core, "_net_pipes", {})
    core._net_pipes[fr] = pr
    core._net_pipes[fw] = pw
    if fds_p:
        core.uc.mem_write(fds_p, struct.pack("<ii", fr, fw))
    _ret(uc, 0)


def _h_eventfd(core, uc):
    fd = core._newfd()
    core._net_files[fd] = "eventfd"
    core._eventfd_state = getattr(core, "_eventfd_state", {})
    core._eventfd_state[fd] = 0
    _ret(uc, fd)


def _h_nanosleep(core, uc):
    req, rem = _rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1)
    if req:
        sec, nsec = struct.unpack("<qq", core.safe_read(req, 16))
        time.sleep(min(max(sec + nsec / 1e9, 0.0), 0.05))
    if rem:
        core.uc.mem_write(rem, b"\0" * 16)
    _ret(uc, 0)


def _h_clock_nanosleep(core, uc):
    clk, flags, req, rem = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                            _rd(uc, UC_ARM64_REG_X2), _rd(uc, UC_ARM64_REG_X3))
    if req:
        sec, nsec = struct.unpack("<qq", core.safe_read(req, 16))
        time.sleep(min(max(sec + nsec / 1e9, 0.0), 0.05))
    if rem:
        core.uc.mem_write(rem, b"\0" * 16)
    _ret(uc, 0)


def _sockaddr_write(core, sa, salenp, ip, port, family=AF_INET):
    if family == AF_INET:
        raw = (struct.pack("<HH", family, _pysock.htons(port))
               + _pysock.inet_aton(ip) + b"\0" * 8)
        out_len = 16
    else:
        raw = struct.pack("<HH", family, _pysock.htons(port)) + b"\0" * 24
        out_len = 28
    cap = out_len
    if salenp:
        try:
            cap = struct.unpack("<I", bytes(core.uc.mem_read(salenp, 4)))[0]
        except Exception:
            cap = out_len
    core.uc.mem_write(sa, raw[:max(1, min(cap, len(raw)))])
    if salenp:
        core.write_u32(salenp, out_len)


def _h_getsockname(core, uc):
    fd, sa, salenp = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                      _rd(uc, UC_ARM64_REG_X2))
    try:
        s = core._sock_of(fd)
        ip, port = s.getsockname()
    except OSError as e:
        core._set_errno(e.errno or _ERRNO.ENOTCONN)
        _ret(uc, -1)
        return
    _sockaddr_write(core, sa, salenp, ip, port)
    _ret(uc, 0)


def _h_getpeername(core, uc):
    fd, sa, salenp = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                      _rd(uc, UC_ARM64_REG_X2))
    try:
        s = core._sock_of(fd)
        ip, port = s.getpeername()
    except OSError as e:
        core._set_errno(e.errno or _ERRNO.ENOTCONN)
        _ret(uc, -1)
        return
    _sockaddr_write(core, sa, salenp, ip, port)
    _ret(uc, 0)


def _h_inet_ntop(core, uc):
    fam, src, dst, n = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                        _rd(uc, UC_ARM64_REG_X2), _rd(uc, UC_ARM64_REG_X3))
    try:
        if fam == AF_INET:
            s = _pysock.inet_ntop(_pysock.AF_INET,
                                  bytes(core.safe_read(src, 4)))
        elif fam == AF_INET6:
            s = _pysock.inet_ntop(_pysock.AF_INET6,
                                  bytes(core.safe_read(src, 16)))
        else:
            core._set_errno(_ERRNO.EAFNOSUPPORT)
            _ret(uc, 0)
            return
    except (OSError, ValueError):
        core._set_errno(_ERRNO.EINVAL)
        _ret(uc, 0)
        return
    b = s.encode() + b"\0"
    if dst and len(b) <= n:
        core.uc.mem_write(dst, b)
        _ret(uc, dst)
        return
    core._set_errno(_ERRNO.ENOSPC)
    _ret(uc, 0)


def _h_inet_pton(core, uc):
    fam, src, dst = (_rd(uc, UC_ARM64_REG_X0), _rd(uc, UC_ARM64_REG_X1),
                     _rd(uc, UC_ARM64_REG_X2))
    text = core._cstr(src, 64).decode("ascii", "replace")
    try:
        if fam == AF_INET:
            raw = _pysock.inet_pton(_pysock.AF_INET, text)
        elif fam == AF_INET6:
            raw = _pysock.inet_pton(_pysock.AF_INET6, text)
        else:
            core._set_errno(_ERRNO.EAFNOSUPPORT)
            _ret(uc, -1)
            return
    except (OSError, ValueError):
        _ret(uc, 0)
        return
    core.uc.mem_write(dst, raw)
    _ret(uc, 1)


def _h_inet_addr(core, uc):
    text = core._cstr(_rd(uc, UC_ARM64_REG_X0), 64).decode("ascii", "replace")
    try:
        raw = _pysock.inet_aton(text)
    except (OSError, ValueError):
        _ret(uc, 0xFFFFFFFF)
        return
    _ret(uc, struct.unpack("<I", raw)[0])


_STRERR = {}


def _h_strerror(core, uc):
    e = _rd(uc, UC_ARM64_REG_X0) & 0xFFFFFFFF
    msg = _STRERR.get(e)
    if msg is None:
        name = _pyerrno.errorcode.get(e)
        msg = (f"{name} (os error {e})" if name
               else f"Unknown error {e}").encode() + b"\0"
        msg = core.alloc(len(msg), msg, name="strerror")
        _STRERR[e] = msg
    _ret(uc, msg)


def _h_gai_strerror(core, uc):
    e = _rd(uc, UC_ARM64_REG_X0) & 0xFFFFFFFF
    key = 0x40000000 | e
    msg = _STRERR.get(key)
    if msg is None:
        msg = f"getaddrinfo error {e}".encode() + b"\0"
        msg = core.alloc(len(msg), msg, name="gai_strerror")
        _STRERR[key] = msg
    _ret(uc, msg)


_HANDLERS = {
    "__FD_SET_chk": _h_fd_set_chk,
    "__FD_ISSET_chk": _h_fd_isset_chk,
    "__FD_CLR_chk": _h_fd_clr_chk,
    "getsockname": _h_getsockname,
    "getpeername": _h_getpeername,
    "inet_ntop": _h_inet_ntop,
    "inet_pton": _h_inet_pton,
    "inet_addr": _h_inet_addr,
    "strerror": _h_strerror,
    "gai_strerror": _h_gai_strerror,
    "getsockopt": _h_getsockopt,
    "bind": _h_bind,
    "listen": _h_listen,
    "accept": _h_accept,
    "getnameinfo": _h_getnameinfo,
    "pipe": _h_pipe,
    "eventfd": _h_eventfd,
    "nanosleep": _h_nanosleep,
    "clock_nanosleep": _h_clock_nanosleep,
    "socket": _h_socket,
    "connect": _h_connect,
    "sendto": _h_sendto,
    "sendmsg": _h_sendmsg,
    "recvfrom": _h_recvfrom,
    "recvmsg": _h_recvmsg,
    "select": _h_select,
    "setsockopt": _h_setsockopt,
    "shutdown": _h_shutdown,
    "close": _h_close,
    "fcntl": _h_fcntl,
    "ioctl": _h_ioctl,
    "getaddrinfo": _h_getaddrinfo,
    "freeaddrinfo": _h_freeaddrinfo,
    "gethostbyname": _h_gethostbyname,
    "gethostname": _h_gethostname,
    "open": _h_open,
    "read": _h_read,
    "write": _h_write,
    "fstat": _h_fstat,
    "epoll_create": _h_epoll_create,
    "epoll_create1": _h_epoll_create1,
    "epoll_ctl": _h_epoll_ctl,
    "epoll_wait": _h_epoll_wait,
    "clock_gettime": _h_clock_gettime,
    "gettimeofday": _h_gettimeofday,
}
