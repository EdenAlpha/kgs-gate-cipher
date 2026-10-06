"""PeerLink transport: HTTP through the game's OWN stack.

Photocopier rule: we never assemble a request by hand.  We hand a URL to the
game's sub-request sender, let its pump drive the libcurl that ships inside
libUE4.so, and read the answer back out of the sub-request object.

Entry points (sub-request vtable 0x98225a0):

    [2]  0x7d03b68  GET   (self, url, out_body, out_len, cb, cb_arg)
    [7]  0x7d03e10  header/body builder   (called by the POST sender)
    [8]  0x7d04148  POST  (self, url, body, body_len, a4, a5, a6,
                          out_body, out_len, cb, cb_arg)
    [10] 0x7d042f0  cleanup -> multi_remove / easy_cleanup / multi_cleanup /
                               slist_free_all
    [11] 0x7d04350  pump  -> curl_multi_perform, then writes the body into
                             *out_body and its length into *out_len
    [12] 0x7d04444  init  -> out slots + callback + zero the response buffer

Results:

    subreq+8         HTTP status code (starts at -1, set by curl's
                     CURLINFO_RESPONSE_CODE on the first response byte)
    subreq+0x1c      response body buffer (0x10001 bytes, zeroed by init)
    subreq+0x10020   body length written by the WRITEFUNCTION
"""
from __future__ import annotations

import struct
import time
from collections import namedtuple

SENDER = 0x7D03B68          # GET sender
POSTER = 0x7D04148          # POST sender
PUMP = 0x7D04350            # curl_multi_perform pump
CLEANUP = 0x7D042F0         # handle teardown
SETOPT = 0x6886498          # curl_easy_setopt (variadic, 2 fixed args)
MULTI_WAIT = 0x687990C      # curl_multi_wait(multi, NULL, 0, ms, NULL)
INFO_READ = 0x687AF14       # curl_multi_info_read
SUBREQ_VT = 0x98225A0       # sub-request vtable
WRITE_CB = 0x7D04570        # WRITEFUNCTION the senders install

CURLOPT_ERRORBUFFER = 0x271A

EXEC_BASE = 0xA4000000000   # RWX scratch page for guest function pointers
_RET_STUB = struct.pack("<I", 0xD65F03C0)   # ret

OK_DONE = 0xE5000207
OK_ERR = 0xE5000208
OK_AGAIN = 0xE5000209

HttpResult = namedtuple("HttpResult", "status code body error curl_result")


def ensure_exec(core) -> int:
    """Map the RWX scratch page used for guest callbacks (a plain `ret`)."""
    try:
        core.uc.mem_map(EXEC_BASE, 0x100000, 7)
        core.uc.mem_write(EXEC_BASE, _RET_STUB)
    except Exception:
        pass          # already mapped
    return EXEC_BASE


def _u64(core, addr) -> int:
    return struct.unpack("<Q", bytes(core.uc.mem_read(addr, 8)))[0]


def _i32(core, addr) -> int:
    return struct.unpack("<i", bytes(core.uc.mem_read(addr, 4)))[0]


class GameHttp:
    """One reusable sub-request object wired to the game's curl stack."""

    def __init__(self, core, log=None, verbose=False):
        self.core = core
        self.log = log or (lambda m: None)
        self.verbose = verbose
        self.exec_base = ensure_exec(core)
        self.subreq = core.alloc(0x10200, b"\0" * 0x10200, name="subreq")
        core.write_u64(self.subreq, core.base + SUBREQ_VT)
        self.out_body = core.alloc(8, b"\0" * 8, name="out_body")
        self.out_len = core.alloc(8, b"\0" * 8, name="out_len")
        self.errbuf = core.alloc(256, b"\0" * 256, name="errbuf")
        self.last_status = None
        self.last_curl_result = None

    # ------------------------------------------------------------- requests
    def get(self, url: str, timeout: float = 120.0) -> HttpResult:
        return self._run(url.encode() if isinstance(url, str) else url,
                         None, timeout)

    def post(self, url: str, body: bytes, a4=0, a5=0, a6=0,
             timeout: float = 120.0) -> HttpResult:
        """POST through the game's sender.

        a4/a5/a6 are the three extra pointers the game itself passes to the
        header builder (vtable[7] = 0x7d03e10).  It rejects the request when
        any of them is NULL, so the game's own caller supplies them; leave
        them 0 for a bare form POST (curl turns CURLOPT_POSTFIELDS into a
        POST) and pass real values once we have captured what the game uses.
        """
        self._a4, self._a5, self._a6 = a4, a5, a6
        return self._run(url.encode() if isinstance(url, str) else url,
                         bytes(body), timeout)

    # -------------------------------------------------------------- helpers
    def _start(self, url: bytes, post: bytes | None):
        core = self.core
        urlbuf = core.alloc(max(len(url) + 1, 64),
                            url + b"\0" * (max(len(url) + 1, 64) - len(url)),
                            name="url")
        core.uc.mem_write(self.errbuf, b"\0" * 256)
        core.uc.mem_write(self.out_body, b"\0" * 8)
        core.uc.mem_write(self.out_len, b"\0" * 8)

        if post is None:
            r = core.call(SENDER, w0=self.subreq, w1=urlbuf,
                          x2=self.out_body, x3=self.out_len,
                          s0=0.0, w4=self.exec_base, w5=0,
                          timeout_s=60, max_insns=40_000_000)
        else:
            bodybuf = core.alloc(len(post) or 1, post or b"\0",
                                 name="post")
            a4 = getattr(self, "_a4", 0)
            a5 = getattr(self, "_a5", 0)
            a6 = getattr(self, "_a6", 0)
            r = core.call(POSTER, w0=self.subreq, w1=urlbuf,
                          x2=bodybuf, x3=len(post), w4=a4, w5=a5,
                          x6=a6, x7=self.out_body,
                          stack=[self.out_len, self.exec_base, 0],
                          timeout_s=60, max_insns=40_000_000)
        if r["error"]:
            return None, ("sender fault: %s pc=%#x" % (r["error"], r["pc"]))

        easy = _u64(core, self.subreq + 0x10060)
        multi = _u64(core, self.subreq + 0x10068)
        if easy:
            core.call(SETOPT, w0=easy, w1=CURLOPT_ERRORBUFFER,
                      x2=self.errbuf, timeout_s=10)
        return (easy, multi), None

    def _pump(self, multi, timeout: float):
        core = self.core
        deadline = time.time() + timeout
        status = None
        fault = None
        while time.time() < deadline:
            r = core.call(PUMP, w0=self.subreq, timeout_s=120,
                          max_insns=40_000_000)
            if r["error"]:
                fault = "pump fault: %s pc=%#x" % (r["error"], r["pc"])
                break
            status = r["x0"] & 0xFFFFFFFFFFFFFFFF
            if status == 0:
                if multi:
                    core.call(MULTI_WAIT, w0=multi, w1=0, x2=0, x3=300,
                              s0=0.0, w4=0, timeout_s=5,
                              max_insns=5_000_000)
                else:
                    time.sleep(0.02)
                continue
            break
        else:
            fault = "timeout after %.0fs" % timeout
        return status, fault

    def _collect(self, status, fault):
        core = self.core
        code = _i32(core, self.subreq + 8)
        blen = _i32(core, self.subreq + 0x10020)
        body_ptr = _u64(core, self.out_body)
        body_len = _i32(core, self.out_len)

        if body_ptr and body_len > 0:
            body = bytes(core.uc.mem_read(body_ptr, min(body_len, 0x400000)))
        elif blen > 0:
            body = bytes(core.uc.mem_read(self.subreq + 0x1C,
                                          min(blen, 0x400000)))
        else:
            raw = bytes(core.uc.mem_read(self.subreq + 0x1C, 0x10000))
            cut = raw.find(b"\0")
            body = raw[:cut] if cut >= 0 else b""

        reason = bytes(core.uc.mem_read(self.errbuf, 256)).split(b"\0")[0]
        curl_result = None
        try:
            msgs = core.alloc(4, b"\0" * 4, name="msgs")
            mp = core.call(INFO_READ, w0=_u64(core, self.subreq + 0x10068),
                           x2=0, w1=msgs, timeout_s=10)["x0"]
            if mp:
                curl_result = struct.unpack_from("<i",
                                                 bytes(core.uc.mem_read(
                                                     mp, 32)), 16)[0]
        except Exception:
            pass

        err = fault or (reason.decode("utf-8", "replace") or None)
        if status is not None and status not in (OK_DONE,) and not err:
            err = "pump status %#x" % status
        return HttpResult(status=status, code=code, body=body, error=err,
                          curl_result=curl_result)

    def _run(self, url: bytes, post: bytes | None,
             timeout: float) -> HttpResult:
        started, fault = self._start(url, post)
        if fault:
            self.last_status = None
            return HttpResult(None, -1, b"", fault, None)
        _easy, multi = started
        status, fault = self._pump(multi, timeout)
        try:
            res = self._collect(status, fault)
        finally:
            try:
                self.core.call(CLEANUP, w0=self.subreq, timeout_s=30)
            except Exception as e:
                self.log("cleanup failed: %s" % e)
        self.last_status = res.status
        if self.verbose:
            self.log("http %s -> %s code=%s bytes=%d" % (
                url[:80], res.status if res.status is not None else "-",
                res.code, len(res.body)))
        return res
