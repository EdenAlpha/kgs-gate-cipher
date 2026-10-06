"""PeerLink step 1: GateInfo, run by the game itself.

Photocopier rule: nothing here is hand-assembled.  We give the binary a
URL and four configuration strings; 0x7d0c06c does the rest with its own
code -- it formats the JSON, hex-encodes it with its own loop, prefixes
"req=", POSTs it through the sub-request sender (0x7d03c68 -> the libcurl
that ships inside libUE4.so), pumps until its completion callback fires,
then walks the reply looking for STATUS / API_STATUS / LOG_ACTIVE.

Layout it expects (reverse-engineered from 0x7d0c06c, live-verified):

    holder  +0x08   sub-request object
            +0x10   0  (must be 0 or the call returns early)
            +0x14   set to 1 before sending, cleared by the callback
            +0x18   completion status, 0xe5000207 == OK
            +0x15c  1 when the reply was not STATUS 200
            +0x160  1 when STATUS==200 and API_STATUS and LOG_ACTIVE are set

    config  +0x000  url            (C string)
            +0x100  titleCode
            +0x120  locale
            +0x128  version
            +0x148  extra
            apiLevel comes from **(*(0x98dd2a0)) -- the game's own global,
            already 4 after boot, so we never supply it.
"""
from __future__ import annotations

import struct
from collections import namedtuple

GATEINFO = 0x7D0C06C
SUBREQ_VT = 0x98225A0
SETOPT = 0x6886498

CURLOPT_URL = 0x2712
CURLOPT_POSTFIELDS = 0x271F
CURLOPT_POSTFIELDSIZE = 0x3C

DEFAULT_URL = "http://ntl.service.konami.net/ntl/api/GateInfo.php"

OK_DONE = 0xE5000207

GateInfo = namedtuple("GateInfo",
                      "status api_status log_active server_time "
                      "put_log_url raw ok")


def _i32(core, addr):
    return struct.unpack("<i", bytes(core.uc.mem_read(addr, 4)))[0]


def _u32(core, addr):
    return struct.unpack("<I", bytes(core.uc.mem_read(addr, 4)))[0]


def parse_reply(raw: bytes) -> dict:
    """The game's own key:value parser, in Python, for reporting only.

    0x7d0c06c does this in the binary; we re-read it just to hand the
    values back to the caller.
    """
    out = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def run(core, url: str = DEFAULT_URL, title_code: str = "pes22",
        locale: str = "en", version: str = "dt270", extra: str = "",
        watch=None, timeout_s: float = 180.0) -> GateInfo:
    """Drive one full GateInfo exchange through the binary.

    `watch` is an optional callable(handle, opt, value) invoked for every
    CURLOPT the game sets, so callers can see the request it built.
    """
    base = core.base
    subreq = core.alloc(0x10200, b"\0" * 0x10200, name="gate_subreq")
    core.write_u64(subreq, base + SUBREQ_VT)

    holder = core.alloc(0x180, b"\0" * 0x180, name="gate_holder")
    core.write_u64(holder + 0x08, subreq)
    core.write_u32(holder + 0x10, 0)
    core.write_u32(holder + 0x14, 1)
    core.write_u32(holder + 0x18, 0)

    cfg = core.alloc(0x180, b"\0" * 0x180, name="gate_cfg")
    core.uc.mem_write(cfg + 0x000, url.encode() + b"\0")
    core.uc.mem_write(cfg + 0x100, title_code.encode() + b"\0")
    core.uc.mem_write(cfg + 0x120, locale.encode() + b"\0")
    core.uc.mem_write(cfg + 0x128, version.encode() + b"\0")
    core.uc.mem_write(cfg + 0x148, extra.encode() + b"\0")

    if watch is not None:
        from unicorn.arm64_const import UC_ARM64_REG_X1, UC_ARM64_REG_X2

        def _on_setopt(uc, _c):
            opt = uc.reg_read(UC_ARM64_REG_X1)
            val = uc.reg_read(UC_ARM64_REG_X2)
            try:
                watch(uc, opt, val)
            except Exception as e:
                core._log.append("gateinfo watcher error: %s" % e)
        core.watch(SETOPT, _on_setopt, name="gate_setopt")

    try:
        r = core.call(GATEINFO, w0=holder, w1=cfg, timeout_s=timeout_s,
                      max_insns=200_000_000)
    finally:
        for w in list(getattr(core, "watchers", [])):
            if isinstance(w, dict) and w.get("name") == "gate_setopt":
                core.unwatch(w)

    status = _u32(core, holder + 0x18)
    pending = _u32(core, holder + 0x14)
    rejected = _u32(core, holder + 0x15C)
    accepted = _u32(core, holder + 0x160)
    http = _i32(core, subreq + 8)
    blen = _i32(core, subreq + 0x10020)
    raw = b""
    if blen > 0:
        raw = bytes(core.uc.mem_read(subreq + 0x1C, min(blen, 0x10000)))

    fields = parse_reply(raw)

    def _num(key, default=-1):
        try:
            return int(fields.get(key, default))
        except ValueError:
            return default

    ok = (r.get("error") is None and pending == 0
          and status == OK_DONE and http == 200 and accepted != 0)

    info = GateInfo(
        status=_num("STATUS", -1),
        api_status=_num("API_STATUS", -1),
        log_active=_num("LOG_ACTIVE", -1),
        server_time=_num("SERVER_TIME", -1),
        put_log_url=fields.get("PUT_LOG_URL", ""),
        raw=raw,
        ok=ok,
    )
    core._gateinfo_debug = dict(
        x0=r.get("x0"), error=r.get("error"), holder_status=status,
        pending=pending, rejected=rejected, accepted=accepted,
        http=http, body_len=blen, ok=ok, fields=fields,
    )
    return info
