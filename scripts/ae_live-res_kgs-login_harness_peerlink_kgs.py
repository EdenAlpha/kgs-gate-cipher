"""PeerLink KGS — the headless eFootball client's server-facing layer.

Implements the wire protocol decoded from libUE4.so v11.0.1 (see
apk_lab/analysis/FINDINGS_M17_kgs_wire.md):

  * NTL GateInfo bootstrap  — POST http://ntl.service.konami.net/ntl/api/
    GateInfo.php with form body `req=` + lowercase-hex(JSON). LIVE-VERIFIED:
    the server answers `STATUS: 200` and returns key:value lines
    (STATUS / API_STATUS / LOG_ACTIVE / SERVER_TIME / PUT_LOG_URL).

  * KGS Cmd*.php requests — MessagePack bodies built exactly like the
    game's own serializer (submit fn 0x74e38c4 → marker writers
    0x745cbd0 / 0x745cd70 / 0x74e65e8):
        map(count = 6 + body_fields):
            "msgid"       -> str  the command, e.g. "CMD_LOGIN"
            "rqid"        -> int
            "user_id"     -> int
            "session_id"  -> str
            "my_platform"-> str
            "s_keyword"   -> str
            <body fields...>
    The login body (23 fields) and the response envelope
    {msgid, rqid, result, msg, maintenance_eula_season} are known.

  * Config defaults recovered from the binary (0x7d66580 registrar,
    verified by executing it under Unicorn and dumping the live struct):
        scheme   = "https"
        host     = "pes22-game.cs.konami.net"      (port 443, config@0xa4b0140)
        path     = "/"
        title    = "pes22"
        stun     = "pesam.stun.service.konami.net"
        dev-tag  = " DEV1"
    URL builder (0x7d65884): scheme + "://" + host + path + title
        -> https://pes22-game.cs.konami.net/pes22

    RESOLVED (M25, FINDINGS_M25_gate_endpoint.md): the command path is built by
    the game's own composer 0x7b099d0:

        scheme + "://" + host + "/pes22" + "/gate/gate_" + <msgid> + ".php"

    where <msgid> is the envelope's msgid (CMD_LOGIN, CMD_GET_SERVER_ENV, ...)
    read from request_object+0x70 by the gate builder 0x7afd364.  NOT the
    Cmd*.php filename -- gate_CmdLogin.php is 404 while gate_CMD_LOGIN.php is
    present.  Live oracle: real msgids answer 500 (script runs, PHP fatals),
    invented ones answer 404 "File not found.".
"""
import json
import secrets
import urllib.request
import urllib.parse

# ---------------------------------------------------------------------------
# NTL layer (LIVE-VERIFIED)
# ---------------------------------------------------------------------------

NTL_HOSTS = [
    "http://ntl.service.konami.net",
    "http://ntlus.service.konami.net",
    "http://ntleu.service.konami.net",
    "http://ntljp2.service.konami.net",
]
GATEINFO_PATH = "/ntl/api/GateInfo.php"
DEFAULT_GATEINFO_URL = NTL_HOSTS[0] + GATEINFO_PATH

RSA_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApC/7GywWS+F2J3/GcD2W
QiRAhGOp7Y8VkMThCczHTd/ygGmuCSH0312p+9u0vZv/v5MyuAWK8Gm9jbZuDwAY
uWKhgFCc4p9xoAMmLBzLoog81VWwQERu4QHRrH/p5z4G5I73aI253gGoZufLvhFO
cLomKOxgEERSvy9uk9zQ8FgIQ03mjKI6XWxIrIaxLg7Kvb5QgcHPQARqmkEgnlNY
/LS/P7lYUEt+leEyXTgzOq9iySmcQlhiUlfey26JQw06FZhT6aB/s5+/sTpxbGy9
cNf0MCPi8x2Eks0oSXc0PMFJkHK8xZf/ecWTAKzk24QNnpHEcpFfWRKSsgaJtzU+
mGHKeeCrZ9YF2n8rc7XJe+fKHK8L1qlz8pcXO/7sL3O1Mt9jKyDAuJivqlvs/V6a
qOjydXJ5HpL5LHSqPxRwost0dMDVMnntC4p75lmRYNyCCRwjF9ELJHgeAKOc2EZS
2Z78Iw/+z+HAE1cC39yVETb4pDWWdeg4dFEeHSs8jpEnyJ6yATvI+w1Z1O1xGGe
A/pLpHAVEBrqNWWkkeY2klPnQu0R6LFdP36aL7+97y0/INKa/ovULwzGTlunyIFi
44iv4DzixU5N3pBzb5cI6ftqQhC+0R1zULwCrKoRxEX26CuI/ZkI8P20DCCDN516
BVYMH4rOt3mF9VafazdTg7cCAwEAAQ==
-----END PUBLIC KEY-----"""


def gate_info(title_code="pes22", locale="en", version="dt270", extra="",
              api_level=1, url=DEFAULT_GATEINFO_URL, timeout=15):
    """NTL GateInfo — LIVE-VERIFIED 200 OK.

    Wire: POST form `req=<hex(JSON)>`; response = key:value lines.
    Mirrors the request builder at 0x7d0c06c (titleCode JSON template,
    hex encoding) and the parser that reads STATUS/API_STATUS/
    LOG_ACTIVE/SERVER_TIME/PUT_LOG_URL.
    """
    payload = {"titleCode": title_code, "locale": locale, "version": version,
               "extra": extra, "apiLevel": api_level}
    body = "req=" + json.dumps(payload, separators=(",", ":")).encode().hex()
    req = urllib.request.Request(
        url, data=body.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "User-Agent": "Mozilla/4.0 (compatible; UPnP/1.0; KONAMI)"},
        method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode()
    out = {}
    for line in raw.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


# ---------------------------------------------------------------------------
# MessagePack writer — byte-exact with the game's serializer
#   str marker: 0x745cbd0 (fixstr 0xa0|n, str8 0xd9, str16 0xda)
#   int writer: 0x745cd70 (positive fixint / int32 0xd2 BE)
#   map header: 0x74e65e8 (fixmap 0x80|n, map16 0xde, map32 0xdf)
# ---------------------------------------------------------------------------

def mp_str(s):
    b = s.encode() if isinstance(s, str) else s
    n = len(b)
    if n < 32:
        return bytes([0xA0 | n]) + b
    if n < 256:
        return b"\xd9" + bytes([n]) + b
    return b"\xda" + n.to_bytes(2, "big") + b


def mp_int(v):
    if 0 <= v < 128:
        return bytes([v])
    return b"\xd2" + int(v).to_bytes(4, "big", signed=True)


def mp_map_header(n):
    if n < 16:
        return bytes([0x80 | n])
    if n < 0x10000:
        return b"\xde" + n.to_bytes(2, "big")
    return b"\xdf" + n.to_bytes(4, "big")


def build_request(msgid, body_fields=None, rqid=1, user_id=0,
                  session_id="", my_platform="", s_keyword=""):
    """Build a full Cmd*.php msgpack request.

    `body_fields` = ordered [(key, value)] where value is str or int.
    Mirrors the game's submit (envelope) + per-Cmd body serializers.
    """
    envelope = [("msgid", msgid), ("rqid", rqid), ("user_id", user_id),
                ("session_id", session_id), ("my_platform", my_platform),
                ("s_keyword", s_keyword)]
    fields = envelope + list(body_fields or [])
    out = mp_map_header(len(fields))
    for k, v in fields:
        out += mp_str(k)
        out += mp_int(v) if isinstance(v, int) and not isinstance(v, bool) else mp_str(v)
    return out


def parse_response(data):
    """Parse a msgpack response map into an ordered dict (envelope first)."""
    out = {}
    i = 0
    n = len(data)
    def rd():
        nonlocal i
        b = data[i]; i += 1
        return b
    def rds(nbytes):
        nonlocal i
        b = data[i:i + nbytes]; i += nbytes
        return b
    def rdval():
        b = rd()
        if 0xA0 <= b <= 0xBF:
            return rds(b & 0x1F).decode("utf8", "replace")
        if b == 0xD9:
            ln = rd(); return rds(ln).decode("utf8", "replace")
        if b == 0xDA:
            return rds(int.from_bytes(rds(2), "big")).decode("utf8", "replace")
        if b == 0xD2:
            return int.from_bytes(rds(4), "big", signed=True)
        if b == 0xCC:
            return rd()
        if b == 0xC2:
            return False
        if b == 0xC3:
            return True
        if b < 0x80:
            return b
        if b >= 0xE0:
            return b - 256
        if 0x90 <= b <= 0x9F:  # fixarray
            return [rdval() for _ in range(b & 0x0F)]
        if 0x80 <= b <= 0x8F:  # fixmap
            d = {}
            for _ in range(b & 0x0F):
                k = rdval(); d[k] = rdval()
            return d
        return f"<tag 0x{b:02x}>"
    b = rd()
    if 0x80 <= b <= 0x8F:
        count = b & 0x0F
    elif b == 0xDE:
        count = int.from_bytes(rds(2), "big")
    elif b == 0xDF:
        count = int.from_bytes(rds(4), "big")
    else:
        raise ValueError(f"not a msgpack map: 0x{b:02x}")
    for _ in range(count):
        k = rdval()
        out[k] = rdval()
    if i != n:
        out["_trailing_bytes"] = n - i
    return out


# ---------------------------------------------------------------------------
# The KGS endpoint names (decoded from the login SSO pattern "Cmd*.php")
# ---------------------------------------------------------------------------

CMD = {
    "guest_token": "CmdGetKgsGuestLoginToken.php",
    "create_user": "CmdCreateUser.php",
    "login": "CmdLogin.php",
    "session_id": "CmdGetSessionId.php",
    "create_room": "CmdCreatejoinRoom.php",
    "room_info": "CmdGetRoomInfo.php",
    "join_request": "CmdSendJoinRoomRequest.php",
    "room_settings": "CmdSetRoomSettings.php",
    "match_ready": "CmdSetRoomMatchReady.php",
    "start_game": "CmdStartGame.php",
    "turn_address": "CmdGetTurnAddressData.php",
    "game_session": "CmdGetGameSession.php",
    "check_result": "CmdCheckGameResult.php",
    "set_result": "CmdSetGameResult.php",
    "matching_result": "CmdGetMatchingResult.php",
    "tutorial_get": "CmdGetMyclubTutorial.php",
    "tutorial_set": "CmdSetMyclubTutorial.php",
}

# login request body fields (serializer 0x76b1b28, submit count 0x17 = 23)
LOGIN_BODY_FIELDS = [
    "auth_code", "hash", "client_version", "platform", "device_identifier",
    "device", "lang", "country_code", "os_version", "model_name",
    "gpu_name", "soc_name", "is_rooting", "phy_mem_used_mib",
    "phy_mem_available_mib", "app_storage_used_mib",
    "app_storage_available_mib", "data_storage_used_mib",
    "data_storage_available_mib", "payment_store_link_send_info",
]


def login_request(auth_code="", client_version="dt270", platform="PES",
                  lang="en", country="US", os_version="13", model="Pixel 7",
                  gpu="Adreno", soc="Tensor", **extra):
    """CmdLogin.php body (23 fields; fields not listed in the game's
    serializer are filled from device scan — values here are plausible
    guest defaults)."""
    fields = [
        ("auth_code", auth_code),
        ("hash", secrets.token_hex(16)),
        ("client_version", client_version),
        ("platform", platform),
        ("device_identifier", secrets.token_hex(8)),
        ("device", model),
        ("lang", lang),
        ("country_code", country),
        ("os_version", os_version),
        ("model_name", model),
        ("gpu_name", gpu),
        ("soc_name", soc),
        ("is_rooting", 0),
        ("phy_mem_used_mib", 2048),
        ("phy_mem_available_mib", 4096),
        ("app_storage_used_mib", 1024),
        ("app_storage_available_mib", 8192),
        ("data_storage_used_mib", 512),
        ("data_storage_available_mib", 8192),
        ("payment_store_link_send_info", 0),
    ]
    fields += list(extra.items())[:3]
    return build_request(CMD["login"], fields)


# ---------------------------------------------------------------------------
# CS transport
# ---------------------------------------------------------------------------

CS_BASE = "https://pes22-game.cs.konami.net"
CS_PATH = "/pes22/gate"   # from the game's own composer 0x7b099d0
CS_PORT = 443
USER_AGENT = "PES/1.0"      # 0x7dbc430 builds "PES/1.0 ( ; 0; ; <id>; ... )"


def gate_url(msgid: str) -> str:
    """The exact URL the game composes: /pes22/gate/gate_<msgid>.php."""
    return f"{CS_BASE}{CS_PATH}/gate_{msgid}.php"


def post_cmd(base_url, msgid, body, timeout=15,
             content_type="application/x-www-form-urlencoded"):
    """POST a msgpack request to <base_url>/gate_<msgid>.php.

    The game's plain POST sender (sub-request vtable slot 3, 0x7d03c68) sets
    no custom Content-Type, so libcurl emits
    application/x-www-form-urlencoded and the MessagePack goes out raw.
    """
    url = f"{base_url.rstrip('/')}/gate_{msgid}.php"
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": content_type, "User-Agent": USER_AGENT},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, str(e).encode()


def probe_cs(msgid=None, base=None):
    """Probe candidate CS bases for an endpoint (research helper)."""
    msgid = msgid or CMD["login"]
    env = build_request(msgid)
    bases = [base] if base else [
        CS_BASE + CS_PATH,
        CS_BASE,
        CS_BASE + "/api",
        CS_BASE + "/kgs",
    ]
    results = []
    for b in bases:
        st, body = post_cmd(b, msgid, env)
        results.append((b, st, body[:120]))
        print(f"{b}/{msgid} -> {st} {body[:80]!r}")
    return results
