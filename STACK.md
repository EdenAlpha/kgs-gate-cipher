# STACK.md — how eFootball's online stack actually works

Everything here is measured, not guessed. Sources are named per section.

* Wire format + keys: `KEYS.md`, `proofs/aes_gate.txt`
* Command vocabulary + enums: from `libUE4.so` (sha256 `2ac4ff17…c1298cd`)
* Live traffic: `corpus/flows.log`, `ae_kgs_flows.log`, `rec2/flows.log`
* Match-side packets: PeerLink's own `captures/match-2026-09-26/`

---

## 1. Transport

| Layer | What it is |
|---|---|
| Gate (HTTP) | `pes22-game.cs.konami.net`, path `…/gate/gate_CMD_*.php`, `POST`, `Content-Type: application/x-www-form-urlencoded` |
| Body | `IV(16) ‖ AES-256-CBC(Key B, PKCS#7/16)` of a msgpack payload |
| Request payload | zlib-compressed msgpack |
| Response payload | gzip-compressed msgpack |
| Header | `pes-custom-encrypt: AES256` |
| Auth header | `sign` = base64(HMAC-SHA256(key, body) ‖ clock_u32_le ‖ rand_u32_le), key `Xrq-RtAF_91MAE82` |

**Decoded 116/116 bodies** across both captures with this recipe — zero failures.

## 2. What GET_SERVER_ENV tells the client at startup

Decoded from `gate_CMD_GET_SERVER_ENV` (see `gate_decoded.txt`):

* `challenge_code` — 32 hex chars, fed back to `CMD_CHECK_STRING`
* `room_list_num: 10`, `room_info_polling_interval_msec: 5000`
* `communication_antenna_status_info` — ping thresholds for the connection-quality bars (30/120/171/209 ms)
* `proto_opt` (base64 JSON) — **has a `P2P` section**: `P2P.Match.NoMoveOperationTimeoutMs = 120000`, plus `CS.Match` of the same value
* `onsys_opt` (base64 JSON) — the behaviour switches:
  * `invitation_task.enable = true`, **`invitation_task.use_http_command = false`**
    → invitations do **not** travel over the gate HTTP API
  * **`connect_grpc_task.disable = true`**
    → the gRPC connect task is off in this configuration
  * `onmode.quality_check_timeout_msec = 30000`, `game_result_timeout_sec = 45`
  * `timeout_settings.align_progress_ready_timeout_sec = 40`

## 2b. `s_keyword` — SOLVED (the thing that blocked every request)

`s_keyword` is **not stored anywhere**. It is computed at request time:

```
s_keyword[i] = CONST[i] ^ client_version[i % len(client_version)]
```

`CONST` is an 8-byte string baked into every build as an obfuscated
`.data.rel.ro` struct, decoded by the per-build string decoder
(`out[i] = p[i] ^ T1[i%9] ^ T2[i%12] ^ 0x75`) and cached in a global:

| build | struct VA | `CONST` |
|---|---|---|
| 11.0.1 | `0x9823c38` | `hGcKSg6k` |
| 11.1.0 | `0x9932ab0` | `YE5PUd6m` |

The captured value falls out exactly:

```
"hGcKSg6k" ^ repeat("6.0.1")[:8]  ==  "^iSebQ\x18["   ← the captured s_keyword
   68 47 63 4b 53 67 36 6b        36 2e 30 2e 31 36 2e 30
```

For 11.1.0 (`CONST = YE5PUd6m`):

| `client_version` | `s_keyword` (hex) |
|---|---|
| `6.1.0` | `6f 6b 04 7e 65 52 18 5c` |
| `6.1.1` | `6f 6b 04 7e 64 52 18 5c` |

**Why this mattered.** Because `CONST` changes per app build, any
`s_keyword` copied out of an older capture silently dies on update. Every
request after the 11.1.0 update was sending `6.0.1`'s value while claiming
`client_version=6.1.0`, and the gate answered `CIYU-` / `ERR_DEFCLIENTVER` —
a *second*, silent, platform-independent check, after the version string
itself had already been accepted.

All four discriminating predictions were confirmed live:

| test | expected | got |
|---|---|---|
| stale 11.0.1 `s_keyword` | `CIYU-` | `CIYU-` |
| `CONST ^ client_version` | pass | **`NOERR`** |
| `CONST ^ app version` (`11.1.0`) | `CIYU-` | `CIYU-` |
| old `CONST ^ client_version` | `CIYU-` | `CIYU-` |

Note what the drop-test does *not* prove: omitting `s_keyword` also yields
`CIYU-`. A stale value and an absent value fail the *same* check, so "same
error either way" was never evidence that the field was unchecked.

## 3. Login (decoded verbatim)

Request `gate_CMD_LOGIN`:

```
msgid          CMD_LOGIN
rqid           1941751481
user_id        2024318960
session_id     ""                  (empty on first login)
auth_code      40 hex chars  (20 bytes, SHA-1 sized)
hash           32 hex chars  (MD5 sized)
s_keyword      8 raw bytes, derived per request — see §2b
device.device_identifier   64 hex chars (SHA-256 sized)
client_version 6.0.1   platform/ANDROID   os_version 14
```

Response:

```
session_id     "0_a8talpfd78ltaor8ferj50mlq9"   ← the login token
svr_time, user_eula_info, pes_user_info{user_id,user_name,…}, uniform_list …
```

Every later request carries `user_id` + `session_id` + `s_keyword`.

### Live login confirmed (2026-10-08)

Replaying the captured `CMD_LOGIN` **byte-for-byte**, changing only
`client_version` → `6.1.0` and `s_keyword` → the derived value, produced:

```
session_id  0_…(redacted, live token)…        svr_time 1791473946
```

Full authenticated payload returned (players, stadiums, campaign passes…).
So the captured `auth_code`/`hash` are **not** time-bound — the only thing
that had actually expired was `s_keyword`.

Supporting results from the same run:

* `auth_code` blanked → `ERR_ONLINEPASS` / `WFJS-` → the field *is* checked.
* `client_version=6.1.1` → `ERR_DATABASE` / `JPWM-` `'get tb_user error:'`
  → 6.1.1 routes the account lookup where the account does not exist.
  **`6.1.0` is the correct `client_version`**, established by behaviour
  rather than inference.

`hash` (32 lower-hex) still has no reproduced derivation. Ruled out: MD5,
SHA-1, Java HMAC-MD5, gRPC hex table, native HMAC-SHA256 (`0x7b39a28`),
nibble-loop hex encoder. It does not block login.

## 4. The command vocabulary — 384 `CMD_*` tokens

Full list: `cmd_strings.txt`. Grouped by what they do:

**Account / login** — `CMD_CREATE_USER`, `CMD_LOGIN`, `CMD_PLATFORM_SESSION`,
`CMD_AUTH_GOOGLE` / `_STEAM` / `_SWITCH` / `_XSTS`,
`CMD_SEND_AUTHORIZATION_CODE`, `CMD_BIND_ID_TO_SERVICE`,
`CMD_GET_IS_ACCOUNT_LINK`, `CMD_GET_KGS_GUEST_LOGIN_TOKEN`.

**Rooms (the ones PeerLink needs)**

```
CMD_CREATEJOIN_ROOM        create AND join in one step
CMD_GET_ROOM_LIST          paged; server returns room_list_num = 10
CMD_GET_ROOM_INFO          polled every room_info_polling_interval_msec = 5000
CMD_JOIN_ROOM              password-protected (ERR_PASSWD_EMPTY/INCORRECT)
CMD_LEAVE_ROOM             CMD_RETURN_ROOM
CMD_ADD_ROOM_GUEST / CMD_DELETE_ROOM_GUEST / CMD_KICK_ROOM_USER
CMD_SET_ROOM_SETTINGS / CMD_SET_ROOM_USER_COMMENT
CMD_SET_ROOM_USER_ENTRY_SIDE / CMD_SET_ROOM_USER_SQUAD_ENABLE
CMD_SET_ROOM_MATCH_READY / CMD_UNSET_ROOM_MATCH_READY
CMD_SEND_JOIN_ROOM_REQUEST / CMD_GET_REQUESTED_JOIN_ROOM_INFO
CMD_WATCH_ROOM_CONNECTION
```

**Matchmaking / match** — `CMD_START_MATCHING`, `CMD_CANCEL_MATCHING`,
`CMD_GET_MATCHING_RESULT`, `CMD_SET_MATCHING_OPTION`, `CMD_CHECK_MATCH_ENABLE`,
`CMD_MATCH_SETTINGS`, `CMD_SIDE_SELECT`, `CMD_TEAM_SELECT`,
`CMD_START_GAME`, `CMD_JOIN_GAME_MODE`, `CMD_LEAVE_GAME_MODE`,
`CMD_SET_GAME_RESULT`, `CMD_GET_GAME_RESULT`, `CMD_CHECK_GAME_RESULT`.

**P2P / relay / session**

```
CMD_GET_TURN_SERVER_LIST       TURN relay discovery
CMD_SEND_TURN_ADDRESS_DATA     client reports its TURN addresses
CMD_WATCH_TURN_ADDRESS_DATA    the other side's addresses
CMD_GET_TURN_ADDRESS_DATA
CMD_GET_GAME_SESSION           the session ticket
CMD_SET_GAME_SESSION_CHECK_RES / CMD_GET_GAME_SESSION_CHECK_RES
CMD_SEND_SESSION_ID / CMD_GET_SESSION_ID
CMD_GET_GAMERELAY_QUALITYCHECK_LIST   ping-target list
CMD_SET_GAMERELAY_QUALITY             measured latencies, sent back
CMD_SET_LOCAL_GAMERELAY_LIST
CMD_CONNECT_GRPC / CMD_HEARTBEAT_GRPC / CMD_UNSUBSCRIBE_GRPC
CMD_SEND_HEARTBEAT
CMD_SEND_VOICE_CHAT_DATA / CMD_WATCH_VOICE_CHAT_DATA
```

**Friends** — `CMD_GET_FRIEND_LIST`, `CMD_SEND_FRIEND_REQUEST`,
`CMD_ACCEPT_FRIEND_REQUEST`, `CMD_REJECT_FRIEND_REQUEST`,
`CMD_DELETE_FRIEND`, `CMD_SEARCH_USER`, `CMD_GET_USER_DETAIL`,
`CMD_WATCH_INVITATION`.

## 5. Room creation's real dependency chain

Read off `ELobbyCreatejoinRoomError` in the binary — these are the ways
creating a room can fail, in the order the client checks them:

```
ERR_GAMERELAY_QUALITY_NOT_MEASURE   ← you must have run SET_GAMERELAY_QUALITY first
ERR_FAILED_STUNCHECK                ← STUN must succeed
ERR_FAILED_CONNECT_RELAY            ← relay must connect
ERR_FAILED_CONNECT_RELAY_TIMEOUT
ERR_FAILED_CREATE_PLATFORMSESSION   ← a platform session must exist
ERR_FAILED_MULTIPLAY_PRIVILEGE
ERR_ROOM_CREATE_LIMIT
ERR_ALREADY_INROOM
ERR_LIVEDATA_UPDATED
ERR_UNKNOWN
```

Joining adds password and membership checks (`ELobbyJoinRoomError`): `ERR_PASSWD_EMPTY`,
`ERR_PASSWD_INCORRECT`, `ERR_TOO_MANY_MEMBERS`, `ERR_OTHER_PLATFORM_USER_IN_ROOM`,
`ERR_BLOCKED_ROOM_USER`, `ERR_FAILED_PLATFORM_SESSION_ID_MISMATCH`.

Room settings the server accepts (`ELobbyRoomMatchSettingsItem`): `MATCH_TIME`,
`MATCH_TIME_ONLINE`, `MATCH_RULE`, `MATCH_LEVEL`, `SIDE`, `SIDE_LEADER`,
`NUM`, `PK`, `WEATHER`, `SEASON`, `TIMEZONE`, `USER_COMMENT`,
`USE_MOBILE_CONTROLLER`, `MEMBER_CHANGE_NUM`, `MEMBER_CHANGE_TIMES`,
`EQUALIZATION`, `INJURY`, `EX`, `EX_SUBSTITUTION`, `COOP_CPU_LEVEL`.

Room detail element IDs (`EMenuRoomDetailElement`): `ID`, `MODE`, `REGULATION`,
`MATCH_TIME`, `CPU_LEVEL`, `NUMMEMBER`, `PASSWORD`, `PK`, `EXTRA`, `INJURY`.

**So: PeerLink cannot just POST `CMD_CREATEJOIN_ROOM`. It must first**
1. log in (`CMD_LOGIN` → `session_id`),
2. measure relay quality (`CMD_GET_GAMERELAY_QUALITYCHECK_LIST` → ping → `CMD_SET_GAMERELAY_QUALITY`),
3. pass STUN,
4. connect the relay,
5. create the platform session,
6. then `CMD_CREATEJOIN_ROOM`.

Steps 3–5 are *client-side preconditions the game enforces before it will send
the create-room request* — they are not separate gate commands.

## 6. The P2P state machine, named by the game itself

`LATENCY_*` literals from `.rodata`:

```
LATENCY_MODE_PRE_MENU
LATENCY_MODE_PRE_MENU_TEAM_DATA_SYNC
LATENCY_MODE_MATCHING_CMD_GET_SERVER_ENV
LATENCY_MODE_MATCHING_CMD_START_MATCHING
LATENCY_MODE_MATCHING_POLLING_CMD_GET_MATCHING_RESULT
LATENCY_MODE_MATCHING_PROCESS_CMD_GET_MATCHING_RESULT
LATENCY_MODE_MATCH_SETTEING_INIT
LATENCY_MODE_SESSION_CMD_GET_TURN_SERVER_LIST
LATENCY_MODE_SESSION_POLLING_CMD_GET_GAME_SESSION
LATENCY_MODE_SESSION_PROCESS_CMD_GET_GAME_SESSION
LATENCY_MODE_CONNECT
LATENCY_MODE_CONNECT_MODE_MULTIPLAY
LATENCY_MODE_WHOLE_CONNECTING
LATENCY_NTL_PUNCHING_PRE
LATENCY_NTL_PUNCHING_RETRY
LATENCY_NTL_PUNCHING_TIME
LATENCY_NTL_PUNCHING_PROCESS
LATENCY_NTL_PUNCHING_PROCESS_ON_SUCCESS
```

Related metrics: `LATENCY_TURN_RESOLVING_NAME_MIN/MAX/MEAN`,
`LATENCY_TURN_CONNECT_ANY_MIN`, `GAMRERELAY_MEASUARE_RESULT_AT_MATCHING`,
`CS_SERVER_ADDRESS`, `CS_SERVER_REGION`.

So the order is **matching → session (TURN + game session) → connect →
NTL punching (hole punching) → playing**.

## 7. Where the endpoints live

| Literal in `libUE4.so` | Offset | Meaning |
|---|---|---|
| `pes22-game.cs.konami.net` | `0xa5ed56` | the gate host |
| `gate/gate_` | `0x9c69b6` | the path is assembled: `…/gate/gate_` + `CMD_…` + `.php` |
| `http://ntl.service.konami.net/ntl/api/GateInfo.php` | `0xaaba08` | NTL gate-info endpoint (next to `STUN_PING_TIMEOUT`, `HOST_DIRECT`) |
| `pesam.stun.service.konami.net` | `0xbc9e65` | the STUN server |
| `https://info.service.konami.net/XWW020-E1/info/` | `0xb8f7fd` | info service |
| `pes-custom-encrypt` | `0xad120e` | the header name — sits right after `Game\Online\OnlineSystem\Api\OnlineSystemApiManagerver3.cpp`, i.e. **this is the class that builds gate requests** |
| `Def_Online_gRPC_server_path`, `grpc_heartbeat_interval_msec` | `0x9c69b6` | gRPC config keys |
| `CmdCreatejoinRoom.php` + `sender_user_id` + `is_invited` | `0xba1aaa` | room-join request fields |
| `CmdGetGameSession.php` + `auth_code` | `0xb7b7a2` | session request fields |

`Cmd*.php` is a second filename family (`CmdGetGameSession.php`,
`CmdGetMatchingResult.php`, `CmdAcceptFriendRequest.php`, …) sitting in the
same string table as the `CMD_*` names — the PHP side of the gate.

## 8. What PeerLink's own match capture showed (internet side)

From `CAPTURE_AUTOPSY.md`, verified full-byte:

* **Match supervisor** — DTLS 1.2 (`17 fe fd 00 01`), high UDP ports on
  GCP/AWS, ~4.5 s cadence, 208 B out / 190 B in. This is the session channel.
* **Ping/keepalive mesh** — UDP 5521 (Google), 10000/30000/50000 (AWS/Agones).
  Never missed a beat, through every stall.
* **TURN** — `turn.konami.com` referenced in the autopsy but **never touched**
  in capture: relay counters were zero. Direct P2P was in use.
* **Agones** — `agones-ping.<region>.nabeshin.people.aws.dev` is Konami's
  game-server fleet (matches the `quality_check_data_list` we decoded).
* The decoded `GET_GAMERELAY_QUALITYCHECK_LIST` response is exactly that
  ping list: `region` + `address` (`ip:port@nogs` or `host:5521`).
* The decoded `SET_GAMERELAY_QUALITY` request is the measured latency per
  region (`quality` = ms, `last_update` = unix time).

## 8b. Error-code model (settled)

Server returns `result` + `errcode` (`XXXX-` + base) + optional `msg`.

| prefix | meaning | notes |
|---|---|---|
| `GKZX-` | `ERR_INVALIDARG` | arg presence/type. Runs **before** the version check. |
| `QIQX-` | version not in the known-candidate list | reports `ERR_DEFCLIENTVER` |
| `CIYU-` | version recognised, a later check fails | also reports `ERR_DEFCLIENTVER`; the `s_keyword` failure lives here |
| `OTZP-` | `ERR_INVALID_SESSION` | session-gated; **skips** the version check |
| `WFJS-` | `ERR_ONLINEPASS` | `auth_code` rejected |
| `JPWM-` | `ERR_DATABASE` | server-side DB error |
| `JPXN-` | `ERR_INVALIDARG` (alt) | see `proofs/` |

**Oracle order: args → session → maintenance**, with the version check after
arg-presence and skipped for session-gated commands.

Request-side axes were exhausted trying to clear `CIYU-` at 6.1.0 — UA slots,
`lang`, `region`, `platform`, `my_platform`, `s_keyword`, `rqid`, `user_id`,
`session_id`, `client_version` (~40 values). A byte-perfect captured request
also failed. **No request-side cause existed besides `s_keyword`.**

Accepted `client_version` = {`6.1.0`, `6.1.1`} only; the rule is
**major − 5** (11.1.0 → 6.1.0). Valid `my_platform` = {`ANDROID`, `IOS`,
`PS4`, `PS5`, `STEAM`, `XBOXONE`}.

## 9. Open

0. **`nat_type` value semantics** — which bit/number means "NAT is open, go
   direct" is not yet pinned down. See §10c.
   **Class B is still unnamed** — see §10a. Resolving its vtable needs an APS2
   `.rela.dyn` decoder (the relocation section is Android-packed, so slots read
   as zero in the file).
1. **No capture yet contains a room message.** `CMD_CREATEJOIN_ROOM`,
   `CMD_GET_ROOM_LIST`, `CMD_JOIN_ROOM` have never been seen on the wire.
   Both captures stop at the main menu / myClub.
2. `hash` (32 lower-hex) derivation is still open — but it does **not**
   block login; see §3.
3. Match/UDP gameplay payload is still opaque (DTLS + game framing).
4. `a4/a5/a6` on the gate sender — documentation item only; see `proofs/xref_post.txt`.
5. `info.service.konami.net/XWW020-E1/info/` returns **403 — stopped, not to
   be retried.**

---

## 10. Direct P2P vs TURN relay — how the client decides

Measured from `libUE4.so` 11.1.0 (build in `game111/`). All addresses are VAs
in that build. Section 9 items 0 and the class-B question live here.

### 10a. The factory

`createStrategy()` @ `0x7ced7f0`, in the TU whose `__FILE__` is
`OnlineSystemMultiplaySession.h` (`0xaf747f`):

```
obj    = 0x82262d0()                 ; global 0xa5fb0a8, the Android app singleton
mode   = 0x822886c()                 ; *(u8*)obj      (setMode() writes this byte)
list   = 0x7e0afcc() -> 0x7e23478()  ; global 0xa5d9d50, the TURN server list

if (mode == 0x1b) {
    v = getInt("direct_online_turn_mode")          ; 0x2f48f28
    2 -> D,  1 -> C,  0 -> B,  else -> null
} else {
    if (list empty) -> A
    v = getInt("turn_mode")                        ; 0x2f48f28
    ; jump table 0xca4a86, bytes {0,11,0,18}, base 0x7ced894
    0 -> D,  1 -> C,  2 -> D,  3 -> A,  >3 -> D
}
```

### 10b. Neither setting key is ever written — so this is what ships

The settings store is a `std::unordered_map<std::string, …>` at global
`0x9baea68`. Its lazy init `0x2f48464` only stores `1` into the guard byte
`0x9baea60` — **it inserts no entries**. `0x2f48f28(name, len)` is a `find`;
on a miss it returns **0** (`0x2f49088: mov w21, wzr`).

* `direct_online_turn_mode` — exactly **one** reference in the whole binary:
  the getter, `0x7ced804`.
* `turn_mode` — exactly **one**: the getter, `0x7ced860`.
* Neither key exists in shipped data. `base.apk`,
  `split_config.arm64_v8a.apk`, `split_pad_it_0.apk` → 0 hits. `gamedata.tgz`
  streamed (gzip, 423 members) → 0 hits. There is no ini/json/cfg member at
  all: 280 files are `.ucas`/`.pak` asset packs plus
  `files/SaveData/SYSTEM/SYSTEM000`.

Both lookups therefore return 0 on every device:

| app state `mode` | TURN list | strategy |
|---|---|---|
| `0x1b` | not consulted | **B** |
| anything else | empty | **A** |
| anything else | non-empty | **D** |

**Strategy C (relay-only) is unreachable in the shipped build.** It would need
`direct_online_turn_mode == 1` or `turn_mode == 1`, and nothing writes either.

### 10c. What the four strategies are

Object size from the `operator new` in the factory; behaviour from a histogram
of `bl` targets inside each class's code range.

| class | code range | object | into TURN/STUN `0x7d80000-0x7d88000` | into NTL core `0x7db8000-0x7dc0000` | verdict |
|---|---|---|---|---|---|
| A | `0x7d34eb4-0x7d36610` | `0xbe0` | 0 | **28** | UDP hole punching through the NTL core. No TURN. |
| B | `0x7d36610-0x7d36d80` | `0x2ce0` | 0 | 0 | No TURN, no NTL. Owns an ~11 kB context. |
| C | `0x7d36d80-0x7d3a000` | `0xef0` | **25** | 0 | `…P2pFullMeshTurnOnly.cpp`. Relay only. |
| D | `0x7d3a000-0x7d3b900` | `0xbc0` | 7 | 0 | `…P2pFullMeshWithTurn.cpp`. Direct + TURN fallback. |

Only C and D carry a `__FILE__` string inside their own code. A and B carry no
log/assert strings at all, so they cannot be named from a source path; every
`OnlineSystemMultiplaySessionStrategy*.cpp` string in the binary is one of
`WithTurn.cpp`, `TurnOnly.cpp`, `SessionStrategy\Session\OnlineSystemObserveSession.cpp`.
A and B therefore come from `OnlineSystemMultiplaySession.cpp` / `.h`.

The config-key families in the binary corroborate the split:
`MultiplaySessionStrategyIoBufferSendSize`, `…IoBufferRecvSize`,
`ChannelReceiveBufferLength`, `FecQueueParityEncoderMaxBufferLength` are the
own-transport knobs B's 11 kB object would hold, while `TURN_QUALITY_*` and
`LATENCY_TURN_*` belong to C/D. B's support module `0x7d0a000-0x7d20000` has
only `Mobile`, `Android`, `,`, `status`, `success`, `fail`, `unknown` — a
result-code vocabulary, not a protocol one. B also builds the literal pair
`("0.0.0.0", 30000)` (`0xc2fc88` = `{0, 0x7530}`).

### 10d. NAT classification is done on the client, before the room exists

* RFC 5780 mapping/filtering tests: `MappingTestIA`…`MappingTestIG`,
  `MappingTestII/III/IV`, `HairpingTest`. Driven by the state machine at
  `0x7dcb9e0`, which dispatches on `[ctx+0x340] == [ctx+0x344]`
  (completed-bitmask vs required-bitmask).
* The composed result lives at `[ctx+0x31c]`; getter `0x7dc602c`. When it is 0
  the getter falls back to the global `0xa5d7618`, which is **never written**
  (one ADRP reference in the whole binary — the fallback read itself).
* Composition `0x7dcc968…0x7dccb7c`: ORs `0x10`, `0x20/0x21/0x22/0x23`, `0x40`,
  `0x44` or `0x4c`, `0x100`, `0x400000`, `0x800000` in from the per-test bits at
  `[ctx+0x350]` and the bools at `[ctx+0x34c..0x34e]`. If the two primary
  mapping bits are not both set it instead writes the **placeholder 2 or 3**
  (`0x7dcc988…0x7dcc998`). So the low bits are a coarse class and the upper
  bits are per-test capability flags.
* The state vocabulary confirms the client runs the whole traversal itself:
  `DETECT_NAT_{COMPLETE,ABORTED,ERROR}`, `STUN_TEST_{PROGRESS,COMPLETE,ERROR}`,
  `START/KEEP/STOP_UDP_HOLE_PUNCHING_{PROGRESS,COMPLETE,ERROR}`,
  `ALLOC_TURN_PORT_*`, `FREE_TURN_PORT_*`,
  `ALLOC_TURN_CHANNEL_BINDING_*`, `START_SERVER_UDP_SESSION_COMPLETE`.
  `TURN_CHANGEOVER_{REASON,TIME}` and `TURN_OFF_COMMUNICATE_COUNT` show that a
  mid-session switch back to direct is implemented too.
* Peer statuses: `NONE, INIT, TIMEOUT, UDHP, FORMALLY_TIMEOUT, RESTRAINED,
  ALLOC_CHNL, ALLOC_PERM, ACCEPTABLE, FORMALLY_CONNECTED, CONNECTED, ABORTED,
  BAD_ROUTE, G_TIMEOUT, CLASH`.
* `RP_NAT_TYPE` (private STUN attribute `0x9097`) travels **peer to peer**, not
  to the server: the parser at `0x7dd7c58` reads it as a 32-bit big-endian int
  out of a peer's attribute list (`ldr w8,[x8,x22]; rev w6,w8; str w6,[x25]`).

### 10e. Transport endpoint type (`[peer+0x1a8]`, switch `0x7debaa4`)

`0x1 HOST_DIRECT`, `0x2 HOST_RELAY`, `0x100 PEER_HOST`, `0x200 PEER_REFLEXIVE`,
`0x400 PEER_RELAYED`, `0x1000 PEER_STUN`, `0x2000 PEER_TURN`,
`0x1000000 TARGET_CHAOS`, `0x2000000 TARGET_PEER`,
`0x4000000 TARGET_STUN_SERVER`, `0x8000000 TARGET_TURN_SERVER`.

### 10f. Full STUN / NTL attribute table

Decoded from `0x7dcac34`, tables `0xca4eed` / `0xca4f18` / `0xca4f25`.
Range rule: `w0 - 0x8020 <= 12`, `w0 - 0x9090 <= 13`, `cmp w0,#0x908f; b.gt`.

Standard: `0x0001 MAPPED_ADDRESS` … `0x000d LIFETIME`, `0x0012 XOR_PEER_ADDRESS`,
`0x0013 DATA`, `0x0014 REALM`, `0x0015 NONCE`, `0x0016 XOR_RELAYED_ADDRESS`,
`0x0017 REQUESTED_ADDRESS_FAMILY`, `0x0018 EVEN_PORT`,
`0x0019 REQUESTED_TRANSPORT`, `0x001a DONT_FRAGMENT`,
`0x8020 XOR_MAPPED_ADDRESS_3489`, `0x8022 SOFTWARE`, `0x8023 ALTERNATE_SERVER`,
`0x8028 FINGERPRINT`, `0x802B RESPONSE_ORIGIN`, `0x802C OTHER_ADDRESS`.

Konami private `0x9090-0x909d`: `RP_P2P_HEADER`, `RP_RELIABILITY`,
`RP_AMF_DATA`, `RP_JSON_DATA`, `RP_HOST_ADDRESS`, `RP_REFLEXIVE_ADDRESS`,
`RP_RELAYED_ADDRESS`, **`RP_NAT_TYPE`**, `RP_SYNC_POINT`, `RP_ENTRY_IDX`,
`RP_PEER_STATUS`, `RP_RAND_SEED`, `RP_RELIABILITY_ECHO`, `UHP_FINALIZE_RET`.
Plus `0x9999 TERM`, `0xf000 ATTR_EXTENSION`.

### 10g. Conclusion

**Direct P2P is the shipped default.** Relay-only is unreachable and TURN shows
up only as the fallback inside D. The one thing that can still push a match
onto TURN is the client's *own* NAT mapping test failing — not a server
instruction. This matches §8: our captured match never touches TURN.

Open, in priority order:

1. What `mode == 0x1b` is. Setter `0x822882c` (`strb w1,[x0]` plus a virtual
   notify at vtable slot `0x4e`); 56 call sites, none passing a literal `0x1b`
   — it arrives through the translation tables at `0xc40c24` / `0xca02a4`.
2. Which `natType` value or flag means "open". §10d gives the composition, not
   the read that decides.
3. Class B's identity. Blocked on an APS2 `.rela.dyn` decoder — the
   relocation section is Android-packed, so vtable slots read as zero in the
   file.
