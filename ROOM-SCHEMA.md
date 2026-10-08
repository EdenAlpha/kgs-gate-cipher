# ROOM-SCHEMA.md — recovered gate request schemas

All schemas below were recovered by *driving the server into telling us*,
not by guessing. The method is the valuable part.

## The method: `client_version=6.1.1` is a verbose validator

| `client_version` | behaviour on a bad body |
|---|---|
| `6.1.0` | silent `GKZX-` / `ERR_INVALIDARG`, no message |
| `6.1.1` | `input error: <PHP class>::<method>(): <reason>, called in /data/pes22/htlocal/core/command/template/<CMD>.php on line N` |

So: **diagnose on 6.1.1, replay on 6.1.0.**

The reason both are needed: a session obtained by `CMD_LOGIN` at 6.1.0 is
rejected at 6.1.1 with `ERR_INVALID_SESSION` / `"session restart failed"`.
At 6.1.0 the *input* gate is never reached for a valid body. So:

1. authenticate at **6.1.0** (the version the account actually exists on),
2. send a deliberately-incomplete body at **6.1.1** to get the error text,
3. iterate on 6.1.1 until the error moves from `input error:` to
   `ERR_INVALID_SESSION` — that means **input validation has passed**,
4. send that exact body at 6.1.0.

`ERR_DATABASE` at step 4 means the request was well-formed but the thing
asked about does not exist — that is a *successful* schema, not a failure.

## Type rules that broke every first attempt

* **Enums are strings, not ints.** `cross_platform_option`, `vacancy`,
  `is_room_search`, `friend_info_type`, `kind`, `mode` all demand strings.
  Sending `0` returns `must be of type string, int given`.
* **Booleans are strings.** `is_room_search` must be e.g. `"NO"`, not
  `false`.
* **`room_id` is an array** — `must be of type ?array, string given` /
  `int given`. Sending `null` returns `ROOM_ID:"room_id' is not nullable'`.
* **For `CMD_GET_ROOM_LIST`, `room_id` is NOT a top-level key.** It lives
  inside `filter_settings`. Sending it at top level silently reads back
  `null` and fails `not nullable`.
* Empty msgpack dict `{}` decodes to PHP `stdClass` and fails
  `must be of type ?array, stdClass given`; use a list `[]` or a
  non-empty dict where a dict is wanted.
* Unknown *values* give `out_of_range:<VALUE>` and echo the value back —
  live confirmation the key itself was right.

## `CMD_GET_ROOM_LIST` — CONFIRMED WORKING

Request (on top of the standard 10-key envelope):

```json
{
  "start_index": 0,
  "num": 10,
  "kind": "STRIKE_ARENA",
  "mode": "ROOM_VACANCY_AND_WAITING",
  "platform": "ANDROID",
  "cross_platform_option": "YES",
  "filter_settings": { "room_id": ["0"] },
  "is_room_search": "NO"
}
```

Response:

```json
{
  "result": "NOERR",
  "msgid": "CMD_GET_ROOM_LIST",
  "room_info": [],
  "is_see_more": "YES"
}
```

Enum values established by the oracle: `kind` ∈ {`STRIKE_ARENA`},
`cross_platform_option` ∈ {`YES`, `NO`}. `filter_settings` accepts any
non-empty dict at this stage — only `room_id` inside it is reachable.

Builder string table (11.1.0 `libUE4.so`, request builder `0x788fe9c`):
`kind`, `start_index`, `num`, `mode`, `enable_room_id`, `id`, `room_id`,
`enable_name_tag`, `name_tag`, `enable_room_kind`, `room_kind`,
`enable_room_entry_restriction`, `room_entry_restriction`,
`enable_vacancy`, `vacancy`, `enable_equalization`, `equalization`,
`enable_regulation`, `regulation`, `enable_match_time`, `match_time`,
`enable_condition_home`, `condition_home`, `enable_condition_away`,
`condition_away`, `filter_settings`, `platform`, `cross_platform_option`.
Enum literals present in the same function: `ROOM_VACANCY_AND_WAITING`,
`CONDITION_NORMAL`.

Note the `enable_<field>` / `<field>` pairs: the client only sends the
value when the matching `enable_` flag is set, so a verbatim replay needs
flags and values to agree.

## `CMD_GET_ROOM_INFO` — VALIDATION PASSES

```json
{
  "mode": "STRIKE_ARENA",
  "id": 0,
  "room_id": ["0"],
  "event_id": 0,
  "user_compe_id": 0,
  "is_room_search": "NO"
}
```

Clears every input check, then returns `ERR_DATABASE` — expected, since
room id `0` does not exist. `mode` ∈ {`STRIKE_ARENA`}.

## `CMD_GET_FRIEND_LIST` — PARTIAL

Requires `friend_info_type` (string) and `target_user_id_list` (array).
Every `friend_info_type` candidate returns
`friend_info_type:out_of_range:<VALUE>`, so its valid set is server-side
only and not discoverable from the binary. Tried and rejected:
`SUMMARY`, `DETAIL`, `ALL`, `FRIEND`, `FRIEND_SUMMARY`, `FRIEND_DETAIL`,
`summary`, `detail`, `all`, `0`–`2`, plus variants. Response keys that do
exist: `friend_summary_info_list`, `friend_detail_info_list`,
`new_arrival_request_num`.

## Errcodes added by this pass

| prefix | string | stage |
|---|---|---|
| `QWZF-` | `ERR_UNUSABLE_CHARACTERS` | value validation (after type) |
| `EVDU-` | `ERR_DATABASE` | server-side DB lookup |

## Commands that already work with the envelope alone

`CMD_GET_SERVER_ENV`, `CMD_GET_GAMERELAY_QUALITYCHECK_LIST`,
`CMD_GET_TURN_ADDRESS_DATA`, `CMD_CHECK_MATCH_ENABLE`,
`CMD_WATCH_INVITATION`, `CMD_GET_SESSION_ID` (needs `game_id` as int).

Note that extra unknown keys are **tolerated** — `CMD_CHECK_MATCH_ENABLE`
with seven additional injected keys still returned `NOERR` — so arg
discovery is safe to do by addition.
