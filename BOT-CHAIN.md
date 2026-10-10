# Bot chain — live 1v1 room flow (credential-free)

The scripts that drive two identities through a full lobby 1v1 match on the
live gate: login → relay quality → create room → join ladder → squads →
ready → session check → START_GAME → phase walk → goals → result.

They are safe to commit by construction: the owner identity is decoded at
runtime from the COMMITTED ciphertext capture
(`peerlink-efootball-disconnects/kgs-login/captures/2026-10-01-gate/gate-login-exchange.txt`)
and patched only with fresh rqid/client_version/s_keyword.

## Run

    python chain3.py            # offline self-test
    python chain3.py --live     # full match on the live server

Every script resolves paths from the project root (`ROOT` in `room1.py`),
so it runs from any checkout position under the root.

## Local-only (never committed)

    C:\...\Default Project\work\bot_identity.json   bot credentials
    C:\...\Default Project\work\bot_create.json     bot roster

`room2.py` points at those files; they stay in `work\`, which is not a
repository. Anyone else running the chain mints their own with `mint.py`.

## Pieces

| file | role |
| --- | --- |
| `room1.py` | Gate client: envelope, send, pacing, login, create room |
| `room2.py` | Bot identity, join body, bot login |
| `chain3.py` | The full green chain (login → match → result) |
| `mint.py` | Mint a bot account, write local identity |
| `squad_fix.py` | Resolve squad → GET_USER_SQUAD NOERR (23 players) |
| `squad_probe.py`, `sendreq_probe.py`, `join_sweep.py`, `lookup_probe.py` | one-axis probes |
| `room_info_shape.py`, `decode_cap.py` | response shaping / capture decoding |
| `redact.py` | stdin→stdout credential redaction — run all output through it |
| `xref2.py`, `dump_keys.py`, `builder_of.py`, `dis_range.py`, `cmd_names.py`, `rootkeys.py` | libUE4.so RE tools |
| `sgr_rootkeys_newbuild.txt` | CMD_SET_GAME_RESULT serializer key map |

## Known gap

The run ends with the server publishing a forfeit 0-3 (`gameend_reason:
DISCONN`, `abnormalend_reason: DISCONN_HB`) because the bot holds no gRPC
`CommandStream` heartbeat. The real game keeps exactly one TLS stream to
`pes22-game.cs.konami.net:443` and sends a beat every 15.0 s for the whole
match (measured in `captures/match-2026-09-26` pass-through). Closing that
gap is the next experiment.
