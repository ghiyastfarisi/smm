# Proving the encryption at rest

```bash
ADMIN_USER=<admin> ADMIN_PASSWORD=<password> node deploy/prove-encryption.mjs   # ~10 s, on the host; cleans up after itself
```

The script writes fresh **canary** data through the normal API (a message with a hashtag, a text file, a draft,
and a user's email, names, nickname and position all containing a random `canary…` string), then inspects what the
server actually stored. Each line is PASS/FAIL; exit code 1 on any failure.

| # | Check | What it proves |
|---|---|---|
| 1 | `pg_dump` of the whole database contains no canary (also not the message, file name, first name or e-mail) | nothing written through the app reaches PostgreSQL in plaintext — tables, indexes and search tokens included |
| 2 | `tar` of the whole file store contains no canary | uploaded file contents are not on disk in plaintext |
| 3 | channel data looks like `enc:v4:<key id>:<team id>/<channel id>:posts.message#<post id>:<base64>`; global data (users, tokens, audits) like `enc:v3:<key id>:users.email#<user id>:<base64>` | AES-256-GCM, versioned, with the key id, the channel scope and a label naming the column and row |
| 4 | the uploaded file starts with `MMENCF3 <key id>`; every file in the store has the header | file blobs are encrypted (chunked AES-GCM, key per team + channel, path as associated data) |
| 5 | the session token we hold is not in the dump; its SHA-256 is | a database copy gives no usable login tokens |
| 6 | search tokens are 64-hex HMAC-SHA256 values | the search index stores keyed hashes of words, not words |
| 7 | the `ENCRYPTION_KEY` / `ENCRYPTION_KEY_FACTOR` values from `deploy/.env` are not in the dump; the server container's environment has no `ENCRYPTION_KEY*`; the root secret in OpenBAO equals the `.env` seed | keys are kept apart from the data and from the app container |
| 8 | the API returns the original message, profile and file; search finds the canary | it is encryption (reversible with the key), not loss |
| 9 | a ciphertext copied into another post's row — same channel or another channel — no longer decrypts there | values are bound to their team, channel, column and row; an attacker with database write access can't move or swap them |

Every check carries a checklist ID (`ENC-01`…`ENC-24`, `ENC-36`…`ENC-41`). Last run (2026-10-25): all checks PASS,
every stored file encrypted, every search token an HMAC.
e-mail addresses on account deletion (`app/user.go`); the fork now logs a short hash instead (`app/log_redact.go`).

## Key custody

`keyring.Load()` (`server/platform/shared/keyring`) is the single entry point for the SQL store, the
file store and the app (`storedFileName`); nothing else reads key material.

- **OpenBAO** (always on: `docker compose up -d` runs it with sealed raft storage, Shamir 3/5 unseal, AppRole with a
  read-only policy and a file audit device; `openbao-setup` initialises and unseals it): with `OPENBAO_ADDR` set, the root secret is read once per
  process from KV v2 at `OPENBAO_KV_PATH` (default `secret/data/mrpostman/root`, fields `key`, `factor`,
  `old_keys`, `old_factors`) with `OPENBAO_TOKEN` or AppRole (`OPENBAO_ROLE_ID` + `OPENBAO_SECRET_ID`). The server
  container's environment holds no `ENCRYPTION_KEY*` (ENC-38). If the fetch fails for any reason the server refuses
  to start — there is no silent fallback to the environment. `openbao-setup` writes the secret from `deploy/.env`
  only when the path is empty, so a restart keeps the kids and the
  data readable. Details and production steps:
  `deploy/openbao/README.md`.
- **Environment fallback**: without `OPENBAO_ADDR` the `ENCRYPTION_KEY*` variables work as before (single-host).

## Key hierarchy and formats

```
root            = (master = ENCRYPTION_KEY, factor = ENCRYPTION_KEY_FACTOR)         kid = HKDF(root, "mrpostman/v3/kid")[:8 hex]
global key      = HKDF-SHA256(master, salt = factor, info = "mrpostman/v3/db-field")   → enc:v3 (users, tokens, audits, team e-mail)
blind-index key = HKDF(root, "mrpostman/v3/blind-index")                             → HMAC word hashes (global: search spans channels)
channel key     = HKDF(root, "mrpostman/v4/channel/<teamId>/<channelId>")           → enc:v4 (posts, hashtags, header/purpose-change props, drafts, scheduled posts, channel header + purpose, file names/contents)
file key        = HKDF(HKDF(root, "mrpostman/v3/file-blob"), salt, "mrpostman/v4/channel/<teamId>/<channelId>")   → MMENCF3 blobs
```

- `enc:v4:<kid>:<scope>:<label>:<b64(nonce|ct)>` with `scope = <teamId>/<channelId>` (`-` for no team: DMs/GMs;
  `-/-` when a row has no channel) and GCM AAD = `scope:label`. The team id is resolved from the channel once per
  process and cached in the cipher; the scope travels with the ciphertext, so decryption needs no lookup. Readers
  that know the row's channel (post, draft, scheduled post, file info structs) reject a ciphertext whose scope names
  another channel (ENC-37); scans into bare strings still get integrity and key binding.
- Files: `MMENCF3\0 | kid | salt | noncePrefix`, scope parsed from the storage path
  (`…/teams/<teamId>/channels/<channelId>/…`, else `-/-`; DM uploads carry Mattermost's `noteam` id there), path
  as AAD. `MMENCF2`/`MMENCF1` still decrypt; Copy/Move re-encrypt under the destination path.
- `enc:v3`/`v2`/`v1` stay readable. Every start seals plaintext users, channel headers/purposes, drafts and scheduled
  posts and re-seals v1–v3 drafts/scheduled posts as v4. `ENCRYPTION_BACKFILL=true` (once, after a root rotation or an
  upgrade) also re-seals posts, file infos, channel headers/purposes, header-change props, drafts and scheduled posts not
  yet `enc:v4:<current kid>` and rebuilds the search tokens. ENC-42 in `deploy/prove-encryption.mjs` counts the rows
  still on an older format or kid (must be 0).
- Crypto-shred ceiling: a channel's key is derived, not stored, so deleting a channel does not destroy its key —
  only a root rotation + backfill (which re-seals what still exists) retires old ciphertext. A stored per-channel
  key (envelope) would be the next step if per-channel shredding is required.

## Covered
Post messages and hashtags, channel headers and purposes (`Channels` and `PublicChannels`, and the old/new values in
header/purpose-change system posts), drafts, scheduled posts, file names, extracted file text and file contents, user e-mail,
first/last name, nickname, position, MFA secret, audit records, team e-mail; session and personal access tokens are
hashed; webhook and slash-command tokens are encrypted. Code: `server/channels/store/sqlstore/{post,pii,channel}_crypto.go`,
`server/platform/shared/filestore/encrypted.go`.

## Not covered (plaintext by design or not done yet)
- **Usernames, team names, channel names and display names**: needed for login, @mentions, URLs and lookups.
- **Other post props** (message attachments, integration payloads): plaintext (ENC-33, 2.0.0). Channel search no longer
  matches words of a channel's purpose (it is ciphertext); name and display name still match.
- Metadata: timestamps, who is in which channel, reactions (emoji names), preferences, file sizes and types.
- **In transit**: this dev stack is plain HTTP. Production needs TLS in front of nginx (and to Postgres if remote).
- Push notification payloads, e-mails, logs and server memory; keys come from
  OpenBAO (see "Key custody"); an HSM-backed OpenBAO seal is the next step.
- **Search trade-off**: `ENCRYPTION_PREFIX_SEARCH=true` (on in `deploy/docker-compose.yml`) adds hashed word prefixes
  so `alph*` works; that shows someone with the database which words share a prefix. Set it to `false` to drop it.
