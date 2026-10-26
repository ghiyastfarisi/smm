# smm architecture

smm (Secure Mattermost) is the Mattermost server and stock clients with one added layer: everything that matters is
encrypted before it reaches Postgres or the file store, under keys that only a key management service (OpenBAO)
holds. Clients, APIs and the user experience stay Mattermost's. Attribution and licences: [`../../NOTICE.md`](../../NOTICE.md).

## 1. Components

```
                ┌──────────── clients (unchanged protocol) ─────────────┐
                │ browser (stock web app)   desktop app    mobile app    │
                └──────────────┬────────────────────────────────────────┘
                               │ HTTPS + WebSocket (TLS at your proxy or the bundled edge)
┌──────────────────────────────▼──────────────────────────────────────────────────┐
│ smm server                                                                      │
│  API · WebSocket · app layer · stock web app (served from the image)             │
│  ┌──────────────────── store layer (where smm hooks in) ──────────────────────┐  │
│  │ sqlstore: seal on write / open on read (AES-256-GCM, AAD) · HMAC search     │  │
│  │ filestore: encrypted blobs (MMENCF3)                                        │  │
│  │ keyring: the only code that holds key material                              │  │
│  └──────────────┬───────────────────────────────────────┬────────────────────┘  │
└─────────────────┼───────────────────────────────────────┼───────────────────────┘
                  │ ciphertext only                       │ once at start: AppRole login, read root secret
          ┌───────▼────────┐  ┌───────────────┐   ┌───────▼─────────────────────────────┐
          │ PostgreSQL 16  │  │ file store    │   │ OpenBAO (KMS)                        │
          │ enc:v3/v4 rows │  │ MMENCF3 blobs │   │ sealed raft storage, Shamir 3-of-5,  │
          └────────────────┘  └───────────────┘   │ read-only AppRole policy, audit log  │
                                                   └──────────────────────────────────────┘
Optional: your own push proxy (generic contents only), your own OpenID Connect IdP, nginx TLS edge.
```

| Service (`deploy/docker-compose*.yml`) | Role | Default port |
|---|---|---|
| `db` | PostgreSQL 16, holds ciphertext only | internal |
| `openbao`, `openbao-init` | KMS; `-dev` in memory for development, sealed raft with the KMS profile | `127.0.0.1:8200` |
| `server` | smm server + stock web app | `8065` |
| `tls` (`--release`) | nginx TLS edge, HSTS, IP allow-list | `8443` |

## 2. How smm extends Mattermost

smm changes as little upstream code as possible so upstream releases can still be merged:

- **Store layer, not the app layer.** Encryption sits in `sqlstore` (seal on write, open on read) and in a wrapping
  `filestore` backend. The app layer, API, WebSocket events and clients see plaintext as before, so every stock client
  keeps working.
- **One key entry point.** `server/platform/shared/keyring` (`keyring.Load()`) is the only code that reads key
  material. The SQL store, the file store and the app all get keys from it.
- **Migrations, not schema rewrites.** `000235`–`000241` add the search-token table, hash session/access tokens and
  widen columns for ciphertext. Existing plaintext is sealed by a pass at start-up.
- **Configuration through the environment.** Security settings that must not drift are set as `MM_*` variables in
  `deploy/docker-compose*.yml`; the System Console shows them read-only.
- **Removed, not disabled:** the source-available `server/enterprise/` code is deleted. Open-source substitutes in
  `deploy/` cover what it provided: `records.mjs` (compliance export, retention) and `nginx-allow.conf` (IP allow-list).

| Upstream area | smm change | Files |
|---|---|---|
| Posts, drafts, scheduled posts, channels | sealed v4 under the channel key | `sqlstore/post_crypto.go`, `channel_crypto.go`, `post_store.go`, `draft_store.go`, `scheduled_post_store.go` |
| Users, teams, audits, integrations | PII sealed v3 under the global key; tokens hashed or sealed | `sqlstore/pii_crypto.go`, `user_store.go`, `session_store.go`, `webhook_store.go`, `command_store.go` |
| Search | HMAC word tokens instead of plaintext full-text search | `post_crypto.go`, migration `000235` |
| Files | encrypted blobs, path as AAD | `platform/shared/filestore/encrypted.go` |
| Keys | OpenBAO client, HKDF hierarchy, rotation | `platform/shared/keyring/keyring.go` |
| Login | native OpenID Connect provider | `app/oauthproviders/openid/` |
| Logs | redaction of sensitive values | `app/log_redact.go` |
| Outbound calls | none to Mattermost, Inc. (telemetry, update check, marketplace, push service off) | `deploy/docker-compose.yml` |
| Web app | branding (strings, logo, favicons) | `webapp/channels/src/...` |

## 3. Encryption

### 3.1 Key hierarchy
```
root (master = ENCRYPTION_KEY, factor = ENCRYPTION_KEY_FACTOR)       held in OpenBAO, key id = HKDF(root,"…/kid")[:8 hex]
 ├─ global key      = HKDF-SHA256(master, salt=factor, "mrpostman/v3/db-field")     users, tokens, audits, team e-mail
 ├─ blind-index key = HKDF(root, "mrpostman/v3/blind-index")                         HMAC-SHA256 search tokens
 ├─ channel key     = HKDF(root, "mrpostman/v4/channel/<teamId>/<channelId>")        messages, hashtags, drafts, scheduled
 │                                                                                    posts, header/purpose, file metadata
 └─ file key        = HKDF(HKDF(root,"mrpostman/v3/file-blob"), per-file salt,
                           "mrpostman/v4/channel/<teamId>/<channelId>")              file contents
```
Keys below the root are derived, never stored. Every channel (and every DM or group chat) has its own key.

### 3.2 Sealed value format
```
enc:v4:<key id>:<teamId>/<channelId>:posts.message#<postId>:<base64(nonce | ciphertext | tag)>
```
- **AEAD:** AES-256-GCM with a fresh random 96-bit nonce per encryption.
- **AAD = `<teamId>/<channelId>:<table>.<column>#<rowId>`.** A value copied to another row, column, channel or team
  fails authentication. Readers that know the row also compare the label with the row they read (test ENC-37).
- DMs and group chats have no team: scope `-/<channelId>`. Rows without a channel: `-/-`.
- Global data uses `enc:v3:<key id>:<label>:…` (AAD = label). `v1`/`v2` are legacy and decrypt only.
- Files: header `MMENCF3\0 | key id | salt | noncePrefix`, chunked GCM with the storage path as AAD; copy and move
  re-encrypt under the destination path.

### 3.3 Search
The server stores HMAC-SHA256 hashes of words (`post_search_tokens`), not words. A search term is hashed the same way
and matched. `ENCRYPTION_PREFIX_SEARCH=true` also stores hashed prefixes so `alph*` works; this shows someone holding
the database which words share a prefix. Set it to `false` to remove that leak.

### 3.4 Rotation and backfill
Rotation writes a new root to OpenBAO with the previous one in `old_keys`/`old_factors`, then one start with
`ENCRYPTION_BACKFILL=true` re-seals every row and file under the new key id and rebuilds search tokens.
`deploy/prove-encryption.mjs` check ENC-42 counts rows still on an old format or key id (must be 0).

## 4. Key custody (OpenBAO)

- The server reads the root secret **once at start** from KV v2 (`secret/data/mrpostman/root`) using AppRole with a
  **read-only policy** (`deploy/openbao/mrpostman-read.hcl`). The server container's environment holds no key.
- **Fail closed:** if OpenBAO is sealed, unreachable or denies the read, the server does not start. There is no
  fallback to environment variables when `OPENBAO_ADDR` is set.
- **Sealed storage:** raft on a volume, initialised with **Shamir 3-of-5** unseal shares. After any OpenBAO restart
  three share holders must unseal it before the server can start.
- **Audit:** OpenBAO's file audit device logs every access to the secret.
- **Keys off the host:** `kms-setup.sh forget-env-keys` removes `ENCRYPTION_KEY*` from `deploy/.env` after checking
  OpenBAO holds the same values and a backup exists. From then on OpenBAO is the only copy on the host.

## 5. Other hardening

| Area | Control | Where / test |
|---|---|---|
| Outbound | no calls to Mattermost, Inc.: telemetry, security-update check, remote marketplace and Mattermost's push service off | `docker-compose.yml`, SEC-27 |
| Push | off by default; only through a push proxy you run, with `generic` contents (no message text in the notification) | `docker-compose.yml` |
| Tokens | session and personal access tokens stored as hashes; webhook/slash-command tokens sealed | migration `000236` |
| Release profile (`--release`) | rate limit, 10 login attempts, password ≥ 12 with mixed classes, shorter sessions, MFA available, no developer/testing endpoints, HTTPS site URL + HSTS, CORS limited to the site origin, invite-only accounts, 50 MB file limit | `docker-compose.release.yml`, CFG-01…13 |
| Network | TLS edge, IP allow-list | `nginx-tls.conf`, `nginx-allow.conf`, OPS-23 |
| Records | decrypted compliance export (DMs included) and retention, run by an operator | `deploy/records.mjs` |
| Backups | database and file store backed up as ciphertext; OpenBAO raft snapshot separately | `backup.sh`, `restore.sh` |

## 6. What is not covered

- **Not end-to-end encryption.** The server decrypts to serve clients, so a compromised running server (or anyone
  with OpenBAO access) can read data. End-to-end encryption (MLS on new clients) is the 2.0.0 plan.
- **Plaintext by design:** usernames, team and channel names and display names (needed for login, @mentions, URLs).
- **Metadata:** timestamps, channel membership, reactions, preferences, file sizes and types.
- **Other post props** (message attachments, integration payloads) — planned (ENC-33).
- **Logs, e-mails, server memory** are outside this layer. Transport security comes from TLS.
- **No per-channel crypto-shredding:** channel keys are derived, so deleting a channel does not destroy its key. A
  stored per-channel key in OpenBAO (envelope encryption) is the next step if this is required.
- OpenBAO's seal is not HSM-backed yet.

## 7. Verification

| Command | Shows |
|---|---|
| `node deploy/prove-encryption.mjs` | every check of data at rest: ciphertext in every covered column, files encrypted, HMAC search tokens, no key in the server environment, rows on the current key |
| `go test ./channels/store/sqlstore/ -run 'TestPostCipher\|TestSealPosts'` (in `server/`, needs a test Postgres) | AAD binding: moved/swapped rows, other channel or team rejected |
| `bash deploy/up.sh --release`, then `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.release.yml config` | the locked release settings (CFG-01…13) |

Detailed proof and coverage list: [`ENCRYPTION.md`](ENCRYPTION.md). KMS operations:
[`../../deploy/openbao/README.md`](../../deploy/openbao/README.md).
