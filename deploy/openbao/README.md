# OpenBAO key custody

The server never holds `ENCRYPTION_KEY` / `ENCRYPTION_KEY_FACTOR` in its environment. At start it reads the
root secret from OpenBAO KV v2 (`OPENBAO_ADDR`, `OPENBAO_KV_PATH`, default `secret/data/mrpostman/root`) with
either `OPENBAO_TOKEN` or AppRole (`OPENBAO_ROLE_ID` + `OPENBAO_SECRET_ID`). Fields: `key`, `factor`,
`old_keys`, `old_factors` — same encodings as the old environment variables. If `OPENBAO_ADDR` is set and the
read fails (unreachable, sealed, wrong token, empty path) the server refuses to start; it never falls back to
the environment. Without `OPENBAO_ADDR` the environment variables still work (single-host installs).

## What `docker compose up -d` runs

- `openbao`: raft storage on volume `openbao-data`, sealed at every start (Shamir 3-of-5), file audit device on
  `openbao-audit` (`kms.hcl`). Port 8200 is bound to 127.0.0.1 for operator commands only.
- `openbao-setup` (`setup.sh`, one shot on every `up`): the first time it initialises OpenBAO and writes the 5 unseal
  shares and the root token to `deploy/openbao/secrets/init.txt` (host only, mode 600, gitignored), unseals, enables
  KV v2, writes the root secret from `.env` **only if the path is empty**, writes the read-only policy
  (`mrpostman-read.hcl`) and the AppRole, and puts the AppRole credentials into the `approle` volume. Later runs
  unseal with `init.txt` while it is still on the host; without it they wait for 3 holders.
- `server`: mounts only the `approle` volume (read-only) and logs in with AppRole. `docker compose exec server env`
  shows no `ENCRYPTION_KEY*` and no token; the shares and the root token never reach this container.

Inspect: `docker compose exec -e BAO_TOKEN=<root token> openbao bao kv get -mount=secret mrpostman/root`.

**Production (OPS-20).** Until then the root secret is in OpenBAO and still in `deploy/.env`. Once an OpenBAO
snapshot (`bash deploy/backup.sh` writes one) is stored offline:
1. `bash deploy/forget-env-keys.sh` — checks OpenBAO holds exactly the `.env` values and that a backup exists, then
   removes `ENCRYPTION_KEY*` from `.env` (`prove-encryption` ENC-39 reports it).
2. Give each of the 5 shares in `init.txt` to a different holder, revoke the root token
   (`docker compose exec -e BAO_TOKEN=<root token> openbao bao token revoke <root token>`) and delete `init.txt`.
3. After a reboot, 3 holders each run `docker compose exec openbao bao operator unseal` with their share; then
   `docker compose up -d`. Until then the server does not start (fail closed).

## Production profile

1. **Storage**: not `-dev`. Use raft (integrated storage) with a config file:
   ```hcl
   storage "raft" { path = "/openbao/data"  node_id = "bao-1" }
   listener "tcp" { address = "0.0.0.0:8200"  tls_cert_file = "/certs/bao.crt"  tls_key_file = "/certs/bao.key" }
   api_addr = "https://openbao.internal:8200"
   cluster_addr = "https://openbao.internal:8201"
   ui = false
   ```
   `bao operator init -key-shares=5 -key-threshold=3` once. Keep the 5 unseal key shares with 5 different named
   holders (sealed envelopes / password manager entries, never on the OpenBAO or app host); the initial root
   token is used only for setup below and then revoked (`bao token revoke <root>`).
2. **Unseal** after every OpenBAO restart: 3 holders run `bao operator unseal` (or configure auto-unseal with a
   cloud KMS / another OpenBAO transit key). Until unsealed, the mrpostman server will not start — by design.
3. **Secret**: `bao secrets enable -path=secret kv-v2` (once), then
   `bao kv put -mount=secret mrpostman/root key=<base64 32 bytes> factor=<secret> old_keys= old_factors=`.
   Rotation = `bao kv put` with the previous pair moved into `old_keys` / `old_factors`, restart the server once
   with `ENCRYPTION_BACKFILL=true` (same procedure as before, the values just live here).
4. **Read-only policy + AppRole** for the server (no root token on the app host):
   ```hcl
   # mrpostman-read.hcl
   path "secret/data/mrpostman/root" { capabilities = ["read"] }
   ```
   ```sh
   bao policy write mrpostman-read mrpostman-read.hcl
   bao auth enable approle
   bao write auth/approle/role/mrpostman token_policies=mrpostman-read \
        token_ttl=1h token_max_ttl=4h secret_id_ttl=24h secret_id_num_uses=0 token_num_uses=0
   bao read auth/approle/role/mrpostman/role-id            # → OPENBAO_ROLE_ID (not secret)
   bao write -f auth/approle/role/mrpostman/secret-id      # → OPENBAO_SECRET_ID (secret; inject at deploy time)
   ```
   The server logs in once at start and reads the secret once; the token TTL only needs to cover startup.
   Set `OPENBAO_ROLE_ID`, `OPENBAO_SECRET_ID` (and no `OPENBAO_TOKEN`) on the server.
5. **Audit device**: `bao audit enable file file_path=/openbao/logs/audit.log` — every read of the root secret is
   logged with the token accessor and the client address; ship this log off the host.
6. **Backups**: raft snapshots (`bao operator raft snapshot save`) + the unseal key shares are the key backup.
   Losing the snapshot *and* the last known `key`/`factor` makes the data unreadable; losing the unseal shares
   makes the snapshot unusable. Store snapshots and shares apart from the database backups.
7. **Network**: OpenBAO listens only on the internal network / localhost of the app host; TLS on the listener;
   never expose 8200 publicly.
