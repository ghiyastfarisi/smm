# OpenBAO key custody

The server never holds `ENCRYPTION_KEY` / `ENCRYPTION_KEY_FACTOR` in its environment. At start it reads the
root secret from OpenBAO KV v2 (`OPENBAO_ADDR`, `OPENBAO_KV_PATH`, default `secret/data/mrpostman/root`) with
either `OPENBAO_TOKEN` or AppRole (`OPENBAO_ROLE_ID` + `OPENBAO_SECRET_ID`). Fields: `key`, `factor`,
`old_keys`, `old_factors` — same encodings as the old environment variables. If `OPENBAO_ADDR` is set and the
read fails (unreachable, sealed, wrong token, empty path) the server refuses to start; it never falls back to
the environment. Without `OPENBAO_ADDR` the environment variables still work (single-host installs).

## Dev stack (what `docker compose` runs)

- `openbao`: `server -dev` — in-memory storage, auto-unsealed, root token `OPENBAO_ROOT_TOKEN` from `deploy/.env`.
- `openbao-init`: one shot; writes the root secret from `.env` **only if the path is empty** (`init.sh`). After a
  restart the in-memory store is gone, so the init job re-seeds the same material: kids stay the same, every
  stored row and file stays readable. `.env` therefore remains the key backup in dev.
- `server`: `OPENBAO_ADDR=http://openbao:8200`, `OPENBAO_TOKEN=${OPENBAO_ROOT_TOKEN}`; `docker compose exec server env`
  shows no `ENCRYPTION_KEY*`.

Inspect: `docker compose exec -e BAO_TOKEN=<root token> openbao bao kv get -mount=secret mrpostman/root`.

## KMS profile (runnable production setup on one host)

Steps 1–5 below are automated for a single-host install:

```bash
bash deploy/openbao/kms-setup.sh            # once: init (Shamir 3/5), unseal, kv + root secret from .env, policy, AppRole; starts the stack
bash deploy/openbao/kms-setup.sh unseal     # after every OpenBAO restart; the server waits (fails closed) until then
bash deploy/up.sh [--release]               # later starts: the KMS profile is the default once approle.env exists
bash deploy/openbao/kms-setup.sh forget-env-keys   # production, once: take ENCRYPTION_KEY* off the host (see below)
```

**Keys off the host (OPS-20).** After `kms-setup.sh`, the root secret is in OpenBAO and still in `deploy/.env` (its
seed). In production, once the 5 unseal shares are with their holders and an OpenBAO snapshot (`deploy/backup.sh`
writes one) is stored offline, run `kms-setup.sh forget-env-keys`: it checks OpenBAO holds exactly the `.env` values
and that a backup exists, then removes `ENCRYPTION_KEY*` from `.env`. From then on OpenBAO is the only copy on the
host; `prove-encryption` ENC-39 reports it, and starting the in-memory dev OpenBAO (`up.sh --dev-kms`) fails closed.
After a host or OpenBAO restart the stack waits until `kms-setup.sh unseal` (or 3 share holders) unseals it; run
`bash deploy/up.sh` once more if it gave up waiting.

Files: `docker-compose.kms.yml` (OpenBAO without `-dev`, raft on volume `openbao-data`, audit log on `openbao-audit`;
server with `OPENBAO_TOKEN` empty and AppRole credentials from `openbao/secrets/approle.env`), `openbao/kms.hcl`
(storage, listener, audit device), `openbao/mrpostman-read.hcl` (policy). `openbao/secrets/` is gitignored; `init.txt`
holds the 5 unseal shares and the root token for the drill — in production hand the shares to 5 holders, revoke the
root token and delete the file.
Dev profile on purpose: `bash deploy/up.sh --dev-kms` (in-memory OpenBAO re-seeded from `.env`, so it needs the keys
there; the `openbao-data` volume is kept).

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
