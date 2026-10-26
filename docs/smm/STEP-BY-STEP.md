# smm step by step

From an empty host to a running smm server with the KMS, a security demo, and production hardening. Architecture
and the encryption design: [`ARCHITECTURE.md`](ARCHITECTURE.md). Every command runs from the repository root unless
it says otherwise.

## 0. Prerequisites
- Linux host with Docker and Docker Compose v2, `git`, `openssl`, Node.js 20+ (for the build and proof scripts).
- 4 GB RAM, 20 GB disk. Ports `8065` (server), optionally `8443` (TLS edge).
- Production: a domain name and a CA certificate for it; 5 people who will each hold one OpenBAO unseal share.

## 1. Get the code
```bash
git clone -b smm https://github.com/ghiyastfarisi/smm.git
cd smm
git checkout <release tag>
```

## 2. Build the stock web app into the server image
```bash
node deploy/build-stock-client.mjs          # once per source change; takes several minutes
```

## 3. Create the secrets
```bash
cd deploy
umask 077
cat > .env <<EOF
ENCRYPTION_KEY=$(openssl rand -base64 32)
ENCRYPTION_KEY_FACTOR=$(openssl rand -base64 32)
DB_PASSWORD=$(openssl rand -hex 16)
OPENBAO_ROOT_TOKEN=$(openssl rand -hex 16)
SITE_URL=http://localhost:8065
EOF
cd ..
```
- `SITE_URL` is the address users open. For a local test keep `http://localhost:8065`; production uses
  `https://<your domain>` (step 9).
- **Back up `deploy/.env` now** (offline). Until step 9.4 it is the only copy of the root key outside OpenBAO;
  losing it before OpenBAO holds the key loses the data.

## 4. Set up the KMS (OpenBAO) — once
```bash
docker compose -f deploy/docker-compose.yml build server
bash deploy/openbao/kms-setup.sh
```
This initialises OpenBAO with Shamir 3-of-5, unseals it, stores the root secret, writes the read-only policy and the
server's AppRole, turns on the audit log and starts the stack. It writes:
- `deploy/openbao/secrets/init.txt` — the 5 unseal shares and the initial root token (mode 600),
- `deploy/openbao/secrets/approle.env` — the server's AppRole credentials.

## 5. Start the server
Only the core services (Postgres, OpenBAO, server):
```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.kms.yml stop web
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.kms.yml up -d db openbao openbao-init server
```
Or the whole development stack with demo users (`ani`, `budi`, `admin`, password `Demo#12345`):
```bash
bash deploy/up.sh
```

## 6. Check it
```bash
curl -s localhost:8065/api/v4/system/ping           # {"status":"OK",...}
node deploy/prove-encryption.mjs                    # ends with "all checks passed: data at rest is encrypted"
```
Open `http://localhost:8065`. The first account you create becomes the system admin. The stock desktop and mobile apps use
the same address.

## 7. Security demo (10 minutes)
1. **Normal use.** Two browser windows (one private), log in as `ani` and `budi`, send messages and a file in a DM
   and in a channel. Messages arrive in real time.
2. **The database holds only ciphertext.**
   ```bash
   docker exec -it mrpostman-db-1 psql -U mmuser mrpostman \
     -c "select id, channelid, left(message,120) from posts where type='' order by createat desc limit 3;"
   ```
   Each message looks like `enc:v4:<key id>:<teamId>/<channelId>:posts.message#<postId>:…`: the team, channel and
   message id are bound into the AEAD, so the value cannot be moved to another row or channel.
3. **No key on the server.** `docker exec mrpostman-server-1 env | grep -i ENCRYPTION_KEY` prints nothing.
4. **The KMS locks the data.**
   ```bash
   docker restart mrpostman-openbao-1               # OpenBAO comes back sealed
   docker restart mrpostman-server-1                # the server refuses to start: it cannot read its key
   docker logs --tail 5 mrpostman-server-1
   ```
5. **Three holders unlock it.**
   ```bash
   bash deploy/openbao/kms-setup.sh unseal          # uses 3 of the 5 shares
   bash deploy/up.sh                                 # everything back; the messages are readable again
   ```
6. **Audit trail.** `docker exec mrpostman-openbao-1 tail -n 3 /openbao/logs/audit.log` shows the server's
   read of the root secret.
7. **Proof report.** `node deploy/prove-encryption.mjs`.

## 8. Clients
- **Browser:** the stock web app at the site URL.
- **Desktop:** the official Mattermost desktop app, server address = site URL.
- **Mobile:** the official Mattermost app from the stores works against the server over HTTPS, without background
  notifications (push is off: smm sends nothing to Mattermost's push service).

## 9. Production hardening
1. **TLS in front of the server.** Put your reverse proxy with the CA certificate in front of `:8065` and pass the
   WebSocket through (real-time messages and notifications need it):
   ```nginx
   server {
     listen 443 ssl http2;
     server_name chat.example.org;
     ssl_certificate     /etc/ssl/chat.crt;
     ssl_certificate_key /etc/ssl/chat.key;
     add_header Strict-Transport-Security "max-age=63072000" always;
     include /etc/nginx/allow.conf;                  # optional IP allow-list, see deploy/nginx-allow.conf
     client_max_body_size 50M;
     location ~ /api/v[0-9]+/(users/)?websocket$ {
       proxy_pass http://127.0.0.1:8065;
       proxy_http_version 1.1;
       proxy_set_header Upgrade $http_upgrade;
       proxy_set_header Connection "upgrade";
       proxy_set_header Host $host;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto https;
       proxy_read_timeout 600s;
     }
     location / {
       proxy_pass http://127.0.0.1:8065;
       proxy_set_header Host $host;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto https;
     }
   }
   ```
   Then in `deploy/.env`: `SITE_URL=https://chat.example.org` and `API_PORT=127.0.0.1:8065` (stop publishing :8065),
   and restart the server. The site URL must match the address users open, or the server rejects the WebSocket.
2. **Release settings.** Apply the locked settings of `deploy/docker-compose.release.yml` (rate limit, password
   policy, session lengths, CORS, invite-only, file size). The bundled `tls` service in that file is a local
   self-signed TLS edge (`up.sh --release`, https://localhost:8443); in production use your proxy from 9.1 and add the
   release file's `server` environment.
3. **Backups, then keys off the host** (while `init.txt` still exists: `backup.sh` uses its root token for the
   OpenBAO snapshot).
   ```bash
   bash deploy/backup.sh                             # database + files (ciphertext) and an OpenBAO raft snapshot
   bash deploy/openbao/kms-setup.sh forget-env-keys  # removes ENCRYPTION_KEY* from .env after checking OpenBAO and the backup
   ```
   Store the backup and the snapshot offline, separately from each other and from the unseal shares.
4. **Unseal shares.** Give each of the 5 shares in `init.txt` to a different named holder (sealed envelope or
   password-manager entry, never on this host). Revoke the root token
   (`docker exec -e BAO_TOKEN=<root token> mrpostman-openbao-1 bao token revoke <root token>`), then delete `init.txt`.
   Later OpenBAO snapshots need an operator token (`bao operator generate-root` with 3 holders), see
   `deploy/openbao/README.md`.
5. **Accounts.** Turn off open sign-up, create users by invite, enable MFA for admins.
6. **Pentest and sign-off** before real users.

Order matters in 9.3 → 9.4: back up first, hand out the shares last.

## 10. Operating
| Task | Command |
|---|---|
| After a host or OpenBAO restart | 3 holders: `bash deploy/openbao/kms-setup.sh unseal`, then `bash deploy/up.sh` |
| Backup | `bash deploy/backup.sh` (store offline) |
| Restore | `bash deploy/restore.sh <backup>` (OpenBAO must hold the matching root secret) |
| Compliance export / retention | `MM_TOKEN=<admin token> node deploy/records.mjs export --since 2026-10-01 > export.csv`; `… retention --days 365` (dry run, `--apply` deletes) |
| Key rotation | new root in OpenBAO with the old one in `old_keys`/`old_factors`, then start once with `ENCRYPTION_BACKFILL=true` (`deploy/openbao/README.md` §3); check `prove-encryption.mjs` ENC-42 = 0 |
| Upgrade | `git checkout <new tag>`, `node deploy/build-stock-client.mjs`, rebuild and start; older rows are re-sealed at start |
| Stop (data kept) | `docker compose -f deploy/docker-compose.yml down` |

## 11. Troubleshooting
| Symptom | Cause | Fix |
|---|---|---|
| Server container keeps restarting, logs mention OpenBAO | OpenBAO is sealed (after any restart) | `bash deploy/openbao/kms-setup.sh unseal` |
| `dependency failed to start: container …openbao… is unhealthy` | same | same, then start again |
| Messages only appear after a page refresh, no notifications | WebSocket rejected: the address you opened is not `SITE_URL` (or an allowed CORS origin), or the proxy does not pass `Upgrade` | open the site URL exactly; set `SITE_URL`; add the WebSocket block of 9.1 |
| No desktop notifications in the browser | permission not granted, or plain HTTP on a non-localhost address | allow notifications; use HTTPS |
| Log: `Failed to send to push proxy … push-proxy-disabled.invalid` | push is off on purpose (no calls to Mattermost's push service) | ignore, or point `PushNotificationServer` at a push proxy you run |
| Log: `Error while sending the email` | no SMTP configured | set SMTP in the System Console |
| `prove-encryption` reports rows on an old key | rotation without backfill | start once with `ENCRYPTION_BACKFILL=true` |
| User limit reached | the free (Team) edition's user cap applies; smm ships no licence | planned for a later release |
