# smm step by step

From an empty host to a running smm server with the KMS, a security demo, and production hardening. Architecture
and the encryption design: [`ARCHITECTURE.md`](ARCHITECTURE.md). Commands run in `deploy/` unless they say otherwise.

## Quick install
```bash
git clone -b smm https://github.com/ghiyastfarisi/smm.git && cd smm/deploy
git checkout v1.0.0-rc.5                      # or the latest release tag
umask 077 && cp .env.example .env && nano .env  # 3 secrets + SITE_URL (step 2)
docker compose up -d                          # first time: builds the image (~15 min), sets up OpenBAO, starts
```
That is the whole install. It creates **no users, teams or channels** (step 6). Then copy `deploy/.env` and
`deploy/openbao/secrets/init.txt` somewhere safe and offline, and before real users work through step 9.

## 0. Prerequisites
- Linux host with Docker and Docker Compose v2, `git`, `openssl`. No Node.js: the web app builds inside Docker.
- 8 GB RAM to build the image (2 GB to run it; with the image from GitHub no build is needed), 20 GB disk.
  Ports `8065` (server), optionally `8443` (TLS edge).
- Run every command as the same user, one that can use `docker` without `sudo` (`sudo usermod -aG docker $USER`,
  then log in again), and that owns the checkout (`sudo chown -R $USER: /opt/app/smm` if you cloned with sudo).
- Production: a domain name and a CA certificate for it; 5 people who will each hold one OpenBAO unseal share.

## 1. Get the code
```bash
git clone -b smm https://github.com/ghiyastfarisi/smm.git
cd smm/deploy
git checkout <release tag>
```

## 2. Create `deploy/.env`
```bash
umask 077
cp .env.example .env
sed -i "s|^ENCRYPTION_KEY=$|ENCRYPTION_KEY=$(openssl rand -base64 32)|; \
        s|^ENCRYPTION_KEY_FACTOR=$|ENCRYPTION_KEY_FACTOR=$(openssl rand -base64 32)|; \
        s|^DB_PASSWORD=$|DB_PASSWORD=$(openssl rand -hex 16)|; \
        s|^SITE_URL=.*|SITE_URL=http://$(hostname -I \| awk '{print $1}'):8065|" .env
cat .env
```
- `SITE_URL` must be exactly the address users open (otherwise messages do not arrive in real time). Production:
  `https://<your domain>` (step 9).
- `SMM_IMAGE`: keep `mrpostman-server:local` to build here; set `ghcr.io/ghiyastfarisi/smm:<tag>` to use the image
  built on GitHub and run `docker compose pull server` once before step 3.
- Release profile (locked settings, TLS edge on :8443): uncomment `COMPOSE_FILE=…` and run `bash gen-cert.sh <host>`
  (self-signed; replace `tls/{cert,key}.pem` with a CA-issued pair in production).
- **Back up `deploy/.env` now** (offline). Until step 9.3 it is the only copy of the root key outside OpenBAO;
  losing it before OpenBAO holds the key loses the data.

## 3. Start
```bash
docker compose up -d
```
On the first run this builds the image (web app + server, about 15 minutes), then the one-shot `openbao-setup`:
initialises OpenBAO (Shamir 3-of-5), unseals it, writes the root secret from `.env`, the read-only policy and the
server's AppRole. Its log: `docker compose logs openbao-setup`. It writes:
- `deploy/openbao/secrets/init.txt` — the 5 unseal shares and the initial root token (mode 600, host only),
- the AppRole credentials into the `approle` volume, which only the server mounts.

## 4. Day-to-day
```bash
docker compose ps                 # status
docker compose logs -f server     # server log
docker compose up -d              # start; after a reboot this also unseals, while init.txt is still on the host
docker compose down               # stop, data kept
```
After a reboot OpenBAO is sealed. While `init.txt` is on the host, `docker compose up -d` unseals it. Once you have
handed out the shares and deleted it (step 9.4), 3 holders run `docker compose exec openbao bao operator unseal`
(each with their share), then `docker compose up -d`.

## 5. Check it
```bash
curl -s localhost:8065/api/v4/system/ping                     # {"status":"OK",...}
docker compose exec server env | grep -c ENCRYPTION_KEY        # 0: no key in the server
```
## 6. Create the users
The server starts empty: no users, teams or channels. Create them yourself, either in the browser (open the
`SITE_URL` address; the first account becomes the system admin and is asked to create a team) or on the host:
```bash
mm() { docker compose exec -T server mmctl --local "$@"; }
mm user create --username <admin> --email <admin@your.org> --password '<strong password>' --system-admin --email-verified
mm team create --name <team> --display-name "<Team name>" --private
mm user create --username <user> --email <user@your.org> --password '<password>' --email-verified
mm team users add <team> <admin> <user>
```
The stock desktop and mobile apps use the same address. Encryption proof (on the host; needs Node.js):
`SERVER=<SITE_URL> ADMIN_USER=<admin> ADMIN_PASSWORD=<password> node prove-encryption.mjs`.

## 7. Security demo (10 minutes)
1. **Normal use.** Create two users (step 6), log in as each in two browser windows (one private), send messages and
   a file in a DM and in a channel. Messages arrive in real time.
2. **The database holds only ciphertext.**
   ```bash
   docker compose exec db psql -U mmuser mrpostman \
     -c "select id, channelid, left(message,120) from posts where type='' order by createat desc limit 3;"
   ```
   Each message looks like `enc:v4:<key id>:<teamId>/<channelId>:posts.message#<postId>:…`: the team, channel and
   message id are bound into the AEAD, so the value cannot be moved to another row or channel.
3. **No key on the server.** `docker compose exec server env | grep -i ENCRYPTION_KEY` prints nothing.
4. **The KMS locks the data.**
   ```bash
   docker compose restart openbao           # OpenBAO comes back sealed
   docker compose restart server            # the server refuses to start: it cannot read its key
   docker compose logs --tail 5 server
   ```
5. **Three holders unlock it.**
   ```bash
   docker compose up -d                     # unseals with 3 of the 5 shares in init.txt; messages readable again
   ```
6. **Audit trail.** `docker compose exec openbao tail -n 3 /openbao/logs/audit.log` shows the server's
   read of the root secret.
7. **Proof report.** `ADMIN_USER=<admin> ADMIN_PASSWORD=<password> node prove-encryption.mjs`.

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
   self-signed TLS edge (`COMPOSE_FILE=…` in `.env`, https://localhost:8443); in production use your proxy from 9.1 and add the
   release file's `server` environment.
3. **Backups, then keys off the host** (while `init.txt` still exists: `backup.sh` uses its root token for the
   OpenBAO snapshot).
   ```bash
   bash deploy/backup.sh                             # database + files (ciphertext) and an OpenBAO raft snapshot
   bash deploy/forget-env-keys.sh                    # removes ENCRYPTION_KEY* from .env after checking OpenBAO and the backup
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
| After a host or OpenBAO restart | `docker compose up -d` (unseals while `init.txt` is on the host); without it, 3 holders: `docker compose exec openbao bao operator unseal`, then `docker compose up -d` |
| Backup | `bash deploy/backup.sh` (store offline) |
| Restore | `bash deploy/restore.sh <backup>` (OpenBAO must hold the matching root secret) |
| Compliance export / retention | `MM_TOKEN=<admin token> node deploy/records.mjs export --since 2026-10-01 > export.csv`; `… retention --days 365` (dry run, `--apply` deletes) |
| Key rotation | new root in OpenBAO with the old one in `old_keys`/`old_factors`, then start once with `ENCRYPTION_BACKFILL=true` (`deploy/openbao/README.md` §3); check `prove-encryption.mjs` ENC-42 = 0 |
| Upgrade | `git checkout <new tag>`, `docker compose build server` (or `docker compose pull server` with the new `SMM_IMAGE`), then `docker compose up -d`; older rows are re-sealed at start |
| Stop (data kept) | `docker compose down` |

## 11. Troubleshooting
| Symptom | Cause | Fix |
|---|---|---|
| Server container keeps restarting, logs mention OpenBAO | OpenBAO is sealed (after any restart) | `docker compose up -d`, or 3 holders unseal (row above) |
| `dependency failed to start: container …openbao… is unhealthy` | same | same, then start again |
| Messages only appear after a page refresh, no notifications | WebSocket rejected: the address you opened is not `SITE_URL` (or an allowed CORS origin), or the proxy does not pass `Upgrade` | open the site URL exactly; set `SITE_URL`; add the WebSocket block of 9.1 |
| No desktop notifications in the browser | permission not granted, or plain HTTP on a non-localhost address | allow notifications; use HTTPS |
| Log: `Failed to send to push proxy … push-proxy-disabled.invalid` | push is off on purpose (no calls to Mattermost's push service) | ignore, or point `PushNotificationServer` at a push proxy you run |
| Log: `Error while sending the email` | no SMTP configured | set SMTP in the System Console |
| `prove-encryption` reports rows on an old key | rotation without backfill | start once with `ENCRYPTION_BACKFILL=true` |
| User limit reached | the free (Team) edition's user cap applies; smm ships no licence | planned for a later release |
