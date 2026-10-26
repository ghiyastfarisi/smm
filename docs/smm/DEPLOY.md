# How to deploy smm

One Linux VM, Docker Compose, about 30 minutes. Everything runs from `deploy/` with `docker compose`. Background,
the security demo and every option: [`STEP-BY-STEP.md`](STEP-BY-STEP.md).

## 1. Prepare the VM
- Linux with Docker Engine and the Compose v2 plugin, `git`, `openssl`.
- 8 GB RAM and 20 GB disk for the first build (2 GB RAM to run). No Node.js needed.
- Use one normal user for everything, allowed to run `docker` without sudo:
  ```bash
  sudo usermod -aG docker $USER      # then log out and back in
  docker ps                          # must work without sudo
  ```
- Open port `8065` to your users (or `443` once a TLS proxy is in front, step 6).

## 2. Get the code
```bash
sudo mkdir -p /opt/app && sudo chown $USER: /opt/app
git clone -b smm https://github.com/ghiyastfarisi/smm.git /opt/app/smm
cd /opt/app/smm/deploy
git checkout v1.0.0-rc.5             # the release you deploy
```

## 3. Create `deploy/.env`
```bash
umask 077
cp .env.example .env
sed -i "s|^ENCRYPTION_KEY=$|ENCRYPTION_KEY=$(openssl rand -base64 32)|; \
        s|^ENCRYPTION_KEY_FACTOR=$|ENCRYPTION_KEY_FACTOR=$(openssl rand -base64 32)|; \
        s|^DB_PASSWORD=$|DB_PASSWORD=$(openssl rand -hex 16)|" .env
nano .env                            # set SITE_URL
```
`SITE_URL` is the exact address users type, for example `http://10.0.0.5:8065` or `https://chat.example.org`.
If it differs, logins work but messages only appear after a page refresh.

**Copy `.env` to a safe offline place now.** `ENCRYPTION_KEY` and `ENCRYPTION_KEY_FACTOR` are the root key: without
them (or the OpenBAO data) nothing can be decrypted.

## 4. Start
```bash
docker compose up -d                 # first time: builds the image (~15 min), sets up OpenBAO, starts
docker compose ps                    # db, openbao, server: healthy; openbao-setup: Exited (0)
docker compose logs openbao-setup    # ends with "openbao-setup: ready"
curl -s localhost:8065/api/v4/system/ping
```
The first start creates `deploy/openbao/secrets/init.txt`: the **5 unseal shares and the OpenBAO root token**.
Copy it offline too (separately from `.env`).

Using the image built on GitHub instead of building: set `SMM_IMAGE=ghcr.io/ghiyastfarisi/smm:v1.0.0-rc.5` in `.env`
and run `docker compose pull server` before `docker compose up -d`.

## 5. Create the users
The server starts empty. Either open `SITE_URL` in a browser and sign up: the first account becomes the system
admin and creates the first team. Or on the VM:
```bash
mm() { docker compose exec -T server mmctl --local "$@"; }
mm user create --username admin --email admin@your.org --password '<strong password>' --system-admin --email-verified
mm team create --name main --display-name "Main" --private
mm user create --username ani --email ani@your.org --password '<password>' --email-verified
mm team users add main admin ani
```
Desktop and mobile: the official Mattermost apps, server address = `SITE_URL`.

## 6. Before real users
1. **TLS.** Put a reverse proxy with a CA certificate in front of `:8065` and pass the WebSocket through (nginx
   example: [`STEP-BY-STEP.md`](STEP-BY-STEP.md) §9.1). Then set `SITE_URL=https://<domain>` and
   `API_PORT=127.0.0.1:8065` in `.env`, and run `docker compose up -d`.
2. **Locked settings.** Uncomment `COMPOSE_FILE=docker-compose.yml:docker-compose.release.yml` in `.env` (password
   policy, rate limits, session lengths, invite-only, CORS) and run `docker compose up -d`. That file also adds a
   TLS edge on `:8443`; it needs `bash gen-cert.sh <host>` or your own `tls/cert.pem` + `tls/key.pem`.
3. **Backup**, while `init.txt` is still here (the snapshot uses its root token):
   `bash backup.sh` → store `backups/` offline.
4. **Keys off the host:** `bash forget-env-keys.sh` (refuses unless OpenBAO holds the same keys and a backup exists).
5. **Hand out the shares.** Give each of the 5 `Unseal Key` lines in `init.txt` to a different person. Revoke the
   root token and delete the file:
   ```bash
   T=$(awk '/^Initial Root Token:/ {print $4}' openbao/secrets/init.txt)
   docker compose exec -e BAO_TOKEN=$T openbao bao token revoke $T
   shred -u openbao/secrets/init.txt
   ```
6. Pentest and sign-off.

## 7. Operating
| Task | Command (in `deploy/`) |
|---|---|
| Status / logs | `docker compose ps` · `docker compose logs -f server` |
| Stop / start (data kept) | `docker compose down` · `docker compose up -d` |
| After a reboot | OpenBAO comes back sealed and the server waits. While `init.txt` exists: `docker compose up -d`. After step 6.5: 3 holders each run `docker compose exec openbao bao operator unseal` (paste their share), then `docker compose up -d` |
| Upgrade | `git fetch --tags && git checkout <new tag>`, `docker compose build server` (or `pull server`), `docker compose up -d` |
| Backup / restore | `bash backup.sh` · `bash restore.sh backups/<archive>.tar.gz` |
| Encryption proof (needs Node.js) | `SERVER=<SITE_URL> ADMIN_USER=<admin> ADMIN_PASSWORD=<pw> node prove-encryption.mjs` |
| Remove everything, data included | `docker compose down -v` and delete `openbao/secrets/` (irreversible) |

## 8. Troubleshooting
| Symptom | Fix |
|---|---|
| `open …/deploy/.env: permission denied` | the file belongs to another user: `sudo chown $USER: .env`, keep `chmod 600` |
| `set DB_PASSWORD in deploy/.env` | `.env` missing or not filled in (step 3) |
| `server` keeps restarting, `openbao-setup` waits "sealed" | OpenBAO is sealed: see "After a reboot" |
| `openbao-setup: no init.txt and no AppRole yet` | `init.txt` was deleted before the first full start: restore it from your offline copy |
| Messages only appear after refresh | `SITE_URL` is not the address in the browser, or the proxy does not pass `Upgrade` headers |
| Build stops with out-of-memory | give the VM 8 GB for the build, or use the GitHub image (`SMM_IMAGE`, step 4) |
| `all predefined address pools have been fully subnetted` | too many Docker networks: `docker network prune` |
| `openbao` restarts: `kms.hcl: permission denied`, or server: `i18n/…json: permission denied` | the checkout was made with a strict umask (files `600`, folders `700`); the containers run as other users. In the checkout: `chmod 711 . deploy deploy/openbao && chmod 644 deploy/openbao/*.hcl && chmod -R a+rX server webapp`, then `docker compose up -d --build`. Clone with the default `umask 022` to avoid it |
