#!/usr/bin/env bash
# One shot: create secrets (first run only), build and start everything, seed demo data.
#   --release  adds docker-compose.release.yml (CFG-01…13 locked through the environment + a TLS edge on :8443 with a
#              self-signed certificate from gen-cert.sh)
#   --kms      docker-compose.kms.yml (OpenBAO with persistent storage, sealed at start, AppRole). The DEFAULT once
#              `bash deploy/openbao/kms-setup.sh` has run (it writes openbao/secrets/approle.env); unseal after
#              restarts with `kms-setup.sh unseal`. Without approle.env the stack starts on dev OpenBAO and says so.
#   --dev-kms  force the dev OpenBAO (-dev, in-memory, root token) even when the KMS is set up
set -euo pipefail
cd "$(dirname "$0")"
files=(--profile demo -f docker-compose.yml)   # demo: seed users (dev only; install.sh leaves it out)
release=false
kms=auto
for a in "$@"; do
  case "$a" in
    --release) release=true; files+=(-f docker-compose.release.yml); [ -f tls/cert.pem ] || bash gen-cert.sh ;;
    --kms) kms=true ;;
    --dev-kms) kms=false ;;
    *) echo "up.sh: unknown option $a" >&2; exit 2 ;;
  esac
done
has_approle() { grep -qs '^OPENBAO_SECRET_ID=' openbao/secrets/approle.env; }
if [ "$kms" = true ] && ! has_approle; then echo "up.sh: run bash deploy/openbao/kms-setup.sh first" >&2; exit 1; fi
if [ "$kms" = auto ]; then
  if has_approle; then kms=true; else kms=false; echo "up.sh: KMS not set up — starting on dev OpenBAO (root token). Production: bash deploy/openbao/kms-setup.sh" >&2; fi
fi
$kms && files+=(-f docker-compose.kms.yml)
docker() { if [ "${1:-}" = compose ]; then shift; command docker compose "${files[@]}" "$@"; else command docker "$@"; fi; }
if [ ! -f .env ]; then
  umask 077
  {
    echo "ENCRYPTION_KEY=$(openssl rand -base64 32)"
    echo "ENCRYPTION_KEY_FACTOR=$(openssl rand -base64 32)"
    echo "DB_PASSWORD=$(openssl rand -hex 16)"
    echo "OPENBAO_ROOT_TOKEN=$(openssl rand -hex 16)"
  } > .env
  echo "Created deploy/.env — back it up: without ENCRYPTION_KEY and ENCRYPTION_KEY_FACTOR the data cannot be read."
fi
# Older .env files predate the key factor: add one (the server re-seals data on start). Not once the keys have left
# .env for OpenBAO (kms-setup.sh forget-env-keys): then neither key is here.
if grep -q "^ENCRYPTION_KEY=" .env && ! grep -q "^ENCRYPTION_KEY_FACTOR=" .env; then
  (umask 077; echo "ENCRYPTION_KEY_FACTOR=$(openssl rand -base64 32)" >> .env)
  echo "Added ENCRYPTION_KEY_FACTOR to deploy/.env — back it up too."
fi
# Older .env files predate OpenBAO custody: add the dev root token (openbao-init seeds the keys from .env).
if ! grep -q "^OPENBAO_ROOT_TOKEN=" .env; then
  (umask 077; echo "OPENBAO_ROOT_TOKEN=$(openssl rand -hex 16)" >> .env)
  echo "Added OPENBAO_ROOT_TOKEN to deploy/.env."
fi
docker compose up -d --build --remove-orphans   # --remove-orphans: drops the tls edge when leaving --release
docker compose wait seed >/dev/null 2>&1 || true
docker compose logs seed | tail -1
# A recreated server container gets a new address; nginx resolved the old one at start.
$release && { docker compose restart tls >/dev/null 2>&1 || true; }
set -a; . ./.env; set +a
echo "Web:     http://localhost:${API_PORT:-8065}"
$release && echo "TLS:     https://localhost:${TLS_PORT:-8443} (self-signed deploy/tls/cert.pem)"
$kms && echo "KMS:     OpenBAO sealed storage + AppRole (unseal after an OpenBAO restart: bash deploy/openbao/kms-setup.sh unseal)"
