#!/usr/bin/env bash
# One-command install on a fresh VM: pulls the server image from GHCR (built by .github/workflows/smm-image.yml),
# creates the secrets, sets up the OpenBAO KMS (Shamir 3-of-5, AppRole) and starts the server. Needs only git,
# Docker (Compose v2) and openssl. Re-running is safe: existing secrets, KMS and data are kept.
#   bash deploy/install.sh                              http://<this VM's IP>:8065
#   bash deploy/install.sh http://chat.internal:8065    your own address (put your TLS proxy in front, STEP-BY-STEP §9)
#   bash deploy/install.sh --release https://chat.example.org:8443
#                                                       + locked release settings and the TLS edge on :8443
#                                                       (self-signed until you replace deploy/tls/{cert,key}.pem)
#   --build                                             build the image here instead (8 GB RAM; web app in a node
#                                                       container, so still no Node.js on the VM)
# Image: ghcr.io/ghiyastfarisi/smm:<checked-out tag>, else :latest; override with SMM_IMAGE=….
# No demo users: the first account created in the browser becomes the system admin.
set -euo pipefail
cd "$(dirname "$0")"
release=() site= build=false
for a in "$@"; do case "$a" in --release) release=(--release) ;; --build) build=true ;; http://*|https://*) site=${a%/} ;; *) echo "install.sh: unknown argument $a" >&2; exit 2 ;; esac; done

for c in git docker openssl; do command -v $c >/dev/null || { echo "install.sh: $c is missing" >&2; exit 1; }; done
docker compose version >/dev/null || { echo "install.sh: Docker Compose v2 is missing" >&2; exit 1; }

if [ -z "$site" ]; then
  ip=$(hostname -I 2>/dev/null | awk '{print $1}'); ip=${ip:-localhost}
  if [ ${#release[@]} -gt 0 ]; then site=https://$ip:8443; else site=http://$ip:8065; fi
fi
host=${site#*://}; host=${host%%[:/]*}

# 1. Secrets (first run only). SITE_URL must be the exact address users open, or the WebSocket is rejected.
if [ ! -f .env ]; then
  (umask 077; {
    echo "ENCRYPTION_KEY=$(openssl rand -base64 32)"
    echo "ENCRYPTION_KEY_FACTOR=$(openssl rand -base64 32)"
    echo "DB_PASSWORD=$(openssl rand -hex 16)"
    echo "OPENBAO_ROOT_TOKEN=$(openssl rand -hex 16)"
  } > .env)
  echo "install.sh: created deploy/.env — copy it somewhere safe and offline now"
fi
if $build; then image=${SMM_IMAGE:-mrpostman-server:local}
else image=${SMM_IMAGE:-ghcr.io/ghiyastfarisi/smm:$(git describe --tags --exact-match 2>/dev/null || echo latest)}; fi
grep -v '^SITE_URL=\|^SMM_IMAGE=' .env > .env.tmp || true
printf 'SITE_URL=%s\nSMM_IMAGE=%s\n' "$site" "$image" >> .env.tmp; (umask 077; mv .env.tmp .env)

# 2. Server image: pulled from GHCR, or built here (stock web app in a node container, several minutes).
if $build; then
  if [ ! -f ../server/client/root.html ]; then
    docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/..:/smm" -w /smm node:24.11.1-bookworm \
      node deploy/build-stock-client.mjs
  fi
  docker compose -f docker-compose.yml build server
else
  docker pull "$image"
fi

# 3. TLS certificate for the release profile, then the KMS (init, unseal, root secret, AppRole, start).
[ ${#release[@]} -gt 0 ] && [ ! -f tls/cert.pem ] && bash gen-cert.sh "$host"
bash openbao/kms-setup.sh "${release[@]}"

files=(-f docker-compose.yml -f docker-compose.kms.yml); [ ${#release[@]} -gt 0 ] && files+=(-f docker-compose.release.yml)
for _ in $(seq 60); do docker compose "${files[@]}" exec -T server curl -sf localhost:8065/api/v4/system/ping >/dev/null 2>&1 && break; sleep 2; done
docker compose "${files[@]}" exec -T server curl -sf localhost:8065/api/v4/system/ping >/dev/null || { echo "install.sh: server not up: docker compose logs server" >&2; exit 1; }

cat <<EOF

smm is running: $site
  - Open it and create the first account (it becomes the system admin).
  - deploy/openbao/secrets/init.txt holds the 5 unseal shares and the root token: hand them out, then follow
    docs/smm/STEP-BY-STEP.md §9 (backup, forget-env-keys, revoke the root token).
  - After a reboot or OpenBAO restart: bash deploy/openbao/kms-setup.sh unseal${release:+ --release}
  - Proof: node deploy/prove-encryption.mjs (needs Node), or docker compose logs server
EOF
