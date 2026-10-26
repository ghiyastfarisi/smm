#!/usr/bin/env bash
# Restore (OPS-04) a backup.sh archive into this stack: verifies the sha256, stops the server, replaces the database
# and the file store, starts again. On a clean host first put deploy/.env back (same ENCRYPTION_KEY /
# ENCRYPTION_KEY_FACTOR, or restore the OpenBAO snapshot in production) and run `docker compose up -d` once so the
# volumes and images exist; then run this. Afterwards: node deploy/prove-encryption.mjs
# Usage: bash deploy/restore.sh deploy/backups/mrpostman-<stamp>.tar.gz
#        (release profile: COMPOSE_FILE=docker-compose.yml:docker-compose.release.yml bash deploy/restore.sh …)
set -euo pipefail
archive=$(realpath "${1:?usage: restore.sh <archive.tar.gz>}")
cd "$(dirname "$0")"
[ -f .env ] || { echo "deploy/.env missing: restore the key material first (docs/STEP-BY-STEP.md)"; exit 1; }
if [ -f "$archive.sha256" ]; then (cd "$(dirname "$archive")" && sha256sum -c "$(basename "$archive").sha256"); else echo "warning: no .sha256 beside the archive"; fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar xzf "$archive" -C "$work"
cat "$work/MANIFEST"
echo "stopping the server"
docker compose stop server >/dev/null
echo "database ← db.dump"
docker compose exec -T db psql -U mmuser -d postgres -qc "DROP DATABASE IF EXISTS mrpostman WITH (FORCE)" -c "CREATE DATABASE mrpostman OWNER mmuser"
docker compose exec -T db pg_restore -U mmuser -d mrpostman --no-owner < "$work/db.dump"
echo "file store ← files.tar"
docker compose run --rm --no-deps -T --entrypoint sh server -c 'rm -rf /mattermost/data/files && tar xf - -C /mattermost/data' < "$work/files.tar"
echo "starting"
docker compose up -d >/dev/null
echo "restored $(basename "$archive"); now: node deploy/prove-encryption.mjs"
