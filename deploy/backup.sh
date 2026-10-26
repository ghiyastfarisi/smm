#!/usr/bin/env bash
# Backup (OPS-03): database dump + file store → deploy/backups/mrpostman-<UTC stamp>.tar.gz with a .sha256 beside it.
# The archive holds only ciphertext: it is useless (and harmless) without the key material, which is backed up
# SEPARATELY and stored apart from this archive:
#   dev   — deploy/.env (ENCRYPTION_KEY, ENCRYPTION_KEY_FACTOR, *_OLD; openbao-setup writes it into OpenBAO on the first start)
#   prod  — the OpenBAO raft snapshot (`bao operator raft snapshot save`) + the unseal key shares (openbao/README.md §6)
# Usage: bash deploy/backup.sh [out-dir]     restore with: bash deploy/restore.sh <archive>
set -euo pipefail
cd "$(dirname "$0")"
out=${1:-backups}
stamp=$(date -u +%Y%m%dT%H%M%SZ)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
echo "database → db.dump (pg_dump custom format)"
docker compose exec -T db pg_dump -U mmuser -d mrpostman -Fc > "$work/db.dump"
echo "file store → files.tar (/mattermost/data/files; encrypted blobs, MMENCF headers)"
docker compose exec -T server sh -c 'cd /mattermost/data && [ -d files ] && tar cf - files || tar cf - --files-from /dev/null' > "$work/files.tar"
printf 'mrpostman backup %s\nserver image: %s\n' "$stamp" "$(docker compose images server --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null | tail -1)" > "$work/MANIFEST"
archive="$out/mrpostman-$stamp.tar.gz"
tar czf "$archive" -C "$work" MANIFEST db.dump files.tar
(cd "$out" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
ls -l "$archive" "$archive.sha256"
# KMS profile: also save the OpenBAO raft snapshot as a SEPARATE file (store it apart from the archive above).
if [ -f openbao/secrets/init.txt ] && docker compose exec -T openbao bao status -format=json 2>/dev/null | grep -q '"storage_type": "raft"'; then
  root=$(awk '/^Initial Root Token:/ {print $4}' openbao/secrets/init.txt)
  docker compose exec -T -e BAO_TOKEN="$root" openbao bao operator raft snapshot save /tmp/bao.snap >/dev/null
  (umask 077; docker compose exec -T openbao cat /tmp/bao.snap > "$out/openbao-$stamp.snap")
  docker compose exec -T openbao rm -f /tmp/bao.snap
  (cd "$out" && sha256sum "openbao-$stamp.snap" > "openbao-$stamp.snap.sha256")
  echo "OpenBAO raft snapshot → $out/openbao-$stamp.snap (move it to the key backup location, not next to the data)"
fi
cat <<'EOF'
Reminder: the keys are NOT in this archive. Back up deploy/.env (dev) or the OpenBAO raft snapshot + unseal shares
(production) to a different, encrypted location. Without ENCRYPTION_KEY and ENCRYPTION_KEY_FACTOR this backup is noise.
EOF
