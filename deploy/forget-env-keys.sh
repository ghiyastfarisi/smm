#!/usr/bin/env bash
# Production, once (OPS-20): removes ENCRYPTION_KEY* from deploy/.env after checking that OpenBAO holds exactly those
# values and that a backup exists. Afterwards OpenBAO is the only copy of the root secret on this host, so first keep
# the unseal shares and an OpenBAO snapshot (bash deploy/backup.sh) offline.
#   bash deploy/forget-env-keys.sh          (root token from deploy/openbao/secrets/init.txt, or BAO_TOKEN=…)
set -euo pipefail
cd "$(dirname "$0")"
grep -q '^ENCRYPTION_KEY' .env || { echo "forget-env-keys: deploy/.env holds no ENCRYPTION_KEY* already"; exit 0; }
ROOT=${BAO_TOKEN:-$(awk '/^Initial Root Token:/ {print $4}' openbao/secrets/init.txt 2>/dev/null || true)}
[ -n "$ROOT" ] || { echo "forget-env-keys: set BAO_TOKEN to an operator token (init.txt is gone)" >&2; exit 1; }
set -a; . ./.env; set +a
for f in key:ENCRYPTION_KEY factor:ENCRYPTION_KEY_FACTOR old_keys:ENCRYPTION_KEY_OLD old_factors:ENCRYPTION_KEY_FACTOR_OLD; do
  got=$(docker compose exec -T -e BAO_TOKEN="$ROOT" openbao bao kv get -mount=secret -field="${f%%:*}" mrpostman/root 2>/dev/null) \
    || { echo "forget-env-keys: cannot read the root secret from OpenBAO (sealed?)" >&2; exit 1; }
  var=${f#*:}
  [ "$got" = "${!var:-}" ] || { echo "forget-env-keys: OpenBAO ${f%%:*} differs from deploy/.env $var; refusing" >&2; exit 1; }
done
ls backups/*.tar.gz >/dev/null 2>&1 || { echo "forget-env-keys: no deploy/backups/*.tar.gz yet; run bash deploy/backup.sh first" >&2; exit 1; }
(umask 077; grep -v '^ENCRYPTION_KEY' .env > .env.tmp && mv .env.tmp .env)
echo "forget-env-keys: ENCRYPTION_KEY* removed from deploy/.env; OpenBAO holds the root secret"
