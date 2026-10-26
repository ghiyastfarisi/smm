#!/bin/sh
# Seeds the mrpostman root secret into OpenBAO KV v2 from the .env values, only if the path is still empty.
# Idempotent: a re-run (or a dev-mode restart, which loses the in-memory store) never overwrites existing
# material, so the keys the data was sealed with stay the ones in use. Env: BAO_ADDR, BAO_TOKEN, OPENBAO_KV_PATH
# (API path, e.g. secret/data/mrpostman/root), ENCRYPTION_KEY, ENCRYPTION_KEY_FACTOR, *_OLD.
set -eu
path="${OPENBAO_KV_PATH:-secret/data/mrpostman/root}"
mount="${path%%/*}"            # secret
rest="${path#*/data/}"         # mrpostman/root
i=0
until bao status >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -gt 60 ] && { echo "openbao-init: OpenBAO not ready after 60 s" >&2; exit 1; }
  sleep 1
done
if bao kv get -mount="$mount" -field=key "$rest" >/dev/null 2>&1; then
  echo "openbao-init: root secret already present at $path (kept)"
  exit 0
fi
if [ -z "${ENCRYPTION_KEY:-}" ] || [ -z "${ENCRYPTION_KEY_FACTOR:-}" ]; then
  echo "openbao-init: no root secret at $path and no ENCRYPTION_KEY/ENCRYPTION_KEY_FACTOR in deploy/.env to seed it." >&2
  echo "openbao-init: the dev OpenBAO is in-memory; use the KMS profile (bash deploy/openbao/kms-setup.sh) or restore the keys." >&2
  exit 1
fi
bao kv put -mount="$mount" "$rest" \
  key="$ENCRYPTION_KEY" factor="$ENCRYPTION_KEY_FACTOR" \
  old_keys="${ENCRYPTION_KEY_OLD:-}" old_factors="${ENCRYPTION_KEY_FACTOR_OLD:-}" >/dev/null
echo "openbao-init: wrote root secret to $path"
