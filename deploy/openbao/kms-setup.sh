#!/usr/bin/env bash
# Sets up OpenBAO for the KMS profile (deploy/docker-compose.kms.yml) and starts the stack. Idempotent.
#   bash deploy/openbao/kms-setup.sh           init (once) → unseal → kv, root secret, policy, AppRole, audit → up
#   bash deploy/openbao/kms-setup.sh unseal    unseal only (after an OpenBAO restart), then start the server
#   bash deploy/openbao/kms-setup.sh --release same as the first form, with the release profile
#   bash deploy/openbao/kms-setup.sh forget-env-keys
#        removes ENCRYPTION_KEY* from deploy/.env after checking OpenBAO holds exactly those values (OPS-20: no
#        long-lived key material on the app host). Take an OpenBAO snapshot (deploy/backup.sh) and keep the unseal
#        shares offline first: after this, OpenBAO is the only copy of the root secret on this host.
# Init writes the 5 unseal key shares and the initial root token to deploy/openbao/secrets/init.txt (mode 600).
# That file exists so a single operator can run the drill. In production: hand the 5 shares to 5 named holders,
# revoke the root token (`bao token revoke`), and delete init.txt. The root secret's key/factor are taken from
# deploy/.env the first time, so existing data stays readable (same kid).
set -euo pipefail
cd "$(dirname "$0")/.."
sec=openbao/secrets
mkdir -p "$sec" && chmod 700 "$sec"
[ -f "$sec/approle.env" ] || : > "$sec/approle.env"   # compose needs the env_file to exist before setup
files=(-f docker-compose.yml -f docker-compose.kms.yml)
[[ " $* " == *" --release "* ]] && files+=(-f docker-compose.release.yml)
dc() { docker compose "${files[@]}" "$@"; }
bao() { dc exec -T -e BAO_TOKEN="${ROOT:-}" openbao bao "$@"; }

if [ "${1:-}" = forget-env-keys ]; then
  grep -qs '^OPENBAO_SECRET_ID=' "$sec/approle.env" || { echo "kms-setup: KMS not set up; refusing" >&2; exit 1; }
  grep -q '^ENCRYPTION_KEY' .env || { echo "kms-setup: deploy/.env holds no ENCRYPTION_KEY* already"; exit 0; }
  ROOT=$(awk '/^Initial Root Token:/ {print $4}' "$sec/init.txt" 2>/dev/null || true)
  ROOT=${BAO_TOKEN:-$ROOT}
  [ -n "$ROOT" ] || { echo "kms-setup: set BAO_TOKEN to an operator token (init.txt is gone)" >&2; exit 1; }
  set -a; . ./.env; set +a
  for f in key:ENCRYPTION_KEY factor:ENCRYPTION_KEY_FACTOR old_keys:ENCRYPTION_KEY_OLD old_factors:ENCRYPTION_KEY_FACTOR_OLD; do
    got=$(bao kv get -mount=secret -field="${f%%:*}" mrpostman/root 2>/dev/null) || { echo "kms-setup: cannot read the root secret from OpenBAO (sealed?)" >&2; exit 1; }
    var=${f#*:}
    [ "$got" = "${!var:-}" ] || { echo "kms-setup: OpenBAO ${f%%:*} differs from deploy/.env $var; refusing" >&2; exit 1; }
  done
  ls backups/*.tar.gz >/dev/null 2>&1 || { echo "kms-setup: no deploy/backups/*.tar.gz yet; run bash deploy/backup.sh first" >&2; exit 1; }
  (umask 077; grep -v '^ENCRYPTION_KEY' .env > .env.tmp && mv .env.tmp .env)
  echo "kms-setup: ENCRYPTION_KEY* removed from deploy/.env; OpenBAO holds the root secret (keep the unseal shares and an OpenBAO snapshot offline)"
  exit 0
fi

dc up -d openbao
for i in $(seq 60); do
  s=$(dc exec -T openbao bao status -format=json 2>/dev/null || true)
  jq -e 'has("initialized")' <<<"$s" >/dev/null 2>&1 && break; s=; sleep 1
done
[ -n "$s" ] || { echo "kms-setup: OpenBAO API not reachable (docker compose logs openbao)" >&2; exit 1; }

if [ "$(jq -r .initialized <<<"$s")" != true ]; then
  [ "${1:-}" = unseal ] && { echo "kms-setup: not initialised; run without 'unseal' first" >&2; exit 1; }
  (umask 077; bao operator init -key-shares=5 -key-threshold=3 > "$sec/init.txt")
  echo "kms-setup: initialised. Unseal shares and root token in deploy/openbao/secrets/init.txt —"
  echo "           distribute the 5 shares to 5 holders and delete that file in production."
fi
[ -f "$sec/init.txt" ] || { echo "kms-setup: $sec/init.txt missing; unseal by hand: docker compose exec openbao bao operator unseal" >&2; exit 1; }

if [ "$(dc exec -T openbao bao status -format=json 2>/dev/null | jq -r .sealed)" = true ]; then
  for n in 1 2 3; do
    bao operator unseal "$(awk -v n="$n" '$0 ~ "^Unseal Key "n":" {print $4}' "$sec/init.txt")" >/dev/null
  done
  echo "kms-setup: unsealed"
fi

if [ "${1:-}" != unseal ]; then
  ROOT=$(awk '/^Initial Root Token:/ {print $4}' "$sec/init.txt")
  # wait for raft leadership after unseal
  for i in $(seq 30); do bao secrets list >/dev/null 2>&1 && break; sleep 1; done
  bao secrets list -format=json | jq -e '."secret/"' >/dev/null || bao secrets enable -path=secret kv-v2 >/dev/null
  if ! bao kv get -mount=secret -field=key mrpostman/root >/dev/null 2>&1; then
    set -a; . ./.env; set +a
    bao kv put -mount=secret mrpostman/root key="$ENCRYPTION_KEY" factor="$ENCRYPTION_KEY_FACTOR" \
      old_keys="${ENCRYPTION_KEY_OLD:-}" old_factors="${ENCRYPTION_KEY_FACTOR_OLD:-}" >/dev/null
    echo "kms-setup: root secret written from deploy/.env (same kid as before)"
  fi
  dc exec -T -e BAO_TOKEN="$ROOT" openbao sh -c 'cat > /tmp/p.hcl' < openbao/mrpostman-read.hcl
  bao policy write mrpostman-read /tmp/p.hcl >/dev/null
  bao auth list -format=json | jq -e '."approle/"' >/dev/null || bao auth enable approle >/dev/null
  bao write auth/approle/role/mrpostman token_policies=mrpostman-read \
    token_ttl=1h token_max_ttl=4h secret_id_ttl=0 secret_id_num_uses=0 token_num_uses=0 >/dev/null
  # audit device: declared in kms.hcl (OpenBAO 2.x refuses to enable audit devices through the API)
  if ! grep -q '^OPENBAO_SECRET_ID=' "$sec/approle.env"; then
    rid=$(bao read -field=role_id auth/approle/role/mrpostman/role-id)
    sid=$(bao write -f -field=secret_id auth/approle/role/mrpostman/secret-id)
    (umask 077; printf 'OPENBAO_ROLE_ID=%s\nOPENBAO_SECRET_ID=%s\n' "$rid" "$sid" > "$sec/approle.env")
    echo "kms-setup: AppRole credentials written to deploy/openbao/secrets/approle.env"
  fi
fi

dc up -d --remove-orphans
dc restart web >/dev/null 2>&1 || true
[[ " $* " == *" --release "* ]] && dc restart tls >/dev/null 2>&1 || true
echo "kms-setup: stack up with the KMS profile"
