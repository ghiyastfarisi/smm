#!/bin/sh
# One-shot (service openbao-setup), runs on every `docker compose up -d`. Idempotent:
#   first run   init OpenBAO (Shamir 3-of-5) → /secrets/init.txt (deploy/openbao/secrets on the host, mode 600),
#               unseal, KV v2 + root secret from ENCRYPTION_KEY/ENCRYPTION_KEY_FACTOR, read-only policy, AppRole
#   later runs  unseal with init.txt while it is still on the host; once you have handed out the shares and deleted
#               it, it waits until 3 holders unseal (docker compose exec openbao bao operator unseal), and the server
#               starts after that (fail closed)
# The AppRole credentials go to /approle/approle.env (volume `approle`, mounted only by the server). The shares and
# the root token never reach the server container.
set -eu
init=/secrets/init.txt
st() { bao status -format=json 2>/dev/null || true; }
is() { st | grep -q "\"$1\": $2"; }

i=0; until st | grep -q '"initialized"'; do i=$((i + 1)); [ $i -gt 60 ] && { echo "openbao-setup: OpenBAO not reachable" >&2; exit 1; }; sleep 1; done

if is initialized false; then
  (umask 077; bao operator init -key-shares=5 -key-threshold=3 > "$init.tmp" && mv "$init.tmp" "$init")
  owner=$(stat -c %u:%g /policy.hcl); chown "$owner" /secrets "$init"   # readable by the checkout's owner, not root
  echo "openbao-setup: initialised; 5 unseal shares + root token in deploy/openbao/secrets/init.txt"
fi

if is sealed true; then
  if [ -f "$init" ]; then
    for n in 1 2 3; do bao operator unseal "$(awk -v n="$n" '$0 ~ "^Unseal Key "n":" {print $4}' "$init")" >/dev/null; done
    echo "openbao-setup: unsealed with init.txt (production: hand out the shares and delete it)"
  else
    echo "openbao-setup: sealed — 3 share holders: docker compose exec openbao bao operator unseal (waiting)"
    until is sealed false; do sleep 5; done
  fi
fi

if [ -s /approle/approle.env ] && [ ! -f "$init" ]; then echo "openbao-setup: ready"; exit 0; fi
[ -f "$init" ] || { echo "openbao-setup: no init.txt and no AppRole yet; restore deploy/openbao/secrets/init.txt" >&2; exit 1; }
export BAO_TOKEN; BAO_TOKEN=$(awk '/^Initial Root Token:/ {print $4}' "$init")
i=0; until bao secrets list >/dev/null 2>&1; do i=$((i + 1)); [ $i -gt 30 ] && exit 1; sleep 1; done   # raft leader

bao secrets list | grep -q '^secret/' || bao secrets enable -path=secret kv-v2 >/dev/null
if ! bao kv get -mount=secret -field=key mrpostman/root >/dev/null 2>&1; then
  [ -n "${ENCRYPTION_KEY:-}" ] && [ -n "${ENCRYPTION_KEY_FACTOR:-}" ] || { echo "openbao-setup: set ENCRYPTION_KEY and ENCRYPTION_KEY_FACTOR in deploy/.env" >&2; exit 1; }
  bao kv put -mount=secret mrpostman/root key="$ENCRYPTION_KEY" factor="$ENCRYPTION_KEY_FACTOR" \
    old_keys="${ENCRYPTION_KEY_OLD:-}" old_factors="${ENCRYPTION_KEY_FACTOR_OLD:-}" >/dev/null
  echo "openbao-setup: root secret written from deploy/.env"
fi
bao policy write mrpostman-read /policy.hcl >/dev/null
bao auth list | grep -q '^approle/' || bao auth enable approle >/dev/null
bao write auth/approle/role/mrpostman token_policies=mrpostman-read \
  token_ttl=1h token_max_ttl=4h secret_id_ttl=0 secret_id_num_uses=0 token_num_uses=0 >/dev/null
if [ ! -s /approle/approle.env ]; then
  rid=$(bao read -field=role_id auth/approle/role/mrpostman/role-id)
  sid=$(bao write -f -field=secret_id auth/approle/role/mrpostman/secret-id)
  printf 'OPENBAO_ROLE_ID=%s\nOPENBAO_SECRET_ID=%s\n' "$rid" "$sid" > /approle/approle.env
  chmod 644 /approle/approle.env   # read by the server (uid 2000); the volume is mounted only there
  echo "openbao-setup: AppRole credentials issued"
fi
echo "openbao-setup: ready"
