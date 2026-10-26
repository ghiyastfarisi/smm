#!/usr/bin/env bash
# Dumps the compose database and searches it for plaintext. Usage: bash deploy/verify-encryption.sh ["text you sent"]
set -uo pipefail
cd "$(dirname "$0")"
dump="$(docker compose exec -T db pg_dump -U mmuser mrpostman)"
fail=0
check() {
  local n; n=$(grep -ciF -- "$2" <<<"$dump")
  if [ "$n" -eq 0 ]; then echo "OK    $1: not found in plaintext"; else echo "FAIL  $1: $n plaintext hits"; fail=1; fi
}
check "user emails (@smm.demo)" "@smm.demo"
check "last name 'Wijaya'" "Wijaya"
[ $# -gt 0 ] && check "message '$1'" "$1"
for v in v1 v2 v3 v4; do echo "encrypted values (enc:$v:) in dump: $(grep -o "enc:$v:" <<<"$dump" | wc -l)"; done
echo "sample stored message: $(docker compose exec -T db psql -U mmuser -d mrpostman -tAc "select left(message,60) from posts where type='' order by createat desc limit 1")"
exit $fail
