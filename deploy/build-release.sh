#!/usr/bin/env bash
# Release build (OPS-15): builds everything from the checked-out tag and records what was built.
#   bash deploy/build-release.sh            needs: HEAD exactly on a tag, clean tree
#   ALLOW_DIRTY=1 bash deploy/build-release.sh   for a dry run on a working copy
# Output: docs/smm/releases/build-<tag>.txt — commit id, image ids, and sha256 of the server/mmctl
# binariesand the stock web client. To check reproducibility, run it from a fresh
# `git clone` of the same tag on another machine and diff the two files.
# ponytail: compares binaries and bundles, not image digests (layer timestamps differ per build); add
# SOURCE_DATE_EPOCH + rewrite-timestamp if byte-identical images are required.
set -euo pipefail
cd "$(dirname "$0")"
root=..
tag=$(git -C $root describe --tags --exact-match 2>/dev/null || true)
if [ -z "${ALLOW_DIRTY:-}" ]; then
  [ -n "$tag" ] || { echo "build-release: HEAD is not on a tag" >&2; exit 1; }
  [ -z "$(git -C $root status --porcelain)" ] || { echo "build-release: working tree not clean" >&2; exit 1; }
fi
tag=${tag:-untagged-$(git -C $root rev-parse --short HEAD)}

docker compose build server

sum() { docker run --rm --entrypoint sh "$1" -c "$2"; }
out=$root/docs/smm/releases/build-$tag.txt
{
  echo "tag            $tag"
  echo "built          $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(uname -sm)"
  echo "commit         $(git -C $root rev-parse HEAD)"
  echo "image server   $(docker image inspect --format '{{.Id}}' mrpostman-server:local)"
  sum mrpostman-server:local 'cd /mattermost/bin && sha256sum mattermost mmctl' | awk '{printf "sha256 bin     %-12s %s\n", $2, $1}'
  echo "sha256 client  $(sum mrpostman-server:local 'cd /mattermost/client && find . -type f | LC_ALL=C sort | xargs sha256sum | sha256sum' | cut -d' ' -f1)  (stock web app, all files)"
} | tee "$out"
echo "build-release: wrote ${out#../}"
