#!/bin/sh
# Starts the Inferno Da Vinci CRD test kit at a pinned version on
# http://localhost:18080 for InfernoCrdClientSuiteTest. See docs/inferno.md.
#
#   tools/inferno/start.sh [checkout-dir]   # default: target/inferno-kit
#   tools/inferno/stop.sh  [checkout-dir]
set -eu

KIT_TAG=v0.14.2
KIT_COMMIT=35dd6ff5cde916e2b1c72f4ce5ac377e1e4fb491
HERE=$(cd "$(dirname "$0")" && pwd)
DIR=${1:-target/inferno-kit}

if [ ! -d "$DIR/.git" ]; then
  git clone --quiet --depth 1 --branch "$KIT_TAG" https://github.com/inferno-framework/davinci-crd-test-kit.git "$DIR"
fi
actual=$(git -C "$DIR" rev-parse HEAD)
if [ "$actual" != "$KIT_COMMIT" ]; then
  echo "expected davinci-crd-test-kit $KIT_TAG at $KIT_COMMIT, found $actual" >&2
  exit 1
fi

cp "$HERE/compose.override.yml" "$DIR/compose.override.yml"
compose="docker compose -p crd-inferno -f $DIR/docker-compose.yml -f $DIR/compose.override.yml"
$compose build --quiet
$compose run --rm inferno bundle exec inferno migrate > /dev/null
$compose up -d

for _ in $(seq 1 60); do
  if curl -sf http://localhost:18080/api/test_suites/crd_client_v221 > /dev/null; then
    echo "Inferno CRD test kit $KIT_TAG is up at http://localhost:18080"
    exit 0
  fi
  sleep 5
done
$compose logs --tail 50
exit 1
