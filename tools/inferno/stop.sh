#!/bin/sh
# Stops and removes the containers started by tools/inferno/start.sh.
set -eu
DIR=${1:-target/inferno-kit}
docker compose -p crd-inferno -f "$DIR/docker-compose.yml" -f "$DIR/compose.override.yml" down
