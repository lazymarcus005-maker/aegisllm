#!/usr/bin/env bash
set -euo pipefail

compose_file="${1:-docker-compose.fake-fleet.yml}"
cleanup() {
  docker compose -f "$compose_file" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker compose -f "$compose_file" up -d --build fake-fleet-control-plane
for _ in $(seq 1 30); do
  if curl --fail --silent http://127.0.0.1:18092/health >/dev/null; then
    break
  fi
  sleep 1
done
curl --fail --silent http://127.0.0.1:18092/health | grep -q 'fake-contract-only'
curl --fail --silent 'http://127.0.0.1:18092/v1/fleet/inventory?limit=1' | grep -q '"version":1'
echo "fake fleet Compose smoke: pass (contract fixture only)"
