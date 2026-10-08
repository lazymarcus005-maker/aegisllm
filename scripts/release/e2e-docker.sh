#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/e2e"
compose="docker compose -f $root/docker-compose.yml -f $root/docker-compose.shadow.yml"
cleanup() { $compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
export TOKEN_VAULT_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
export TELEMETRY_HMAC_KEY=release-gate-synthetic-key
$compose up -d --build
for _ in $(seq 1 45); do
    curl --fail --silent http://127.0.0.1:8080/health >/dev/null 2>&1 && break
    sleep 1
done
curl --fail --silent http://127.0.0.1:8080/ready >/dev/null
LOAD_URL=http://127.0.0.1:8080 RELEASE_OUT="$out" "$root/scripts/release/load-short.sh"
$compose restart security-gateway
for _ in $(seq 1 45); do
    curl --fail --silent http://127.0.0.1:8080/health >/dev/null 2>&1 && break
    sleep 1
done
curl --fail --silent http://127.0.0.1:8080/ready >/dev/null
printf '%s\n' '{"schema_version":"aegisllm.e2e/v1","status":"pass","profile":"shadow","dependencies":["mock-upstream","redis","fake-mcp","prometheus"],"restart":"pass","read_only_probe":"image policy checked separately"}' >"$out/e2e/report.json"
