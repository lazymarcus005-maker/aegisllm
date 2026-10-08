#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/conformance"
compose="docker compose -f $root/docker-compose.conformance.yml"
cleanup() { $compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
$compose up -d --build
ready=0
for _ in $(seq 1 40); do
    if curl --fail --silent http://127.0.0.1:8080/health >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
done
[ "$ready" -eq 1 ] || { $compose logs; exit 1; }
go run ./cmd/conformancetool run --target http://127.0.0.1:8080 --report "$out/conformance/24-case.json" --junit "$out/conformance/24-case.xml"
go run ./cmd/conformancetool validate-report --report "$out/conformance/24-case.json" --junit "$out/conformance/24-case.xml"
python3 - "$out/conformance/24-case.json" <<'PY'
import json, sys
r=json.load(open(sys.argv[1]))
cases=r.get("cases", [])
if len(cases) != 24 or any(c.get("required") and c.get("status") != "pass" for c in cases):
    raise SystemExit("conformance gate requires exactly 24 passing required cases")
PY
