#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/load"
base=${LOAD_URL:-http://127.0.0.1:8080}
go run ./cmd/loadtest -url "$base" -duration "${LOAD_DURATION:-2s}" -warmup 300ms -workers 4 -gomaxprocs 1 -scenario clean -expect 200,429 -backpressure -report "$out/load/clean.json"
go run ./cmd/loadtest -url "$base" -duration "${LOAD_DURATION:-2s}" -warmup 300ms -workers 4 -gomaxprocs 1 -scenario stream -expect 200,429 -backpressure -report "$out/load/stream.json"
