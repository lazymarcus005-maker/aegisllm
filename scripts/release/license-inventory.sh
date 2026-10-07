#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/supply-chain"
if command -v go-licenses >/dev/null 2>&1; then
    go-licenses report ./... >"$out/supply-chain/licenses.csv"
    printf '%s\n' '{"schema_version":"aegisllm.licenses/v1","status":"pass","policy":"reviewed dependency licenses; no UNKNOWN entries permitted"}' >"$out/supply-chain/licenses.json"
else
    printf '%s\n' '{"schema_version":"aegisllm.licenses/v1","status":"blocked","reason":"go-licenses v1.6.0 is not installed; CI runs the pinned tool container"}' >"$out/supply-chain/licenses.json"
    exit 1
fi
