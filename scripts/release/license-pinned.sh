#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/supply-chain"
image=${GO_TOOL_IMAGE:-golang:1.25.0-bookworm}
docker run --rm --user root -v "$root:/src" -w /src "$image" sh -ceu '
  export GOBIN=/tmp/release-tools
  mkdir -p "$GOBIN"
  go install github.com/google/go-licenses@v1.6.0
  /tmp/release-tools/go-licenses report ./... > /src/build/release/supply-chain/licenses.csv
' >"$out/supply-chain/license-tool.log" 2>&1
if rg -v '^github.com/aegisllm/gateway/' "$out/supply-chain/licenses.csv" | rg -ni ',unknown|noassertion'; then
  printf '%s\n' '{"schema_version":"aegisllm.licenses/v1","status":"fail","reason":"dependency license is unknown or disallowed"}' >"$out/supply-chain/licenses.json"
  exit 1
fi
printf '%s\n' '{"schema_version":"aegisllm.licenses/v1","status":"pass","tool":"go-licenses v1.6.0","policy":"reviewed licenses; UNKNOWN/NOASSERTION prohibited"}' >"$out/supply-chain/licenses.json"
