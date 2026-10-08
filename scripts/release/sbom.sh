#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/supply-chain"
. "$root/scripts/release/toolchain.sh"
docker run --rm --user root -v "$root:/src" -w /src "$GO_TOOL_IMAGE" sh -ceu 'go run /src/scripts/release/sbom.go /src/build/release/supply-chain/sbom.cdx.json'
python3 - "$out/supply-chain/sbom.cdx.json" <<'PY'
import json, sys
r=json.load(open(sys.argv[1]))
assert r["bomFormat"] == "CycloneDX" and r["specVersion"] == "1.5" and r["version"] == 1
assert isinstance(r["components"], list) and r["components"]
for c in r["components"]: assert c["type"] == "library" and c["purl"].startswith("pkg:golang/")
PY
