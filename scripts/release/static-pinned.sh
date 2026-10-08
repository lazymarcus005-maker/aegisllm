#!/bin/sh
set -u
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/security"
. "$root/scripts/release/toolchain.sh"
tool_cache=${RELEASE_TOOL_CACHE:-/tmp/aegisllm-release-tool-cache}
mkdir -p "$tool_cache/mod" "$tool_cache/build"
staticcheck_status=0
govulncheck_status=0
gosec_status=0
docker run --rm --user root -v "$tool_cache/mod:/go/pkg/mod" -v "$tool_cache/build:/root/.cache/go-build" -v "$root:/src" -w /src "$GO_TOOL_IMAGE" sh -ceu '
  export GOBIN=/tmp/release-tools; mkdir -p "$GOBIN"
  export GOFLAGS=-buildvcs=false
  go install honnef.co/go/tools/cmd/staticcheck@2025.1.1
  /tmp/release-tools/staticcheck ./... > /src/build/release/security/staticcheck.txt
' >"$out/security/staticcheck-tool.log" 2>&1 || staticcheck_status=$?
docker run --rm --user root -v "$tool_cache/mod:/go/pkg/mod" -v "$tool_cache/build:/root/.cache/go-build" -v "$root:/src" -w /src "$GO_TOOL_IMAGE" sh -ceu '
  export GOBIN=/tmp/release-tools; mkdir -p "$GOBIN"
  export GOFLAGS=-buildvcs=false
  go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
  /tmp/release-tools/govulncheck -json ./... > /src/build/release/security/govulncheck.json
' >"$out/security/govulncheck-tool.log" 2>&1 || govulncheck_status=$?
docker run --rm --user root -v "$tool_cache/mod:/go/pkg/mod" -v "$tool_cache/build:/root/.cache/go-build" -v "$root:/src" -w /src "$GO_TOOL_IMAGE" sh -ceu '
  export GOBIN=/tmp/release-tools; mkdir -p "$GOBIN"
  export GOFLAGS=-buildvcs=false
  go install github.com/securego/gosec/v2/cmd/gosec@v2.22.8
  /tmp/release-tools/gosec -fmt=json -out=/src/build/release/security/gosec.json ./...
' >"$out/security/gosec-tool.log" 2>&1 || gosec_status=$?
python3 "$root/scripts/release/static_report.py" "$out/security" "$staticcheck_status" "$govulncheck_status" "$gosec_status"
