#!/bin/sh
set -u
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/security"
image=${GO_TOOL_IMAGE:-golang:1.25.0-bookworm}
status=0
docker run --rm --user root -v "$root:/src" -w /src "$image" sh -ceu '
  export GOBIN=/tmp/release-tools; mkdir -p "$GOBIN"
  export GOFLAGS=-buildvcs=false
  go install honnef.co/go/tools/cmd/staticcheck@2025.1.1
  /tmp/release-tools/staticcheck ./... > /src/build/release/security/staticcheck.txt
' >"$out/security/staticcheck-tool.log" 2>&1 || status=1
docker run --rm --user root -v "$root:/src" -w /src "$image" sh -ceu '
  export GOBIN=/tmp/release-tools; mkdir -p "$GOBIN"
  export GOFLAGS=-buildvcs=false
  go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
  /tmp/release-tools/govulncheck -json ./... > /src/build/release/security/govulncheck.json
' >"$out/security/govulncheck-tool.log" 2>&1 || status=1
if docker image inspect securego/gosec:2.22.8 >/dev/null 2>&1 || docker pull securego/gosec:2.22.8 >/dev/null 2>&1; then
  docker run --rm -v "$root:/src" -w /src securego/gosec:2.22.8 -fmt=json -out=/src/build/release/security/gosec.json ./... >"$out/security/gosec-tool.log" 2>&1 || status=1
else
  printf '%s\n' '{"status":"blocked","reason":"gosec:2.22.8 image unavailable"}' >"$out/security/gosec.json"
  status=1
fi
python3 - "$out/security" "$status" <<'PY'
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
tool_status = int(sys.argv[2])
try:
    staticcheck = [line for line in (out / "staticcheck.txt").read_text(errors="replace").splitlines()
                   if line and not line.startswith("-: error obtaining VCS status")]
except FileNotFoundError:
    staticcheck = []
gosec = {}
try:
    gosec = json.loads((out / "gosec.json").read_text())
except (FileNotFoundError, json.JSONDecodeError):
    pass
govuln_findings = 0
try:
    decoder = json.JSONDecoder()
    raw = (out / "govulncheck.json").read_text()
    offset = 0
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset >= len(raw):
            break
        event, offset = decoder.raw_decode(raw, offset)
        govuln_findings += int("finding" in event)
except (FileNotFoundError, json.JSONDecodeError):
    pass
gosec_findings = len(gosec.get("Issues", [])) if isinstance(gosec, dict) else 0
findings = len(staticcheck) + govuln_findings + gosec_findings
if tool_status:
    status = "fail" if findings else "blocked"
    reason = ("actionable findings; see staticcheck.txt, govulncheck.json, and gosec.json"
              if findings else "external tool, network, or vulnerability database unavailable")
else:
    status = "fail" if findings else "pass"
    reason = "actionable findings; see per-tool reports" if findings else ""
report = {
    "schema_version": "aegisllm.static/v1",
    "status": status,
    "staticcheck": "2025.1.1",
    "staticcheck_findings": len(staticcheck),
    "govulncheck": "v1.1.4",
    "govulncheck_findings": govuln_findings,
    "gosec": "v2.22.8",
    "gosec_findings": gosec_findings,
    "container": "golang:1.25.0-bookworm",
    "allowlist": "security/findings-allowlist.yaml",
    "reason": reason,
}
(out / "static-pinned.json").write_text(json.dumps(report, sort_keys=True) + "\n")
raise SystemExit(1 if status != "pass" else 0)
PY
