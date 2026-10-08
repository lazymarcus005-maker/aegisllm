#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/security"
report="$out/security/secrets.json"
rm -f "$out/security/secrets.txt"
tracked=$(git -C "$root" ls-files)
diff=$(git -C "$root" diff HEAD -- . ':(exclude)build' ':(exclude)release-evidence' ':(exclude)scripts/release/secret-scan.sh' || true)
patterns='BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY|AKIA[0-9A-Z]{16}|-----BEGIN|xox[baprs]-[0-9A-Za-z-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}'
findings=$( { printf '%s\n' "$tracked" | while read -r f; do
    case "$f" in
        tests/security/*|internal/gateway/mcp_gateway_test.go|internal/detectors/detectors_test.go|internal/detectors/pii_test.go|internal/gateway/pipeline_test.go|internal/detectors/secrets.go|evals/datasets/security-v1.jsonl|scripts/release/secret-scan.sh) continue;;
    esac
    [ -f "$root/$f" ] && rg -n -H -e "$patterns" "$root/$f" || true
done; printf '%s\n' "$diff" | rg -n -H -e "$patterns" || true; } | sort -u || true )
if [ -n "$findings" ]; then
    printf '%s\n' "$findings" >"$out/security/secrets.txt"
    printf '%s\n' '{"schema_version":"aegisllm.secret-scan/v1","status":"fail","findings_file":"secrets.txt"}' >"$report"
    exit 1
fi
printf '%s\n' '{"schema_version":"aegisllm.secret-scan/v1","status":"pass","private_key_findings":0,"scanned":"tracked tree and git diff"}' >"$report"
