#!/bin/sh
set -u
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/logs"
rm -f "$out/evidence.jsonl" "$out/evidence-manifest.json"
blockers=0
record() {
    id=$1; status=$2; command=$3; reason=${4:-}
    report_hash=$(find "$out" -type f ! -name 'evidence*' -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null | sha256sum | awk '{print $1}')
    cmd_json=$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$command")
    reason_json=$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$reason")
    go_json=$(go version | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))')
    docker_json=$(docker version --format '{{.Server.Version}}' 2>/dev/null | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip() or "unavailable"))')
    printf '{"schema_version":"aegisllm.evidence/v1","stage":"%s","command":%s,"tool_versions":{"go":%s,"docker":%s},"report_hash":"%s","status":"%s","reason":%s}\n' "$id" "$cmd_json" "$go_json" "$docker_json" "$report_hash" "$status" "$reason_json" >>"$out/evidence.jsonl"
}
required() {
    id=$1; shift; command=$*
    echo "== $id =="
    if (cd "$root" && RELEASE_OUT="$out" sh -c "$command") >"$out/logs/$id.log" 2>&1; then record "$id" pass "$command"; else cat "$out/logs/$id.log" >&2; record "$id" fail "$command" "required stage failed"; exit 1; fi
}
advisory() {
    id=$1; shift; command=$*
    echo "== $id =="
    if (cd "$root" && RELEASE_OUT="$out" sh -c "$command") >"$out/logs/$id.log" 2>&1; then
        record "$id" pass "$command"
    else
        cat "$out/logs/$id.log" >&2
        status=blocked
        reason="external tool, network, or vulnerability database unavailable; no pass asserted"
        if [ "$id" = image-scan ] && rg -q '"status":"fail"' "$out/supply-chain/image-scan.json" 2>/dev/null; then
            status=fail
            reason="actionable vulnerabilities found in final image; inspect trivy.json"
        fi
        record "$id" "$status" "$command" "$reason"
        blockers=$((blockers+1))
    fi
}

required normal "gofmt -l . | tee '$out/gofmt.txt'; test ! -s '$out/gofmt.txt'; go test -p 1 ./...; go build ./...; go vet ./...; git diff --check"
required race-docker "$root/scripts/release/race-docker.sh"
required fuzz-smoke "$root/scripts/release/fuzz-smoke.sh"
required benchmark "$root/scripts/release/benchmark-gate.sh"
required coverage "$root/scripts/release/coverage-gate.sh"
required chaos "$root/scripts/release/chaos-smoke.sh"
required conformance-docker "$root/scripts/release/conformance-docker.sh"
required e2e-docker "$root/scripts/release/e2e-docker.sh"
required reproducible "$root/scripts/release/reproducible-build.sh"
required secret-scan "$root/scripts/release/secret-scan.sh"
required sbom "$root/scripts/release/sbom.sh"
advisory static-security "$root/scripts/release/static-pinned.sh"
advisory licenses "$root/scripts/release/license-pinned.sh"
advisory image-scan "$root/scripts/release/image-scan.sh"

python3 - "$out/evidence.jsonl" "$out/evidence-manifest.json" <<'PY'
import json,sys
rows=[json.loads(x) for x in open(sys.argv[1]) if x.strip()]
json.dump({"schema_version":"aegisllm.evidence-manifest/v1","required_skips_fail":True,"stages":rows},open(sys.argv[2],"w"),indent=2)
PY
if [ "$blockers" -ne 0 ]; then
    echo "release verification blocked: $blockers external security/supply-chain stage(s); inspect evidence-manifest.json" >&2
    exit 1
fi
echo "release verification passed: $out"
