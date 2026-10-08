#!/bin/sh
set -u
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/logs"
rm -f "$out/evidence.jsonl" "$out/evidence-manifest.json"
blockers=0
record() {
    id=$1; status=$2; command=$3; reason=${4:-}; exit_code=${5:-0}
    report_hash=$(find "$out" -type f ! -name 'evidence*' -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null | sha256sum | awk '{print $1}')
    cmd_json=$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$command")
    reason_json=$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$reason")
    go_json=$(go version | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))')
    docker_json=$(docker version --format '{{.Server.Version}}' 2>/dev/null | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip() or "unavailable"))')
    printf '{"schema_version":"aegisllm.evidence/v1","stage":"%s","command":%s,"tool_versions":{"go":%s,"docker":%s},"report_hash":"%s","status":"%s","exit_code":%s,"reason":%s}\n' "$id" "$cmd_json" "$go_json" "$docker_json" "$report_hash" "$status" "$exit_code" "$reason_json" >>"$out/evidence.jsonl"
}
required() {
    id=$1; shift; command=$*
    echo "== $id =="
    if (cd "$root" && RELEASE_OUT="$out" sh -c "$command") >"$out/logs/$id.log" 2>&1; then
        if [ "$id" = normal ] && [ -n "${HOST_GO_WARNING:-}" ]; then
            record "$id" pass "$command" "$HOST_GO_WARNING" 0
        else
            record "$id" pass "$command" "" 0
        fi
    else
        exit_code=$?
        cat "$out/logs/$id.log" >&2
        status=fail
        reason="required stage failed"
        case "$id" in
            static-security) report="$out/security/static-pinned.json" ;;
            licenses) report="$out/supply-chain/licenses.json" ;;
            image-scan) report="$out/supply-chain/image-scan.json" ;;
            *) report="" ;;
        esac
        if [ -n "$report" ] && grep -q '"status": "blocked"\|"status":"blocked"' "$report" 2>/dev/null; then
            status=blocked
            reason=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("reason", "required external dependency unavailable"))' "$report" 2>/dev/null || printf '%s' 'required external dependency unavailable')
        fi
        record "$id" "$status" "$command" "$reason" "$exit_code"
        blockers=$((blockers+1))
    fi
}

host_go=$(go version 2>/dev/null || printf '%s' 'unavailable')
HOST_GO_WARNING=""
case "$host_go" in
    *go1.25.13*) ;;
    *) HOST_GO_WARNING="host toolchain $host_go; release artifacts are built/scanned in the pinned Go 1.25.13 container" ;;
esac

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
required static-security "$root/scripts/release/static-pinned.sh"
required licenses "$root/scripts/release/license-pinned.sh"
required image-scan "$root/scripts/release/image-scan.sh"

python3 - "$out/evidence.jsonl" "$out/evidence-manifest.json" <<'PY'
import json,sys
rows=[json.loads(x) for x in open(sys.argv[1]) if x.strip()]
required=["normal","race-docker","fuzz-smoke","benchmark","coverage","chaos","conformance-docker","e2e-docker","reproducible","secret-scan","sbom","static-security","licenses","image-scan"]
seen={row["stage"] for row in rows}
if seen != set(required): raise SystemExit("evidence manifest stage set is incomplete")
if any(row["exit_code"] == 0 and row["status"] != "pass" for row in rows): raise SystemExit("evidence status disagrees with a zero command exit")
if any(row["exit_code"] != 0 and row["status"] == "pass" for row in rows): raise SystemExit("evidence status disagrees with a non-zero command exit")
json.dump({"schema_version":"aegisllm.evidence-manifest/v1","required_skips_fail":True,"required_stages":required,"stages":rows},open(sys.argv[2],"w"),indent=2)
PY
if [ "$blockers" -ne 0 ]; then
    echo "release verification failed: $blockers required stage(s); inspect evidence-manifest.json" >&2
    exit 1
fi
echo "release verification passed: $out"
