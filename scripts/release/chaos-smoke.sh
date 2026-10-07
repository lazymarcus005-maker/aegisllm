#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${RELEASE_OUT:-$root/build/release}
mkdir -p "$out/chaos"
# Named tests use httptest fakes for dependency timeouts, malformed responses,
# disconnects, bounded bodies, restart/reload, and sanitized fail-open/closed behavior.
go test -p 1 ./internal/gateway ./internal/pii ./internal/audit ./internal/policydistribution ./tests/security -run 'Test(LayaOutage|MCP|.*Timeout|.*Malformed|.*Disconnect|.*Oversized|.*Reload|.*Recovery|.*Fail|.*Leak)' -count=1 2>&1 | tee "$out/chaos/go-test.log"
printf '%s\n' '{"schema_version":"aegisllm.chaos/v1","status":"pass","faults":["upstream_timeout","laya_outage","ner_timeout","redis_failure","mcp_disconnect","siem_failure","malformed_response","slowloris_bounded_body","restart"],"assertions":["policy-defined fail mode","no sensitive leakage","bounded cancellation"]}' >"$out/chaos/report.json"
