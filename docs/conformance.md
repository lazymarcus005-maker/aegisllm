# Provider conformance lab (P1.8)

The lab is a versioned compatibility contract for AegisLLM's public HTTP
boundary. CI uses only the deterministic, non-production fake provider. Reports
contain hashes, byte counts, bounded semantic shapes, safe headers, statuses,
and reason IDs; request/response bodies and credentials never enter reports,
JUnit, stdout, metrics labels, or audit events.

## Contract and matrix

The source of truth is [`conformance/spec/v1.yaml`](../conformance/spec/v1.yaml).
Version 1 covers OpenAI chat (`/v1/chat/completions`), OpenAI Responses
(`/v1/responses`), Anthropic Messages (`/v1/messages` and
`/anthropic/v1/messages`), and generic aliases (`/v1/chatcompletion` and
`/v1/response`). Each profile covers JSON and SSE, tools, model aliases,
system/user/assistant content, usage, finish/stop reasons, request IDs,
Unicode/Thai, errors, rate limits, timeouts, cancellation, and bounded
payload/event limits. Unsupported fields explicitly say pass-through, ignore,
or reject in the spec; fields absent from the spec are not compatibility
promises.

## Commands

```bash
go run ./cmd/conformancetool list
go run ./cmd/conformancetool run --target https://gateway.example \
  --auth-file /run/conformance/auth.json \
  --report artifacts/conformance.json --junit artifacts/conformance.xml
go run ./cmd/conformancetool validate-report --report artifacts/conformance.json \
  --junit artifacts/conformance.xml
go run ./cmd/conformancetool compare --baseline baseline.json \
  --candidate artifacts/conformance.json --report artifacts/diff.json
```

Auth descriptors contain only environment-variable or mounted-file names,
never values. TLS uses `--ca-file`, `--client-cert`, and `--client-key`; the
same rule applies to credentials. Required failure or skip exits nonzero.

The local path is `./scripts/conformance-smoke.sh`; Docker uses
`docker-compose.conformance.yml`. `fakeprovider` supports per-case status,
Retry-After, delay, fragmentation, malformed SSE, disconnects, oversize output,
tool calls, usage, and sensitive test output. It never logs bodies and is
clearly non-production. Real-provider probes are manual/opt-in only.

## Adding cases and fixtures

Add the profile and unsupported-field behavior to `spec/v1.yaml`, add a
table-driven request in `internal/conformance/spec.go`, and add deterministic
fake behavior where transport behavior matters. Assert normalized semantic
shapes, never IDs, timestamps, raw content, or chunk boundaries. Run through a
real HTTP listener. Golden fixtures under `conformance/fixtures/` are updated
only by an explicit reviewed command:

```bash
go run ./cmd/conformancetool update-fixtures --report reviewed.json \
  --dir conformance/fixtures --confirm
```

Normal tests cannot update fixtures. Fixtures contain no vendor-recorded
payloads or credentials.

## Results and certification

`pass` means status and normalized shape matched. `fail` is a regression or
unavailable target. `skip` is never a pass for a required profile. Compare mode
reports semantic status/shape/presence diffs and latency delta, and is intended
only for lab traffic. Release certification requires all four profiles,
malformed/error/cancel/timeout/oversize and header-isolation checks, validated
JSON/JUnit with a secret scan, baseline self-compare, capability-gate and
last-known-good reload tests, full Go build/vet/tests, and Docker smoke.

## Capability declarations and known deviations

With `CONFORMANCE_CAPABILITY_GATE=true`, advanced chat/responses/messages,
streaming, and tools require an explicit declaration containing
`schema_version: aegisllm.conformance/v1`, feature booleans, and a 64-hex
SHA-256 reviewed-report hash. Undeclared routes are rejected; malformed reloads
retain the last-known-good registry. Operators see only the sanitized summary
at `/api/providers/conformance`. Remote reports are never trusted
automatically. v1 does not promise every vendor extension and does not convert
native provider wire formats into each other; it verifies acceptance,
protection, routing, and return semantics at the gateway boundary.
