# Laya LLM Security Gateway

A pluggable LLM security gateway that sits between applications/agents and an
existing LLM Gateway. It inspects content before and after LLM requests and
produces deterministic enforcement actions based on deterministic secret/PII
detection, span-oriented PII detection, Laya semantic decision evidence,
identity/application/model metadata, and versioned policy-as-code. Detected
secrets are hard-masked (`[REDACTED:SUBTYPE]`) by the default policy so the
raw value never leaves the gateway; per-subtype `block` is also available.

> Deterministic code enforces policy. Laya contributes semantic classification
> and risk signals. The LLM being protected never gets authority to override
> security policy.

Read [docs/spec.md](docs/spec.md) (requirements), [docs/architecture.md](docs/architecture.md)
(design), and [docs/implement.handoff.md](docs/implement.handoff.md) (delivery plan).

## Quick start (local)

```bash
docker compose up --build
# gateway on :8080, mock upstream on :9090
curl -s http://localhost:8080/health
curl -s http://localhost:8080/ready

curl -s http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-Application-Id: demo' \
  -d '{"model":"mock-model","messages":[{"role":"user","content":"hello"}]}'
```

Run natively instead:

```bash
go run ./cmd/mockupstream          # terminal 1 (listens on :9090)
UPSTREAM_BASE_URL=http://localhost:9090 go run ./cmd/gateway   # terminal 2
```

## Configuration

All configuration is environment-based; see [.env.example](.env.example).

| Variable | Default | Purpose |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8080` | Gateway listen address |
| `UPSTREAM_BASE_URL` | — (required) | Upstream LLM Gateway base URL |
| `UPSTREAM_AUTH_MODE` | `none` | `none`, `bearer`, or `header` |
| `UPSTREAM_API_KEY` | — | Key for `bearer` mode (never a client-supplied value) |
| `MAX_BODY_BYTES` | `1048576` | Request body limit (oversized → 413) |
| `SECURITY_MODE` | `off` | `off`, `shadow`, `enforce` |
| `DEFAULT_TARGET_PROVIDER` | `cloud` | Provider class when `X-Target-Provider` absent |

Identity/application/model metadata comes from trusted headers:
`X-Application-Id`, `X-Tenant-Id`, `X-User-Id`, `X-Target-Provider`.

## Repository layout

Conceptual modules from `implement.handoff.md`, adapted to Go conventions:

```
cmd/gateway/          gateway binary
cmd/mockupstream/     OpenAI-compatible mock upstream for local dev
internal/core/        domain models: InspectionEnvelope, findings, enums
internal/gateway/     HTTP server, OpenAI parser, upstream proxy, config
internal/detectors/   deterministic detection framework + detectors
internal/pii/         PII span providers + transformation planner
internal/decision/    DecisionProvider abstraction (Laya adapter, planner)
internal/policy/      policy-as-code schema + deterministic engine
internal/tokenization/ tokenizer + encrypted token vault
internal/audit/       sanitized audit events
internal/observability/ metrics + tracing
policies/             versioned policy-as-code (YAML)
questions/            versioned Laya security question schemas
evals/                datasets, baselines, reports
tests/                cross-package test corpora (golden/security/integration)
docs/                 spec, architecture, handoff, threat model, ADRs
```

## Observability

`GET /metrics` exposes the Prometheus metric set from spec §15:
`security_requests_total{action,mode}`, `findings_total{category,subtype}`,
`laya_calls_total` / `laya_errors_total` / `laya_latency_ms`,
`scanner_latency_ms`, `gateway_security_latency_ms`,
`shadow_disagreements_total`, `fallback_total`, `transformations_total`.
Docker Compose includes a Prometheus scraping the gateway; see
[docs/operations.md](docs/operations.md) for runbook guidance.

## Documentation

- [docs/spec.md](docs/spec.md) — requirements (FR/NFR/UC/AS)
- [docs/architecture.md](docs/architecture.md) — design and trust boundaries
- [docs/implement.handoff.md](docs/implement.handoff.md) — delivery plan
- [docs/threat-model.md](docs/threat-model.md) — threats, controls, residual risk
- [docs/operations.md](docs/operations.md) — runbook
- [docs/mvp-dod-checklist.md](docs/mvp-dod-checklist.md) — DoD audit with evidence
- [docs/adr/](docs/adr/) — architecture decision records

## Development

```bash
go build ./...
go vet ./...
go test ./...
gofmt -l .
```

`/v1/responses` support is deferred per FR-001 (the MVP may implement one
endpoint first; the normalizer abstraction supports both). Streaming requests
are forwarded verbatim in `off` mode; security behavior for streaming follows
the staged plan in architecture §13.
