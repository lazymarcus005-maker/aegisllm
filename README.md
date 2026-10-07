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
docker compose up --build                 # development profile, security off
# gateway on :8080, mock upstream on :9090
curl -s http://localhost:8080/health
curl -s http://localhost:8080/ready

curl -s http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-Application-Id: demo' \
  -d '{"model":"mock-model","messages":[{"role":"user","content":"hello"}]}'
```

To exercise the shadow deployment contract against the same local mock and
Redis services:

```bash
docker compose -f docker-compose.yml -f docker-compose.shadow.yml up --build
```

Production uses the reviewed image plus external upstream and Redis services;
start from [.env.production.example](.env.production.example) and
[docker-compose.production.example.yml](docker-compose.production.example.yml).
The production profile rejects missing protection settings before it opens a
listening socket.

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
| `DEPLOYMENT_PROFILE` | `development` | `development`, `shadow`, or `production` |
| `UPSTREAM_BASE_URL` | — (required) | Upstream LLM Gateway base URL |
| `UPSTREAM_CHAT_PATH_PREFIX` | — | Optional inbound path prefix to strip before forwarding (for example `/generic`) |
| `UPSTREAM_AUTH_MODE` | `none` | `none`, `bearer`, or `header` |
| `UPSTREAM_API_KEY` | — | Key for `bearer` mode (never a client-supplied value) |
| `MAX_BODY_BYTES` | `1048576` | Request body limit (oversized → 413) |
| `MAX_RESPONSE_BYTES` | `4194304` | Maximum buffered upstream response (oversized → sanitized 502) |
| `MAX_PROMPT_CHARS` | `65536` | Normalized prompt character budget (oversized → 413) |
| `MAX_STREAM_DURATION` | `5m` | Maximum stream lifetime |
| `UPSTREAM_DIAL_TIMEOUT` / `UPSTREAM_TLS_HANDSHAKE_TIMEOUT` | `5s` | Upstream connection bounds |
| `UPSTREAM_RESPONSE_HEADER_TIMEOUT` | `30s` | Maximum wait for upstream headers |
| `UPSTREAM_REQUEST_TIMEOUT` | `2m` | Overall upstream request bound |
| `UPSTREAM_IDLE_CONN_TIMEOUT` / `UPSTREAM_MAX_IDLE_CONNS` | `90s` / `100` | Upstream pool bounds |
| `UPSTREAM_BREAKER_FAILURE_THRESHOLD` / `UPSTREAM_BREAKER_OPEN_INTERVAL` | `3` / `30s` | Process-local upstream circuit breaker |
| `SERVER_READ_HEADER_TIMEOUT` / `SERVER_READ_TIMEOUT` / `SERVER_IDLE_TIMEOUT` | `10s` / `30s` / `2m` | Inbound server bounds |
| `SERVER_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown bound |
| `REQUESTS_PER_SECOND` / `RATE_BURST` | `10` / `20` | Per-identity token bucket |
| `MAX_CONCURRENT_REQUESTS` | `16` | Per-identity concurrency cap |
| `MAX_CONCURRENT_LAYA` | `4` | Global in-process Laya evaluation cap |
| `LIMITER_MAX_KEYS` / `LIMITER_KEY_IDLE_TIMEOUT` | `10000` / `10m` | Bounded limiter key lifecycle |
| `SECURITY_MODE` | `off` | `off`, `shadow`, `enforce` |
| `AUTH_MODE` | `off` | `off` for development compatibility or `jwt` for authenticated ingress |
| `JWT_PUBLIC_KEY_FILE` | — | PEM RSA (RS256) or P-256 EC (ES256) public key for JWT mode |
| `JWT_HMAC_SECRET` | — | Development/test only HS256 secret; rejected in shadow/production |
| `JWT_ISSUER` / `JWT_AUDIENCE` | — | Expected JWT issuer and audience; required in production |
| `JWT_*_CLAIM` | see `.env.example` | Claim names for tenant, application, subject, roles, and provider |
| `ALLOW_UNAUTHENTICATED_SHADOW` | `false` | Explicit local development waiver; carries spoofing risk |
| `POLICY_FILE` / `QUESTIONS_FILE` / `THRESHOLDS_FILE` | versioned repo assets | Reviewed policy and semantic assets |
| `TOKEN_VAULT_KEY` | ephemeral in development | Required as 64 hex chars in production |
| `TOKEN_VAULT_REDIS_URL` | in-memory in development | Required in production |
| `TELEMETRY_HMAC_KEY` | empty in development | Required in production |
| `DEFAULT_TARGET_PROVIDER` | `cloud` | Provider class when `X-Target-Provider` absent |

With `AUTH_MODE=off`, development retains the compatibility headers
`X-Application-Id`, `X-Tenant-Id`, `X-User-Id`, and `X-Target-Provider`. With
`AUTH_MODE=jwt`, those headers are ignored and stripped; tenant, application,
user, roles, and provider metadata come only from verified JWT claims. JWT
defaults are `tenant_id`, `azp`, `sub`, `roles`, and `provider` respectively.
LLM POST routes and `/v1/models` require `aegis.invoke` or `aegis.operator`;
the dashboard, protection stats, and metrics require `aegis.operator`.

Rate and concurrency controls are process-local and keyed by verified
tenant/application in JWT mode. Development uses application plus remote
address as a compatibility fallback. Multiple gateway instances require an
external/distributed limiter for global enforcement; that is deferred.

## Repository layout

Layered modules from `docs/code-structure.md`, adapted to Go conventions:

```
cmd/gateway/          gateway binary
cmd/mockupstream/     OpenAI-compatible mock upstream for local dev
internal/core/        domain models: InspectionEnvelope, findings, enums
internal/gateway/     transport server + application pipeline orchestration
internal/detectors/   infrastructure: deterministic detection framework
internal/pii/         infrastructure: PII spans + transformation planner
internal/decision/    infrastructure: DecisionProvider and Laya adapter
internal/policy/      domain policy-as-code schema + deterministic engine
internal/tokenization/ infrastructure: tokenizer + encrypted token vault
internal/audit/       infrastructure: sanitized audit events
internal/observability/ infrastructure: metrics + tracing
internal/dashboard/   transport: sanitized protection statistics
web/leaderboard/      transport: embedded dashboard assets
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
`shadow_disagreements_total`, `fallback_total`, `transformations_total`,
`rate_limited_total`, `concurrency_rejected_total`,
`prompt_budget_rejected_total`, `response_too_large_total`,
`upstream_timeout_total`, `breaker_open_total`, `active_requests`, and
`active_laya_evaluations`. Runtime metrics have no tenant/application labels.
Docker Compose includes a Prometheus scraping the gateway; see
[docs/operations.md](docs/operations.md) for runbook guidance.

## Protection Leaderboard

Open [http://localhost:8080/dashboard](http://localhost:8080/dashboard) while
the gateway is running to see a live leaderboard of prevented sensitive sends.
The headline count is `blocked + tokenized + redacted + review`; the rows are
sanitized finding categories and subtypes, with no raw request content.

```bash
curl -s http://localhost:8080/api/protection-stats
```

The dashboard polls the JSON endpoint every two seconds and supports Thai and
English labels, responsive light/dark styling, and reduced-motion preferences.

## Documentation

- [docs/spec.md](docs/spec.md) — requirements (FR/NFR/UC/AS)
- [docs/architecture.md](docs/architecture.md) — design and trust boundaries
- [docs/implement.handoff.md](docs/implement.handoff.md) — delivery plan
- [docs/threat-model.md](docs/threat-model.md) — threats, controls, residual risk
- [docs/operations.md](docs/operations.md) — runbook
- [docs/policy-authoring.md](docs/policy-authoring.md) — policy contract, profiles, and simulator
- [docs/mvp-dod-checklist.md](docs/mvp-dod-checklist.md) — DoD audit with evidence
- [docs/adr/](docs/adr/) — architecture decision records

## Development

```bash
go build ./...
go vet ./...
go test ./...
gofmt -l .
```

The gateway accepts OpenAI-compatible chat/responses/completions/embeddings and
Anthropic-compatible messages/complete endpoints, plus generic aliases such as
`/message`, `/chatcompletion`, and `/response`. All supported POST formats use
the same normalized security pipeline. `GET /v1/models` is a body-free
passthrough with audit/metrics coverage. Streaming requests are inspected for
audit evidence but forwarded verbatim and are never blocked or rewritten.
They remain subject to admission, prompt/response budgets, upstream timeouts,
and `MAX_STREAM_DURATION`; streamed content inspection is deferred to P0.3.
