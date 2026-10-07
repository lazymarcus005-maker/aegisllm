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

Production uses the reviewed image plus an external route registry and Redis services;
start from [.env.production.example](.env.production.example) and
[docker-compose.production.example.yml](docker-compose.production.example.yml).
The production profile rejects missing protection settings before it opens a
listening socket. Direct gateway TLS is required unless the explicitly named
`TLS_TERMINATED_BY_TRUSTED_EDGE=true` contract is configured. Upstream, Laya,
and Redis use verified TLS (`https://`/`rediss://`); production never accepts
plaintext dependency URLs or inline secret values.

Run natively instead:

```bash
go run ./cmd/mockupstream          # terminal 1 (listens on :9090)
UPSTREAM_BASE_URL=http://localhost:9090 go run ./cmd/gateway   # terminal 2 (legacy development compatibility)
```

The local encrypted-link seam can be exercised without committing any
material: `./scripts/mtls-smoke.sh` creates an ephemeral CA and client/server
certificates in a temporary directory, verifies mTLS seams, and removes them.

## Configuration

All configuration is environment-based; see [.env.example](.env.example).

| Variable | Default | Purpose |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8080` | Gateway listen address |
| `DEPLOYMENT_PROFILE` | `development` | `development`, `shadow`, or `production` |
| `UPSTREAM_REGISTRY_FILE` | — | Strict versioned local/cloud route registry; required in production |
| `MCP_REGISTRY_FILE` / `MCP_CREDENTIALS_FILE` | — | Versioned MCP trust registry and separate opaque credential profiles |
| `MCP_SESSION_TTL` / `MCP_TOOL_SCHEMA_TTL` | `15m` / `5m` | Bounded session and sanitized tool-schema cache lifetimes |
| `MCP_MAX_BODY_BYTES` / `MCP_MAX_EVENT_BYTES` | `1048576` / `65536` | MCP JSON and SSE limits |
| `UPSTREAM_BASE_URL` | — | Legacy single-upstream compatibility, development only |
| `UPSTREAM_CHAT_PATH_PREFIX` | — | Optional inbound path prefix to strip before forwarding (for example `/generic`) |
| `UPSTREAM_AUTH_MODE` | `none` | `none`, `bearer`, or `header` |
| `UPSTREAM_API_KEY_FILE` / `UPSTREAM_AUTH_HEADER_VALUE_FILE` | — | Reloadable mounted credential files; production requires the applicable file |
| `UPSTREAM_TLS_CA_FILE` / `UPSTREAM_TLS_CERT_FILE` / `UPSTREAM_TLS_KEY_FILE` / `UPSTREAM_TLS_SERVER_NAME` | — | Upstream-specific trust and optional mTLS material |
| `MAX_BODY_BYTES` | `1048576` | Request body limit (oversized → 413) |
| `MAX_RESPONSE_BYTES` | `4194304` | Maximum buffered upstream response (oversized → sanitized 502) |
| `MAX_PROMPT_CHARS` | `65536` | Normalized prompt character budget (oversized → 413) |
| `MAX_STREAM_DURATION` | `5m` | Maximum stream lifetime |
| `MAX_SSE_EVENT_BYTES` | `65536` | Maximum one SSE event, including framing |
| `STREAM_INSPECTION_WINDOW` | `4096` | Rolling response holdback; production rejects values below 4096 |
| `MAX_BUFFERED_STREAM_BYTES` | `1048576` | Maximum queued stream bytes during inspection |
| `STREAM_FLUSH_INTERVAL` | `25ms` | Streaming flush/latency budget |
| `STREAM_FAIL_CLOSED` | `true` | Fail malformed/oversized streams closed; production always fails closed |
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
| `SECURITY_SEMANTIC_ENFORCE` | `false` | Requires a reachable real Laya provider and a promoted, provenance-bound threshold artifact |
| `LAYA_URL` / `LAYA_TIMEOUT` | — / `5s` | Operator-provided private Laya endpoint and bounded request timeout |
| `LAYA_TLS_CA_FILE` / `LAYA_TLS_CERT_FILE` / `LAYA_TLS_KEY_FILE` / `LAYA_TLS_SERVER_NAME` | — | Laya-specific trust and optional mTLS material |
| `PII_NER_REGISTRY_FILE` / `PII_NER_REQUIRED` | — / production default | Versioned private Presidio/Aegis NER registry and strict outage policy |
| `AUTH_MODE` | `off` | `off`, `jwt`, or direct `mtls` authenticated ingress |
| `INBOUND_TLS_CERT_FILE` / `INBOUND_TLS_KEY_FILE` / `INBOUND_TLS_CLIENT_CA_FILE` | — | Reloadable gateway listener certificate and optional client CA |
| `INBOUND_MTLS_MODE` | `off` | `require` verifies client certificates against the configured client CA |
| `TLS_MIN_VERSION` / `TLS_MAX_VERSION` / `TLS_RELOAD_INTERVAL` | `1.2` / automatic / `2s` | TLS floor, optional ceiling, and bounded material polling |
| `JWT_PUBLIC_KEY_FILE` | — | PEM RSA (RS256) or P-256 EC (ES256) public key for JWT mode |
| `JWT_HMAC_SECRET` | — | Development/test only HS256 secret; rejected in shadow/production |
| `JWT_ISSUER` / `JWT_AUDIENCE` | — | Expected JWT issuer and audience; required in production |
| `JWT_*_CLAIM` | see `.env.example` | Claim names for tenant, application, subject, roles, and provider |
| `ALLOW_UNAUTHENTICATED_SHADOW` | `false` | Explicit local development waiver; carries spoofing risk |
| `POLICY_FILE` / `QUESTIONS_FILE` / `THRESHOLDS_FILE` | versioned repo assets | Reviewed policy and semantic assets |
| `TOKEN_VAULT_KEYRING_FILE` / `TOKEN_VAULT_KEY_FILE` | ephemeral in development | Reloadable versioned keyring or legacy key file; production requires a file |
| `TOKEN_VAULT_REDIS_URL` | in-memory in development | Required as verified `rediss://` in production |
| `TOKEN_VAULT_REDIS_CA_FILE` / `TOKEN_VAULT_REDIS_CERT_FILE` / `TOKEN_VAULT_REDIS_KEY_FILE` | — | Redis-specific trust and optional mTLS material |
| `TELEMETRY_HMAC_KEY_FILE` | empty in development | Reloadable mounted secret; production requires the file |
| `DEFAULT_TARGET_PROVIDER` | `cloud` | Provider class when `X-Target-Provider` absent |

Evasion scanning is declared in the selected policy under `evasion`. The
reviewed profiles enable bounded NFKC/control/confusable projection, standard
and URL-safe Base64, percent encoding, JSON Unicode escapes, recursive JSON
string inspection, and one decode level by default. Limits cover decode work,
expansion, JSON depth/nodes/string bytes, and candidate size. Decoded or
cross-part findings carry only bounded `encoding_chain` metadata and fail
closed when the original span cannot be safely rewritten. Local and balanced
profiles must explicitly choose any broader transform or action.

The registry format and rollout/failover rules are documented in
[docs/routing.md](docs/routing.md); a development mock example is
[examples/upstream-registry.yaml](examples/upstream-registry.yaml). Production
route auth uses only `auth.secret_file` and route TLS reuses securetransport.

## MCP tool gateway

Set `MCP_REGISTRY_FILE` to enable `POST`, `GET` (SSE/session), and `DELETE`
at `/mcp/{server}`. The gateway authenticates the verified JWT/mTLS principal,
filters the upstream catalog by registry patterns and policy restrictions,
validates arguments against cached JSON Schemas, and inspects both tool calls
and results. Client `Authorization` and identity headers are never forwarded.
`MCP_CREDENTIALS_FILE` contains only file-backed header/bearer profiles or
OAuth2 client-credentials profiles; the referenced secret is resolved
immediately before the outbound tool request and is never logged or returned.
Operators can inspect only bounded metadata through
`GET /api/mcp/servers`, `/api/mcp/audit`, and `/api/mcp/metrics`.

The local compose stack includes `fake-mcp` and
[`examples/mcp-registry.yaml`](examples/mcp-registry.yaml). Its HTTP URL is
accepted only for development; production registry validation requires HTTPS,
rejects URL userinfo/inline credential query parameters, and uses configured
securetransport CA/mTLS files.

Semantic enforcement is fail-closed at startup: `SECURITY_SEMANTIC_ENFORCE=true`
requires `LAYA_URL`, a non-noop provider, matching question-schema and
checkpoint provenance, complete language/risk coverage, passing metrics, and
an explicitly promoted artifact. Production may remain deterministic-only with
the flag false; `/ready` then reports `semantic.status=disabled`. The committed
threshold file and `evals/reports/security-v1-synthetic-non-promoted.yaml` are
synthetic/noop examples and are not production-ready.

Production free-form PII recognition, provider privacy boundaries, fallback,
offset contracts, and held-out span evaluation are documented in
[docs/pii-ner.md](docs/pii-ner.md). `GET /api/pii/providers` is operator-only.

With `AUTH_MODE=off`, development retains the compatibility headers
`X-Application-Id`, `X-Tenant-Id`, `X-User-Id`, and `X-Target-Provider`. With
`AUTH_MODE=jwt`, those headers are ignored and stripped; tenant, application,
user, roles, and provider metadata come only from verified JWT claims. JWT
defaults are `tenant_id`, `azp`, `sub`, `roles`, and `provider` respectively.
LLM POST routes and `/v1/models` require `aegis.invoke` or `aegis.operator`;
MCP tool routes require `aegis.tools.invoke` or `aegis.operator`; the
dashboard, protection stats, MCP status/audit/metrics, and metrics require
`aegis.operator`.

Direct `AUTH_MODE=mtls` requires `INBOUND_MTLS_MODE=require`; the verified
client certificate supplies subject/application identity and headers cannot
override it. Development may use HTTP dependencies for local mocks; the
narrow `PLAINTEXT_DEPENDENCY_DEVELOPMENT_WAIVER=true` flag is documented as a
local-only contract and is rejected by the production profile.

Rate and concurrency controls are process-local and keyed by verified
tenant/application in JWT mode. Development uses application plus remote
address as a compatibility fallback. Multiple gateway instances require an
external/distributed limiter for global enforcement; that is deferred.

## Streaming security

`stream:true` changes only response transport: the request is still normalized,
detected, policy-evaluated, and transformed before upstream forwarding. Known
OpenAI Chat/Responses, Anthropic Messages, and generic SSE deltas are parsed
incrementally. A bounded rolling holdback protects secrets and PII split over
events; BLOCK/REVIEW closes with a sanitized terminal error, while
REDACT/TOKENIZE use the established placeholders and vault behavior. See
[operations.md](docs/operations.md#streaming) for provider coverage,
limitations, and production configuration.

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
internal/streaming/    bounded SSE parser and provider delta extraction
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
`active_laya_evaluations`. Streaming also exposes bounded
`stream_actions_total`, `stream_bytes_inspected_total`, and
`stream_events_inspected_total`; runtime metrics have no tenant/application
labels.

P0.5 additionally exposes bounded `semantic_calibration_artifact_info`,
`semantic_rejected_evidence_total`, schema/checkpoint mismatch, missing
decision, and reason-labelled semantic fallback metrics. Readiness exposes
only semantic state and safe artifact identifiers; it never exposes endpoint
credentials or artifact content.
P1.1 adds bounded `route_selected_total`, `route_failover_total`, and
`route_health` metrics. `/api/protection-stats` reports applied local/cloud
counts, and operator-only `GET /api/routes` reports sanitized capabilities,
health, breakers, and model mappings.
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
passthrough with audit/metrics coverage. Streaming requests are inspected and
request policy is enforced before forwarding. Streaming responses are
statefully inspected, transformed, or terminated using bounded SSE controls.
They remain subject to admission, prompt/response budgets, upstream timeouts,
and `MAX_STREAM_DURATION`.
# Signed policy distribution

P1.5 adds versioned Ed25519-signed policy bundles, durable anti-replay state,
atomic policy/question/threshold activation, deterministic canaries, and
operator-authorized rollback. See [docs/policy-bundles.md](docs/policy-bundles.md),
the [runbook](docs/policy-distribution-runbook.md), and the
[control-plane contract](docs/control-plane-contract.md).
