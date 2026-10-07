# Operations Guide — Laya LLM Security Gateway

## Running

```bash
docker compose up --build      # gateway :8080, mock upstream :9090, redis :6379, prometheus :9091
```

Native: see README quick start. All configuration is environment-based
(`.env.example` documents every variable).

## Deployment profiles and secure production

`DEPLOYMENT_PROFILE` is `development` by default. Development keeps the
convenient `SECURITY_MODE=off` and may use the in-memory vault. The shadow
profile requires `SECURITY_MODE=shadow` and is available locally with:

```bash
docker compose -f docker-compose.yml -f docker-compose.shadow.yml up --build
```

Production requires `DEPLOYMENT_PROFILE=production`, `SECURITY_MODE=enforce`,
and `AUTH_MODE=jwt`. Startup fails before the listener opens unless all of
the following are present and valid: a 64-hex-character `TOKEN_VAULT_KEY`, a
Redis `TOKEN_VAULT_REDIS_URL`, `TELEMETRY_HMAC_KEY`, `UPSTREAM_BASE_URL`, and
the reviewed policy, question, and threshold files. Known mock-upstream
hostnames are rejected in production. Inject secret values at deploy time;
never commit a populated `.env.production` or compose file. Use
`.env.production.example` and `docker-compose.production.example.yml` as
placeholder-only references.

The production image contains the gateway binary, embedded dashboard, and
versioned policy/question/threshold assets. It runs as a non-root user and its
container healthcheck calls `/health`.

### Runtime resilience and abuse controls

Admission runs after authentication. JWT deployments are limited by verified
tenant/application; development uses application plus remote address. The
token bucket (`REQUESTS_PER_SECOND`, `RATE_BURST`) and per-identity
concurrency semaphore (`MAX_CONCURRENT_REQUESTS`) return sanitized
OpenAI-compatible `429` responses with `Retry-After`. Limiter keys are capped
and evicted using `LIMITER_MAX_KEYS` and `LIMITER_KEY_IDLE_TIMEOUT`.
These limits are process-local; multi-instance global enforcement requires an
external/distributed limiter and is deferred.

`MAX_PROMPT_CHARS` is measured over normalized text parts before scanners or
upstream forwarding and returns `413`. Non-stream responses are bounded by
`MAX_RESPONSE_BYTES` before any bytes are written. Streams remain pass-through,
but their context is cancelled at `MAX_STREAM_DURATION` and their body is
capped. Streamed content inspection is not part of this milestone.

Upstream connections use explicit dial, TLS, response-header, overall request,
idle-connection, and pool bounds. Transport failures are sanitized as `502`,
timeouts as `504`, and an open upstream breaker as `503`; POST requests are
never retried. `GET /v1/models` is also no-retry. `/ready` reports the
upstream dependency as not ready while its breaker is open.

### Authenticated ingress and RBAC

JWT mode accepts bearer tokens signed with RS256 (RSA PEM) or ES256 (P-256 EC
PEM). The gateway verifies the signature, algorithm, expiry, not-before,
issuer, and audience, then retains only configured identity claims. It never
logs the token or raw claims. `aegis.invoke` or `aegis.operator` is required
for LLM POST routes and `/v1/models`; `aegis.operator` is required for
`/dashboard`, `/api/protection-stats`, and `/metrics`.

`AUTH_MODE=off` is a development-only compatibility mode. The shadow compose
example sets `ALLOW_UNAUTHENTICATED_SHADOW=true` only because it targets the
local mock upstream; this waiver leaves caller identity spoofable and must not
be used with real traffic. Production requires an asymmetric public key and
rejects HS256. Mount the public key at deploy time; never commit private keys
or JWTs.

## Modes (FR-018)

- `SECURITY_MODE=off` — pure proxy, no inspection, no audit.
- `SECURITY_MODE=shadow` — full pipeline runs, `predicted_action` audited,
  traffic unchanged. Use this first on real traffic (rollout stage 1).
- `SECURITY_MODE=enforce` — deterministic policy acts. Semantic rules act
  ONLY when `SECURITY_SEMANTIC_ENFORCE=true` AND a calibrated threshold
  record (evaluated: true) matches the traffic slice (rollout stage 3).

## Readiness & health

- `GET /health` — liveness.
- `GET /ready` — returns the compatible `status` field plus
  `deployment_profile`, `security_mode`, and sanitized dependency states. It
  checks upstream reachability, policy loaded, question schema loaded, token
  store (Redis ping when configured), and laya-serve (when `LAYA_URL` is
  configured). It never returns credentials, auth configuration values, or
  inspected content. Non-200 →
  not ready.

## Metrics (spec §15)

`GET /metrics` (Prometheus format): `security_requests_total{action,mode}`,
`findings_total{category,subtype}`, `laya_calls_total`, `laya_errors_total`,
`laya_latency_ms`, `scanner_latency_ms`, `gateway_security_latency_ms`,
`shadow_disagreements_total`, `fallback_total`, `transformations_total{action}`.

Runtime protection metrics also include `rate_limited_total`,
`concurrency_rejected_total`, `prompt_budget_rejected_total`,
`response_too_large_total`, `upstream_timeout_total`, `breaker_open_total`,
`active_requests`, and `active_laya_evaluations`. They have no tenant or
application labels. Alert on sustained limiter rejection, response-budget
rejections, upstream timeouts, or an open breaker.

Alerts worth wiring: `fallback_total` spikes (Laya instability),
`laya_errors_total` rate, p95 `gateway_security_latency_ms` > 25 ms,
`shadow_disagreements_total` growth rate (tuning signal).

## Audit events

One JSON object per line on stdout: request_id, direction, application,
policy version, mode, action, finding types (never raw content), latencies,
and sanitized Laya evidence (checkpoint, question schema, confidences).
Latency is split honestly: `latency_ms.deterministic` excludes the semantic
provider, `latency_ms.laya` is present only when the provider actually ran,
and `latency_ms.total_security` covers the whole boundary crossing
(architecture §15).
Ship stdout to the log platform of choice; keep the raw-content evaluation
path (if ever enabled) separately governed (PRIV-004).

## Policy & thresholds

- `POLICY_FILE` (default `policies/enterprise-default.yaml`) — invalid
  policy fails startup.
- `THRESHOLDS_FILE` (default `policies/thresholds-security-v1.yaml`) —
  required for semantic enforcement; `evaluated: true` records are the
  enforcement permission slip (INV-010).
- `QUESTIONS_FILE` (default `questions/security-v1.yaml`) — question wording
  is versioned code; changes require a re-run of evals (spec §17).

### Secret handling: hard mask vs block

`secrets.<SUBTYPE>.action` accepts `redact` (hard mask) or `block`.
`enterprise-default.yaml` (version 7) ships `redact` for all secret subtypes:

- **`redact` (hard mask)** — the matched span is replaced with
  `[REDACTED:SUBTYPE]` and the request/response/tool call proceeds; the raw
  value never leaves the gateway and is not recoverable (no vault entry, no
  re-identification). Applies in every direction: request, response
  (AS-005), tool-call arguments (UC-006), and tool results (UC-007).
  Laya is never invoked on a secret finding (SEC-002).
- **`block`** — the whole request/response is rejected with
  `security_policy_violation` / `SECRET_DETECTED`. Set per-subtype when a
  category is too sensitive to forward even masked.

Note: when a REDACT decision covers a request, every detected span in it
(secrets and PII alike) is masked with `[REDACTED:…]` for that request —
per-subtype PII tokenization only applies when no secret rule fires.

## Token vault

- `TOKEN_VAULT_KEY` — 64 hex chars (32-byte AES-256 KEK). In production,
  inject via secret manager; the ephemeral dev default loses mappings on
  restart (logged as a warning).
- `TOKEN_VAULT_REDIS_URL` — persistent store; omit for in-memory (dev).
- `TOKEN_VAULT_TTL` — mapping lifetime (default 24h; PRIV-003).

## Rollout (architecture §18)

1. Offline evals (`cmd/evaltool`), 2. dev shadow, 3. UAT shadow, 4.
deterministic enforcement, 5. semantic canary on one calibrated slice
(`SECURITY_SEMANTIC_ENFORCE=true` + a single `evaluated: true` record),
6. expand only after measured review. Regression CI fails promotion on
tolerance violations (`evaltool -compare`).

## Streaming

Streaming requests bypass outbound scanning in this MVP stage and pass
through verbatim (documented behavior; architecture §13 plan: buffered
non-streaming enforce → streaming shadow → streaming enforce).
