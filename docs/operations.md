# Operations Guide — Laya LLM Security Gateway

## Release evidence and promotion gate

Run `make verify-release` from a clean checkout before promotion. The command
writes only to the ignored `build/release/` directory and produces an evidence
manifest with command lines, pinned tool versions, report hashes, and explicit
pass/fail/block reasons. A required skipped gate is a release failure; a
scanner database outage is never recorded as a vulnerability pass. Attach the
manifest, checksums, reproducibility report, SBOM, conformance report, and
image-policy report to the release record. Artifact signing is optional until a
real keyless identity or managed signing key is available; never substitute a
synthetic signature.

## Running

```bash
docker compose up --build      # gateway :8080, mock upstream :9090, redis :6379, prometheus :9091
```

Native: see README quick start. All configuration is environment-based
(`.env.example` documents every variable).

## Durable audit and SIEM

P1.6 uses a local framed WAL as the audit durability boundary. Configure
`AUDIT_WAL_DIR`, segment/quota/retention limits, `AUDIT_FSYNC`, and production
file-backed HMAC/encryption keys. Set `AUDIT_SIEM_URL` only to an HTTPS webhook;
the exporter supports mTLS, bounded responses, retries, `Retry-After`, stable
event IDs, restart-safe checkpoints, and a mode-0600 dead-letter directory.
The gateway exposes only metadata at operator-role `/api/audit/status` and
`/api/audit/verify`. It is explicitly at-least-once and never exactly-once.
Use [audit.md](audit.md) for backup, restore, capacity, rotation, repair, and
incident procedures. Start the integration receiver with
`docker compose --profile audit-siem up --build fake-siem`.

## Deployment profiles and secure production

`DEPLOYMENT_PROFILE` is `development` by default. Development keeps the
convenient `SECURITY_MODE=off` and may use the in-memory vault. The shadow
profile requires `SECURITY_MODE=shadow` and is available locally with:

```bash
docker compose -f docker-compose.yml -f docker-compose.shadow.yml up --build
```

Production requires `DEPLOYMENT_PROFILE=production`, `SECURITY_MODE=enforce`,
and `AUTH_MODE=jwt` or direct `AUTH_MODE=mtls`. Startup fails before the
listener opens unless it has a certificate/key or the explicit
`TLS_TERMINATED_BY_TRUSTED_EDGE=true` contract. Service links must use
verified `https://` and `rediss://`; production rejects plaintext links and
inline secret values. Use mounted `*_FILE` values for credentials, JWT keys,
telemetry keys, and vault keys; prefer the versioned
`TOKEN_VAULT_KEYRING_FILE`. Startup fails before the listener opens unless all
of the following are present and valid: a file-backed vault key, a Redis
`TOKEN_VAULT_REDIS_URL`, telemetry key file, `UPSTREAM_REGISTRY_FILE`, and
the reviewed policy and question files. If semantic enforcement is requested,
the threshold artifact is additionally required to be readable, promoted, and
strictly provenance-valid. Deterministic-only production may set
`SECURITY_SEMANTIC_ENFORCE=false` and reports semantic `disabled`. Known
mock-upstream hostnames are rejected in production. Inject secret files at deploy time;
never commit a populated `.env.production` or compose file. Use
`.env.production.example` and `docker-compose.production.example.yml` as
placeholder-only references. The registry replaces the single-upstream
production contract; see [routing.md](routing.md) for health, explicit
fallback, force-local isolation, reload, and `/api/routes` operations.

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

### Multimodal/document DLP

Production attachment DLP uses the private HTTPS extractor adapter with
`DLP_ATTACHMENT_ALLOWED_HOSTS`, explicit private-host policy, CA material, and
mTLS client certificate/key files. Keep byte, count, page, expansion, text,
timeout, and redirect limits bounded. `/ready` is not ready when production
attachment DLP is disabled or extractor TLS material is unavailable.

The builtin adapter and `cmd/fakeextractor` prove contracts only. Before
promotion, validate the real OCR/document engine behind the private adapter,
issue and rotate its PKI, test DNS/redirect policy from the gateway network,
and run a reviewed sensitive-data calibration set. Never log media URLs with
credentials, extracted text, raw bytes, or base64 bodies.

`MAX_PROMPT_CHARS` is measured over normalized text parts before scanners or
upstream forwarding and returns `413`. Non-stream responses are bounded by
`MAX_RESPONSE_BYTES` before any bytes are written. Streaming requests are
inspected and transformed before forwarding. SSE responses are parsed with a
bounded event limit and a rolling holdback; protected text/tool arguments are
never released until the window is safe. `MAX_STREAM_DURATION` cancels the
upstream request and client disconnects propagate to the upstream context.

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

P1.7 adds operator-only `/api/dashboard/v2/overview`, `/timeseries`,
`/breakdown`, and `/alerts`. The browser uses the existing bearer workflow or
mTLS; production browser deployments should provide a same-origin
reverse-proxy/session integration rather than placing a JWT in browser storage
or a URL. The dashboard is read-only and links only to sanitized status views.

`AUTH_MODE=off` is a development-only compatibility mode. The shadow compose
example sets `ALLOW_UNAUTHENTICATED_SHADOW=true` only because it targets the
local mock upstream; this waiver leaves caller identity spoofable and must not
be used with real traffic. Production requires an asymmetric public key and
rejects HS256. Mount the public key at deploy time; never commit private keys
or JWTs.

### TLS, mTLS, and rotation

The shared transport enforces TLS 1.2 or newer, uses the system trust store
plus an optional custom CA bundle, verifies hostnames, and never enables
`InsecureSkipVerify`. Client and listener certificate files are polled at the
bounded `TLS_RELOAD_INTERVAL`. Replacements are loaded atomically; malformed
files retain the last-known-good value and increment
`secure_material_reload_failures_total`. Production readiness turns negative
after a failed reload until a valid replacement is observed.

For direct mTLS, set `INBOUND_MTLS_MODE=require` and mount
`INBOUND_TLS_CLIENT_CA_FILE`. A verified client certificate supplies the
principal subject/application identity; inbound identity headers are removed
and cannot spoof it. `AUTH_MODE=mtls` grants the standard invoke role to a
verified certificate. The trusted-edge contract terminates TLS before the
gateway and cannot be combined with direct mTLS.

Rotation procedure:

1. Write new certificate, key, CA, credential, JWT key, or keyring material to
   a new file and atomically replace the mounted path. Keep old material
   available until the reload generation is visible in `/ready`.
2. Confirm `generation` and `last_reload_success` changed, then exercise a new
   connection/request against the dependency. Existing in-flight requests
   continue on their established connection.
3. For vault rotation, add the new active key while retaining every previous
   decrypt key. New envelopes record the opaque active key ID. The default
   policy rejects key removal; only after all records expire may an operator
   use `TOKEN_VAULT_ALLOW_KEY_REMOVAL=true` for a controlled change, then roll
   it back.

Rollback is an atomic replacement using the prior known-good file. A malformed
replacement keeps the old material, marks production readiness not ready, and
raises the reload-failure metric. Never print file contents or credentials.

## Modes (FR-018)

- `SECURITY_MODE=off` — pure proxy, no inspection, no audit.
- `SECURITY_MODE=shadow` — full pipeline runs, `predicted_action` audited,
  traffic unchanged. Use this first on real traffic (rollout stage 1).
- `SECURITY_MODE=enforce` — deterministic policy acts. Semantic rules act
  ONLY when `SECURITY_SEMANTIC_ENFORCE=true` AND a calibrated threshold
  artifact is explicitly promoted, all required decisions are present, and
  provider/schema/checkpoint bindings match (rollout stage 3).

## Readiness & health

- `GET /health` — liveness.
- `GET /ready` — returns the compatible `status` field plus
  `deployment_profile`, `security_mode`, and sanitized dependency states. It
  also returns `semantic.status` (`disabled`, `shadow`, `ready`, or `unready`),
  provider, schema version, threshold policy id/version, checkpoint id, and
  calibration timestamp. It checks upstream reachability, policy loaded,
  question schema loaded, token store (Redis ping when configured), and
  laya-serve (when `LAYA_URL` is configured). `secure_material` contains only
  loaded state, generation, reload timestamps, failure count, and certificate
  expiry. It never returns credentials, endpoint URLs, auth configuration
  values, key IDs, or inspected content. Non-200 →
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

P1.4 adds `evasion_events_total{type,encoding_depth,action,budget_rejected}`.
Labels are bounded evasion classes only; canonical, decoded, and raw values are
never metrics or audit fields. Budget rejection in the production profile is
fail-closed and emits only the sanitized `EVASION_REJECTED` reason.

Streaming adds `stream_actions_total{direction,endpoint_family,predicted_action,applied_action,mode}`,
`stream_bytes_inspected_total{direction,endpoint_family}`, and
`stream_events_inspected_total{direction,endpoint_family}`. Labels use the
fixed endpoint families `openai-chat`, `openai-responses`, `anthropic`, and
`generic`; raw chunks never enter metrics or audit events. Shadow mode records
the predicted action and `applied_action=ALLOW`.

Alerts worth wiring: `fallback_total` spikes (Laya instability),
`laya_errors_total` rate, p95 `gateway_security_latency_ms` > 25 ms,
`shadow_disagreements_total` growth rate (tuning signal).
P0.5 adds bounded `semantic_calibration_artifact_info`,
`semantic_rejected_evidence_total`, schema/checkpoint mismatch counters,
`semantic_missing_decisions_total`, and reason-labelled
`semantic_fallback_total`.
P0.7 adds `secure_material_reload_failures_total` and
`secure_certificate_expiring_total`; alert on any production reload failure
and certificates inside the 30-day expiry horizon.

## Audit events

The versioned event contains event/request IDs, UTC time, W3C trace/span
correlation, bounded verified principals, policy/routing/tool IDs, counts,
stable reason IDs, sanitized Laya evidence, fixed-shape latencies, and frame
integrity metadata. It contains no raw content, secrets, authorization
headers, token originals, decoded payloads, or stack traces. Latency is split
honestly: `latency_ms.deterministic` excludes the semantic provider,
`latency_ms.laya` is present only when it ran, and
`latency_ms.total_security` covers the boundary crossing. The WAL is the
durable source; stdout is only a development mirror and SIEM delivery is
at-least-once.

## Policy & thresholds

- `POLICY_FILE` (default `policies/enterprise-default.yaml`) — invalid
  policy fails startup.
- `GET /api/effective-policy` — operator-only sanitized policy identity and
  effective rule summary. It never returns YAML values, credentials, request
  content, or finding hashes.
- `THRESHOLDS_FILE` (default `policies/thresholds-security-v1.yaml`) —
  required for semantic enforcement; `evaluated: true` records are the
  enforcement permission slip (INV-010).
- `QUESTIONS_FILE` (default `questions/security-v1.yaml`) — question wording
  is versioned code; changes require a re-run of evals (spec §17).

### Evasion policy and limitations

The `evasion` policy block controls enabled transforms, decode depth/work,
decoded expansion ratio, JSON depth/node/string limits, budget action,
per-evasion actions, and stable allowlist IDs. Keep the production transform
set small. A clean same-part NFKC/control/confusable projection can be
redacted or tokenized using its source span; decoded, structured-escaped, and
cross-message findings cannot be safely rewritten and therefore use the
configured fail-closed action. The one-window streaming holdback is reused for
split chunks. Operators should validate local/balanced changes against
`evals/datasets/evasion-p1.4.jsonl` and the report in
`evals/reports/evasion-p1.4.md` before enforcement.

### P0.5 calibration gate

Threshold artifacts bind the question schema id/version/hash, held-out dataset
id/version/hash, provider, checkpoint/model revision, RFC3339 calibration and
evaluation timestamps, bounded per-language/risk sample counts and metrics,
tool version, and explicit `evaluated`/`promoted` state. The gateway rejects
tampered hashes, duplicate or missing question/language slices, unknown
questions, missing decisions, schema/checkpoint mismatches, and invalid
confidence values. High-risk semantic evidence errors use the strict policy's
BLOCK fallback; direction/provider-specific alternatives belong in the policy
fallback matrix.

The workflow is intentionally explicit:

```bash
go run ./cmd/evaltool -action evaluate -provider laya -url http://127.0.0.1:8300 \
  -baseline /tmp/semantic-eval.json -report /tmp/semantic-eval.md
go run ./cmd/evaltool -action calibrate -provider laya -url http://127.0.0.1:8300 \
  -output /tmp/thresholds-candidate.yaml
go run ./cmd/evaltool -action verify -provider laya -url http://127.0.0.1:8300 \
  -artifact /tmp/thresholds-candidate.yaml
go run ./cmd/evaltool -action promote -provider laya -url http://127.0.0.1:8300 \
  -artifact /tmp/thresholds-candidate.yaml -output /tmp/thresholds-reviewed.yaml
```

`promote` only writes the reviewed artifact; it does not change environment
flags, copy files into the repository, push, or merge. The committed
`policies/thresholds-security-v1.yaml` and
`evals/reports/security-v1-synthetic-non-promoted.yaml` are synthetic/noop
examples and must never be promoted.

### Laya deployment contract

Laya is an operator-provided private service, not an image or credential
owned by this repository. Production Compose requires `LAYA_IMAGE` from the
operator and uses an optional `semantic` profile; the image value is never
hard-coded. Put the gateway and Laya on a private internal network, expose
only Laya's health/evaluation port to the gateway, and do not publish it to
the host or internet. Configure `LAYA_TIMEOUT` and `MAX_CONCURRENT_LAYA` as
bounded latency/concurrency controls. CI uses only the in-repository
synthetic `cmd/fakelaya` HTTP provider and it is not a production calibration
source.

### Secret handling: hard mask vs block

`secrets.<SUBTYPE>.action` accepts `redact` (hard mask) or `block`.
`enterprise-default.yaml` (version 7) declares high-risk secret subtypes as
`block`, with lower-risk secret subtypes using `redact` and a declarative
high-confidence escalation:

- **`redact` (hard mask)** — the matched span is replaced with
  `[REDACTED:SUBTYPE]` and the request/response/tool call proceeds; the raw
  value never leaves the gateway and is not recoverable (no vault entry, no
  re-identification). Applies in every direction: request, response
  (AS-005), tool-call arguments (UC-006), and tool results (UC-007).
  Laya is never invoked on a secret finding (SEC-002).
- **`block`** — the whole request/response is rejected with
  `security_policy_violation` / `SECRET_DETECTED`. Set per-subtype when a
  category is too sensitive to forward even masked.

See [policy-authoring.md](policy-authoring.md) for the v7 migration contract,
reviewed profiles, and `policytool` examples.

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
(`SECURITY_SEMANTIC_ENFORCE=true` only after a complete promoted artifact;
canary scope is controlled by policy/routing),
6. expand only after measured review. Regression CI fails promotion on
tolerance violations (`evaltool -compare`).

## Streaming

The production streaming guarantee covers known deterministic secret/PII
detectors when a candidate is no longer than the configured holdback. The
derived operational minimum is `STREAM_INSPECTION_WINDOW=4096` bytes: it
covers the structured credential and PII candidates normally split across
provider deltas while keeping memory and first-token delay bounded. Production
startup rejects smaller values. Candidates longer than the configured window
are outside the guarantee; the bounded queue still fails closed when its byte
budget is exhausted.
`MAX_SSE_EVENT_BYTES` defaults to 64 KiB, `MAX_BUFFERED_STREAM_BYTES` to 1 MiB,
and `STREAM_FLUSH_INTERVAL` to 25 ms. The parser supports comments,
keepalives, multiline `data:` fields, and provider `[DONE]` markers.

OpenAI Chat Completions inspect `choices[].delta.content` and tool-call
argument deltas. OpenAI Responses inspect output-text and function/tool
argument deltas. Anthropic Messages inspect `content_block_delta` text and
`partial_json`; generic SSE accepts known JSON text/content/argument fields
or plain text conservatively. BLOCK/REVIEW sends a sanitized provider-style
terminal error and closes the stream. REDACT/TOKENIZE preserve SSE framing and
use the same placeholders/vault semantics as buffered responses.

The holdback adds up to one inspection window of latency for small streams;
providers should send normal keepalive and terminal events. Malformed,
oversized, budget-exhausted, or timed-out streams fail closed in production.
Development can explicitly set `STREAM_FAIL_CLOSED=false` for compatibility,
but that setting is not appropriate for production traffic.

The checked-in parser benchmark (`go test ./internal/streaming -run '^$' -bench
BenchmarkParser -benchmem -count=1`) measured 206,493 ns/op and 87,328 B/op
for a 1,632-byte, 32-event OpenAI-shaped input on the verification host.
Treat this as a baseline; production capacity planning must include detector and
policy latency in addition to framing overhead.

## MCP operations

Development compose includes a fake MCP server for smoke testing. Configure
`MCP_REGISTRY_FILE` and, when needed, `MCP_CREDENTIALS_FILE`; do not put
secrets in registry URLs or YAML values. Use the operator-only MCP endpoints
to verify enabled state, capabilities, bounded action counts, and sanitized
audit events. A registry edit that fails validation remains on the prior
last-known-good snapshot and increments secure-material reload failure state.
