# Operations Guide — Laya LLM Security Gateway

## Running

```bash
docker compose up --build      # gateway :8080, mock upstream :9090, redis :6379, prometheus :9091
```

Native: see README quick start. All configuration is environment-based
(`.env.example` documents every variable).

## Modes (FR-018)

- `SECURITY_MODE=off` — pure proxy, no inspection, no audit.
- `SECURITY_MODE=shadow` — full pipeline runs, `predicted_action` audited,
  traffic unchanged. Use this first on real traffic (rollout stage 1).
- `SECURITY_MODE=enforce` — deterministic policy acts. Semantic rules act
  ONLY when `SECURITY_SEMANTIC_ENFORCE=true` AND a calibrated threshold
  record (evaluated: true) matches the traffic slice (rollout stage 3).

## Readiness & health

- `GET /health` — liveness.
- `GET /ready` — checks upstream reachability, policy loaded, question
  schema loaded, token store (Redis ping when configured), laya-serve
  (when `LAYA_URL` configured). Non-200 → not ready.

## Metrics (spec §15)

`GET /metrics` (Prometheus format): `security_requests_total{action,mode}`,
`findings_total{category,subtype}`, `laya_calls_total`, `laya_errors_total`,
`laya_latency_ms`, `scanner_latency_ms`, `gateway_security_latency_ms`,
`shadow_disagreements_total`, `fallback_total`, `transformations_total{action}`.

Alerts worth wiring: `fallback_total` spikes (Laya instability),
`laya_errors_total` rate, p95 `gateway_security_latency_ms` > 25 ms,
`shadow_disagreements_total` growth rate (tuning signal).

## Audit events

One JSON object per line on stdout: request_id, direction, application,
policy version, mode, action, finding types (never raw content), latencies,
and sanitized Laya evidence (checkpoint, question schema, confidences).
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
