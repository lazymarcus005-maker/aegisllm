# Threat Model — Laya LLM Security Gateway

Scope: the MVP gateway as implemented (tickets 01–13). Trust boundaries follow
`architecture.md` §5. Review status: reviewed during the MVP DoD sweep.

## Trust boundaries

- **TB-1 Client → Gateway**: fully untrusted. In protected deployments the
  gateway verifies a bearer JWT and derives identity only from selected claims;
  inbound identity and Authorization headers are stripped before proxying. The
  development-only `AUTH_MODE=off` mode retains trusted-header compatibility.
- **TB-2 Gateway → Laya**: local, non-internet-facing. Laya is a classifier,
  never an enforcement authority (INV-002).
- **TB-3 Gateway → LLM Gateway**: only policy-approved or transformed content.
- **TB-4 LLM Gateway → provider**: policy varies by provider class
  (cloud stricter than local).
- **TB-5 Tool runtime / MCP**: credentials live outside model context
  (INV-007); this gateway inspects intent and content only.

## Threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Secret leakage to LLM | deterministic secret detectors + policy BLOCK before forwarding (AS-001); bounded stateful outbound SSE scan with holdback blocks split model-emitted secrets (AS-005) | encoded/homoglyph evasions and candidates longer than the configured holdback remain limitations |
| Secret leakage to Laya | planner skips semantics on deterministic secret findings (SEC-002) | none deterministic-path |
| Secret leakage to logs | findings carry HMAC value hashes only; audit events are whitelisted-field structs; leak tests over audit + logs | operator-added logging must follow the same rule |
| PII leakage to cloud providers | PII/span detection + policy TOKENIZE/REDACT per provider (AS-002); outbound redaction (UC-008) | heuristic person-name spans are regex-based; NER adapter deferred |
| PII re-identification abuse | vault: envelope encryption, TTL, namespace isolation, issuance-time application authorization; model-invented placeholders never resolve (T-023) | vault compromise requires the master key (KEK) — external secret management required in production |
| Prompt injection / jailbreak | Laya semantic evidence + calibrated policy slices; deterministic fast path unaffected | pattern-based deterministic detection only for known phrases; semantic enforcement requires calibration evidence (INV-010) |
| System-prompt extraction | security-v1 question + semantic policy | same calibration gate |
| Credential exfiltration intent | security-v1 question on request and tool_call directions; policy block/restrict | classifier false negatives — eval corpus emphasizes FNR |
| Tool abuse | InspectToolCall / InspectToolResult reuse the full pipeline; RESTRICT_TOOLS strips tools physically (T-025) | full MCP proxy deferred |
| Policy bypass | policy-as-code with strict schema validation; corruption fails startup (fail closed) | policy repo compromise = config poisoning; protect with review + CI |
| Caller identity spoofing | RS256/ES256 JWT verification, strict algorithm/key matching, issuer/audience/time checks, and route RBAC; inbound identity headers are stripped | development/off mode and the explicit unauthenticated shadow waiver remain spoofable |
| Client credential forwarding | proxy forwards only content negotiation headers and applies upstream credentials from gateway configuration | a compromised gateway host can access configured upstream credentials |
| Laya outage | circuit breaker + risk-sensitive policy fallback; high-risk routes fail closed (AS-004, INV-008); never catch→ALLOW | availability impact on high-risk routes is deliberate (policy-controlled) |
| Classifier false negatives/positives | eval harness with FNR-emphasized slices; regression CI gates promotion (§17) | thresholds are only as good as the labelled data |
| Audit-log leakage | audit struct cannot carry raw content by construction (ticket 02 tests) | downstream log sinks must be access-controlled |
| Configuration poisoning | KnownFields-strict YAML loaders; validated declarative actions, thresholds, count rules, operator-only effective-policy summary, and versioned policy files | supply chain of those files — protect the repo and require policy review |
| Semantic calibration poisoning/tampering | SHA-256-bound question/dataset provenance, provider/checkpoint binding, strict slice coverage and explicit reviewed promotion | operators must protect reviewed artifacts and the real Laya image |
| Malformed semantic evidence | missing/extra decisions, unknown questions, schema/checkpoint mismatch, and non-finite/out-of-range confidence are rejected; fallback matrix is policy-controlled | high-risk availability impact is deliberate |
| Supply-chain dependency risk | small dependency surface: yaml.v3, go-redis, miniredis (test), prometheus client | pin versions in go.sum; review updates |
| Oversized request / DoS | MaxBytesReader → 413 before inspection; read-header timeout; Laya circuit breaker | volumetric DDoS protection belongs to the edge |
| Tenant/application abuse and cost amplification | verified-identity token bucket and concurrency semaphore, normalized prompt budget, bounded response/stream lifetime, global Laya semaphore, bounded key cleanup | process-local limits do not enforce a global budget across instances; distributed limiter is deferred |
| Upstream stall or connection exhaustion | dial/TLS/header/request/idle timeouts, bounded pool, response byte cap, no automatic POST retry, circuit breaker and sanitized readiness | provider-side overload and volumetric attacks still need edge controls |
| Unicode/encoding evasions | documented limitations (base64/homoglyphs); bounded rolling SSE state covers split structured candidates | arbitrary encodings and streams exceeding configured memory budgets fail closed rather than being scanned without bounds |
| Cross-tenant token collision | token namespace is per-request ID; vault keys carry namespace + token label | multi-tenant session namespaces are a V1.1 item |
| Model context carries tool credentials | out of scope for the gateway (TB-5) — credential broker is Phase 2 | deployment must route tool creds outside model context |

## Failure modes (architecture §16)

- Deterministic scanner unavailable → fail closed for protected routes.
- Laya unavailable → risk-sensitive fallback: high-risk routes take
  `fallback.laya_unavailable.high_risk` (BLOCK by default), others continue
  deterministic-only.
- Semantic enforcement cannot be enabled with the committed noop/synthetic
  artifact: startup requires a real reachable provider, promoted provenance,
  complete eligible slices, and passing criteria.
- Policy engine failure → fail closed (500 on pipeline error; BLOCK on
  unknown action).
- Audit sink failure → console sink; production deployments should buffer
  minimal sanitized events and alert.
- Streaming responses are inspected through bounded SSE parsing. Production
  requires a 4096-byte minimum holdback, 64 KiB default event limit, and 1 MiB
  default queued-byte budget. On BLOCK/REVIEW the upstream body is closed and
  the client receives only a sanitized error; shadow records a prediction but
  forwards the original event. A provider that emits malformed or oversized
  events is rejected in production.
