# Roadmap implementation status

This status follows the implementation order, workstreams, milestones, and
rollout sequence in `docs/implement.handoff.md` (the repository has no
separate feature-roadmap file).

## P0 — production foundation

- [x] P0.1 Secure production deployment profile: typed development/shadow/production profiles, fail-fast production validation, self-contained non-root image, readiness evidence, and CI container smoke gate.
- [x] P0.2 Authenticated ingress, verified identity claims, and operator RBAC.
- [x] P0.3 PII transformation, encrypted vault, outbound protection hardening, and stateful streaming content inspection.
- [x] P0.4 Runtime resilience, rate limits, cost controls, bounded upstream transport, and stream lifetime protection.
- [x] P0.6 Declarative effective policy contract, reviewed profiles, shared explanations, sanitized simulator, and operator policy summary endpoint.
- [x] P0.7 Encrypted gateway/dependency links, verified TLS/mTLS, file-backed secret and certificate rotation, reload-safe JWT/vault keyring rotation, sanitized readiness, and rotation smoke coverage.

## P1 — semantic and operational maturity

- [x] P1.1 Policy-aware local/cloud routing: strict registry, local-only force routing, model/capability constraints, health/breakers, explicit failover, atomic reload, sanitized route API/audit/metrics, and development compatibility.
- [x] P0.5 Fail-closed semantic calibration gate: typed enablement contract, provenance-bound threshold artifacts, runtime evidence binding, policy fallback matrix, sanitized readiness, bounded metrics, and explicit evaltool verify/promote workflow. Semantic enforcement remains disabled until a real Laya artifact is promoted.
- [x] P1.1-semantic Laya shadow integration and failure fallback; semantic enforcement is implemented but intentionally not production-enabled by the committed synthetic artifact.
- [x] P1.2 Tool/MCP inspection and restricted-tool enforcement: authenticated Streamable HTTP proxy, atomic registry reload, schema/stream bounds, session isolation, server-side credential brokering, sanitized operator surfaces, and fake-MCP integration coverage.
- [x] P1.3 Sanitized audit, metrics, evaluation datasets, and deterministic regression/promotion gates.
- [x] P1.3 production PII/NER span engine: exercised Presidio/Aegis adapters, strict registry, UTF-8/UTF-16 spans, bounded private routing, fail-closed policy, fake CI service, and held-out span evaluation.
- [x] P1.4 Evasion-resistant scanning: bounded NFKC/control/confusable projection, Base64/URL-safe/percent/JSON decoding, structured traversal, cross-message state, reversible spans, fail-closed unsafe transforms, policy controls, sanitized metrics/audit, and corpus/latency coverage.
- [x] P1.6 Durable audit, privacy-safe versioned events, CRC/HMAC/SHA-256 WAL with recovery/rotation/quota/keyring encryption, at-least-once HTTPS SIEM export with retry/DLQ, W3C trace correlation/allowlisted propagation, operator status/verify endpoints, audittool, fake SIEM profile, and lifecycle runbook.
- [x] P1.7 Security Operations Dashboard v2: operator-only versioned aggregate APIs, bounded process-local rolling telemetry, responsive embedded operations UI, freshness/reset semantics, sanitized alerts, CSP/security headers, and SLO/data semantics documentation.
- [x] P1.8 Provider conformance and compatibility lab: versioned OpenAI/Anthropic/generic profiles, deterministic fake-provider matrix, privacy-safe JSON/JUnit reports, compare mode, explicit fixtures, capability declarations/gates, and operator conformance summary.
- [x] P1.9 Session-scoped token vault and re-identification controls: verified session bindings, opaque MACed placeholders, scope/AAD authorization, Redis/memory atomic retrieval and revocation, bounded TTL/quota, key rotation, trusted delivery paths, privacy-safe status, and vaulttool operations.
- [x] P1.10 Release quality, performance, and supply-chain gates: one evidence-producing verification entrypoint, pinned Docker race/fuzz/static tooling, Go load/soak probe, robust benchmark lane, Compose E2E/chaos/restart checks, 24-case conformance validation, coverage/security/license/SBOM/image/reproducibility gates, and release checklist.

## P2 — expanded coverage

- [x] P2.1 Streaming inspection and enforcement (delivered early as P0.3).
- [x] P2.1 Production multimodal/document DLP boundary: bounded OpenAI,
  Anthropic, and generic attachment normalization; private extractor seam;
  fail-closed MIME/base64/archive/URL/SSRF/timeout limits; shared extracted
  text policy path; honest binary action semantics; readiness and audit-safe
  metadata. Evidence class: contract and fake-service integration only;
  real OCR/document engines, production PKI, and data calibration remain
  promotion dependencies. Evidence: `internal/attachment/attachment_test.go`,
  `internal/gateway/multimodal_test.go`, and
  `docs/multimodal-document-dlp.md`.
- [ ] P2.2 Credential brokering and deeper MCP/runtime integration.
- [ ] P2.3 Richer entity detection and multi-tenant vault namespaces (bounded cross-message detection moved into P1.4).

P0.1 is marked complete only after the repository acceptance commands and the
container smoke test pass on this branch.

P0.2 is marked complete after strict RS256/ES256 JWT validation, RBAC, proxy
credential isolation, full Go verification, Docker image build, and an
authenticated RS256 container smoke test pass on this branch.

Runtime resilience is marked complete after focused limiter, breaker, timeout,
response-budget, Laya-cancellation, stream-duration, full-suite, benchmark,
Docker, authenticated-smoke, and secret-scan verification pass on this branch.
P0.3 streaming enforcement is complete: JSON requests with `stream:true` use
the normal request pipeline, and OpenAI Chat/Responses, Anthropic Messages,
and generic SSE responses use bounded parsing plus a 4096-byte production
minimum rolling holdback. Production validation rejects smaller windows.

Verification note: the former wall-clock gateway p95 unit assertion is replaced
by the warm-up/multi-sample benchmark and load gate. The documented 25 ms
gateway security SLO remains a release criterion; shared-host measurements are
advisory and pinned CI is the blocking lane.
# P1.5 signed policy distribution

Implemented on `feature/production-readiness-roadmap`: deterministic bundle
format/tooling, trust rotation and validity checks, local/HTTPS sources with
ETag and bounded reads, atomic runtime snapshots, durable anti-replay, canary
shadow comparison, operator promotion/rollback endpoints, retention, and a
non-production fake control plane. Remaining deployment-specific work is
operator provisioning of real CA/client certificates and production signer
governance.
