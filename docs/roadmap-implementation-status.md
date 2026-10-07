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

## P2 — expanded coverage

- [x] P2.1 Streaming inspection and enforcement (delivered early as P0.3).
- [ ] P2.2 Credential brokering and deeper MCP/runtime integration.
- [ ] P2.3 Stateful cross-message detection, richer entity detection, and multi-tenant vault namespaces.

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

Verification note: the first full-suite run observed the existing deterministic
scan p95 target above 10 ms under host load; the isolated
`TestDeterministicScanLatencyTarget` rerun passed at 6.527 ms without changing
the threshold.
