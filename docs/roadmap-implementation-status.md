# Roadmap implementation status

This status follows the implementation order, workstreams, milestones, and
rollout sequence in `docs/implement.handoff.md` (the repository has no
separate feature-roadmap file).

## P0 — production foundation

- [x] P0.1 Secure production deployment profile: typed development/shadow/production profiles, fail-fast production validation, self-contained non-root image, readiness evidence, and CI container smoke gate.
- [ ] P0.2 Deterministic inspection and policy enforcement hardening.
- [ ] P0.3 PII transformation, encrypted vault, and outbound protection hardening.

## P1 — semantic and operational maturity

- [ ] P1.1 Laya shadow integration, failure fallback, and calibrated semantic enforcement.
- [ ] P1.2 Tool/MCP inspection and restricted-tool enforcement.
- [ ] P1.3 Sanitized audit, metrics, evaluation datasets, and regression promotion gates.

## P2 — expanded coverage

- [ ] P2.1 Streaming inspection and enforcement.
- [ ] P2.2 Credential brokering and deeper MCP/runtime integration.
- [ ] P2.3 Stateful cross-message detection, richer entity detection, and multi-tenant vault namespaces.

P0.1 is marked complete only after the repository acceptance commands and the
container smoke test pass on this branch.

Verification note: the first full-suite run observed the existing deterministic
scan p95 target above 10 ms under host load; the isolated
`TestDeterministicScanLatencyTarget` rerun passed at 6.527 ms without changing
the threshold.
