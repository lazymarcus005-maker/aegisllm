# 13: Metrics, hardening, and MVP definition-of-done sweep

**What to build:** The production-polish slice: the full observability surface, the adversarial test corpus, operational docs, and the final MVP DoD audit. From the user's perspective: the compose stack comes up complete, metrics answer "what did the gateway do and how fast", the threat model is written and reviewed, and every checklist item in spec §18 has evidence.

**Blocked by:** 11 (semantic enforcement), 12 (tool inspection).

**Status:** ready-for-agent

- [ ] /metrics exposes the spec §15 set including findings_total{category,subtype}, laya_calls_total / laya_errors_total / laya_latency_ms, scanner_latency_ms, gateway_security_latency_ms, shadow_disagreements_total, fallback_total
- [ ] Trace attributes per spec §15 (request_id, application, policy_version, mode, provider, model, laya_checkpoint, question_schema, action, finding_types) with no raw sensitive values
- [ ] Security test corpus: encoded/split secrets, Unicode homoglyphs, case variations, JSON and tool-argument nesting, oversized payloads, Laya outage, policy corruption (handoff §12)
- [ ] Golden request suite consolidated: representative requests with expected findings, policy action, transformed request
- [ ] docs/threat-model.md covering the handoff §14 checklist and reviewed; docs/operations.md written
- [ ] Full compose stack (gateway, laya, redis token store, mock upstream, prometheus optional); .env.example; README
- [ ] Repo-wide check: no raw secret appears in any test log; spec §18 MVP Definition of Done audited item by item with evidence links
