# 09: Semantic inspection planner + Laya failure fallback

**What to build:** Laya is called only when it earns its latency: a SemanticInspectionPlanner decides which questions to ask per direction/target/findings/policy, skipping semantics when deterministic detection is conclusive — and detected secrets never reach Laya. When Laya is down or slow, risk-sensitive fallback applies instead of silent allow. From the user's perspective: clean fast-path requests don't pay Laya's latency, and pulling the Laya service out from under the gateway leaves high-risk traffic failing closed, not open.

**Blocked by:** 08 (Laya integration).

**Status:** ready-for-agent

- [ ] SemanticInspectionPlanner: inputs direction, application, target, deterministic findings, tool context, policy → question ids to ask or skip (T-016)
- [ ] Fast path honored: definitive deterministic block skips Laya (NFR-PERF-004); gateway-excluding-Laya latency measured (NFR-PERF-002)
- [ ] SEC-002: content with detected secrets is not sent to Laya when deterministic detection is sufficient
- [ ] Timeout, circuit breaker, and laya_calls_total / laya_errors_total / laya_latency metrics; fallback chosen by route risk — high-risk: block/review per policy; never catch-exception → ALLOW (AS-004, INV-008, NFR-AVAIL-003)
- [ ] Fallback behavior policy-controlled (NFR-AVAIL-002), exercised in integration tests with Laya stopped
