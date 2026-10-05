# 03: Full policy engine precedence

**What to build:** The complete deterministic policy engine: all seven actions representable, the full precedence chain, provider-boundary rules (local vs cloud), and provably deterministic conflict resolution. From the user's perspective: policy authors can express "secrets block, PII tokenizes for cloud, local models allow" and the engine's answer to any conflict is fixed, testable, and versioned.

**Blocked by:** 02 (secret-block tracer supplies the minimal engine and policy schema).

**Status:** done

- [x] Precedence chain: explicit deny > secret block > tenant/application restriction > identity/role restriction > provider-boundary policy > PII transformation > semantic risk > default
- [x] All seven actions (ALLOW, BLOCK, REDACT, TOKENIZE, REVIEW, RESTRICT_TOOLS, FORCE_LOCAL_MODEL) representable in PolicyDecision; REVIEW maps to a safe fallback for now
- [x] Provider-boundary rules keyed on target.provider (cloud vs local), matching the example enterprise-default policy
- [x] Conflict determinism tests (secret BLOCK beats PII TOKENIZE; explicit deny beats everything); repeated evaluation of identical input yields an identical decision
- [x] PolicyDecision carries policy version; audit events include policy_version
- [x] Invalid or schema-violating policy fails startup/readiness with an actionable error
