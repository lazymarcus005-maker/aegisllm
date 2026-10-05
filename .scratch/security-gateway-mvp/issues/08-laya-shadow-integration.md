# 08: Laya decision integration (shadow only)

**What to build:** Laya joins the pipeline as a semantic evidence provider — in shadow only. The gateway asks the versioned security-v1 questions of a local laya-serve, normalizes the answers into DecisionEvidence, and audits them. From the user's perspective: a prompt-injection sample produces an audit event with checkpoint, question schema, decision ids and answer_confidence — while traffic behavior stays unchanged.

**Blocked by:** 02 (pipeline + audit + modes), 03 (semantic layer of the precedence chain).

**Status:** done

- [x] DecisionProvider interface with LayaDecisionProvider (HTTP against laya-serve), FakeDecisionProvider (tests), NoopDecisionProvider (bypass); Laya's raw response structures normalized at the adapter boundary (T-014)
- [x] questions/security-v1.yaml: six versioned questions (prompt_injection, system_prompt_extraction, credential_exfiltration, sensitive_data_intent, policy_bypass_intent, unsafe_tool_intent), each with id, version, decision type, question, allowed directions, risk class
- [x] laya-serve added to compose (multilingual routing for Thai/English/mixed, checkpoints preloaded, never publicly exposed); selected checkpoint/route recorded in sanitized audit (FR-008)
- [x] Evidence flows into policy evaluation as evidence only; no Laya output executes an action (FR-010, INV-002)
- [x] /ready includes Laya reachability when configured as required (FR-020)
- [x] UC-004 demoable in shadow: injection sample audited with decisions + confidences; enforcement unchanged
