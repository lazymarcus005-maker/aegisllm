# 07: Outbound response protection + controlled re-identification

**What to build:** The return path is protected: upstream responses are normalized, scanned, and policy-filtered before the client sees them, and placeholders the model echoes back are re-identified only for authorized callers in the matching namespace. From the user's perspective: a model that tries to leak a token-like secret gets redacted/blocked at the gateway (AS-005), and a client that legitimately tokenized PII gets the real values back.

**Blocked by:** 06 (tokenization + vault).

**Status:** ready-for-agent

- [ ] Upstream response normalized into InspectionEnvelope(direction=RESPONSE) for the non-streaming path
- [ ] Outbound pipeline runs deterministic scan + span scan + semantic check where configured + policy; allow/redact/block implemented (FR-015)
- [ ] AS-005: a model-emitted secret never reaches the client under block/redact policy
- [ ] Re-identification requires all of: authorized identity, response policy allows, namespace matches issued tokens; blind replacement of any `<TYPE_001>`-looking string coming from model output is rejected and tested (T-023)
- [ ] Streaming explicitly out of scope for this ticket: documented behavior per the handoff sequence (non-streaming enforce first, streaming shadow later)
