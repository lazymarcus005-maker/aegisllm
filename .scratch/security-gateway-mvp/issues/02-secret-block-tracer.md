# 02: Secret-block tracer bullet

**What to build:** The first complete security path end to end: deterministic secret detection feeds a policy decision that BLOCKs the request before it reaches the upstream, with a sanitized audit trail and off/shadow/enforce modes. From the user's perspective: send a request containing a GitLab token and get the spec's policy-violation error instead of a model response; flip the gateway to shadow and the same request passes through while the audit records what would have happened.

**Blocked by:** 01 (scaffold + pass-through proxy).

**Status:** done

- [x] Detector framework: Detector.detect(envelope) → findings, DetectorRegistry, per-detector timing hook; each detector independently testable
- [x] Secret detectors for GitLab PAT, GitHub token, PEM private key, JWT, bearer token with positive and negative corpora; detected value never stored or logged
- [x] Policy-as-code YAML with id, version, owner, effective date, rules; invalid policy fails startup and readiness
- [x] PolicyEngine evaluates findings → PolicyDecision deterministically; precedence at minimum: secret block > default
- [x] Enforce mode returns the spec §9 security_policy_violation error (code SECRET_DETECTED, request_id, no secret echoed) and makes zero upstream calls and zero Laya calls where the deterministic block is conclusive (AS-001)
- [x] Shadow mode: findings computed, policy evaluated, predicted_action + mode=shadow audited, production traffic unmodified (AS-006)
- [x] Sanitized audit event carries finding types and value hashes only; tests inject passwords/PATs/JWTs/citizen IDs/phones and assert they never appear in serialized audit output or logs
