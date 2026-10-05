# 05: PII span detection + REDACT for cloud targets

**What to build:** Span-oriented PII detection and the first content transformation: cloud-bound requests containing Thai PII get redacted before forwarding. From the user's perspective: "ลูกค้าชื่อ สมชาย ใจดี โทร 0812345678" sent toward a cloud model arrives upstream with PII removed, while the same text to a local model passes per policy.

**Blocked by:** 03 (PII-transformation layer of the precedence chain), 04 (PII detectors).

**Status:** ready-for-agent

- [ ] PiiSpanProvider interface with RegexSpanProvider and CompositeSpanProvider adapters; Laya explicitly excluded from this interface (FR-006)
- [ ] Exact spans produced for person names and addresses where regex recognizers exist (e.g. Thai honorific patterns); Presidio/NER adapter deferred, interface ready for it
- [ ] Transformation planner converts findings + spans into non-overlapping transformations with deterministic precedence: more specific detector > generic, longer validated span > shorter ambiguous, secret > PII
- [ ] PII transformation policy resolves per provider (cloud → redact, local → allow) through the policy engine, not ad-hoc code
- [ ] End-to-end REDACT: AS-002 variant — upstream receives redacted content; audit records finding types (TH_CITIZEN_ID, PHONE_NUMBER) with no raw values
