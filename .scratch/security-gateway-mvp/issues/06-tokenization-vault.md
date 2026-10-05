# 06: Tokenization + encrypted token vault

**What to build:** Stable pseudonymization: selected PII spans become stable `<TYPE_001>` placeholders within a request/session scope, with mappings held in an encrypted, TTL'd vault that neither Laya nor the target LLM can reach. From the user's perspective: AS-002 — the upstream model sees `<PERSON_001>` and `<PHONE_001>`, and the same real value maps to the same placeholder within scope.

**Blocked by:** 05 (span detection + transformation planner).

**Status:** done

- [x] Tokenizer emits stable placeholders per configured scope; no original value encoded in the placeholder
- [x] Token vault (Redis MVP) stores namespace, ciphertext (envelope encryption), type, created/expires timestamps, authorization metadata; TTL configurable (PRIV-003)
- [x] No raw value in key names, logs, or audit; vault isolated from Laya and the target LLM (INV-007)
- [x] TOKENIZE action end-to-end for cloud targets per policy; same value → same token within scope, different scopes → different tokens
- [x] Explicitly authorized re-identification path exists as a controlled interface (used by ticket 07), least-privilege by construction
