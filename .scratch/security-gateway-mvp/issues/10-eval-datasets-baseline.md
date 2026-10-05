# 10: Evaluation datasets + Laya baseline

**What to build:** The measurement foundation: a versioned JSONL dataset format, the minimum synthetic Thai/English/mixed corpus, and a first Laya baseline report — all synthetic, no real PII or secrets. From the user's perspective: evals/ contains reproducible artifacts that say how the current checkpoint + question schema performs per language and risk slice.

**Blocked by:** 08 (question schema + provider to evaluate against).

**Status:** done

- [x] evals/datasets/security-v1.jsonl format implemented: id, language, direction, risk, state, expected
- [x] Minimum corpus per handoff T-029: Thai clean 200 / English clean 200 / mixed clean 100; Thai + English prompt injection 150 each; system prompt extraction 150; credential exfiltration 150; policy bypass 100; unsafe tool intent 100 — synthetic data only
- [x] Deterministic detector metrics (TP/FP/FN, throughput, matching latency) produced from the same harness
- [x] Baseline artifacts: evals/baselines/security-v1-<checkpoint>.json and evals/reports/security-v1-<date>.md recording checkpoint/revision, dataset hash, question schema hash, language slices, threshold policy
- [x] Raw-content samples governed separately from production audit (PRIV-004)
