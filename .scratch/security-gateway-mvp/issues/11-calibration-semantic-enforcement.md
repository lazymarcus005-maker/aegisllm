# 11: Calibration + bounded semantic enforcement + regression CI

**What to build:** Semantic rules go live — narrowly. Thresholds are fitted per question/language/risk slice on held-out data (never one hardcoded universal number), semantic policies enable in enforce mode only for evaluated slices, and CI fails when evaluations regress. From the user's perspective: AS-003 — a prompt-injection sample gets the policy action the calibrated rule predicts, and nobody can move a threshold without an evaluation report.

**Blocked by:** 09 (planner + fallback), 10 (datasets + baseline).

**Status:** done

- [x] Dev/calibration/held-out split; answer_confidence thresholds fitted per question, language slice, and risk class (REQ-CONF-002/003); no universal threshold in source (handoff §22)
- [x] Threshold records are policy-as-code with checkpoint, revision, question schema version, dataset version, calibration method, threshold, owner, effective date (architecture §7.4)
- [x] Bounded semantic enforcement: evaluated slices only (language, application, question schema, risk class, target provider) — rollout stage 3
- [x] AS-003 golden: policy action matches the configured calibrated rule for evaluated samples
- [x] Regression CI: reruns affected evals on checkpoint/question/normalizer/threshold changes; candidate promotion fails on tolerance regression (spec §17, T-032)
