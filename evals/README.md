# Evals

Labelled datasets, baselines, and reports for the security gateway.

- `datasets/` — versioned JSONL datasets (format defined by ticket 10)
- `baselines/` — frozen baseline artifacts per checkpoint/question schema
- `reports/` — dated evaluation reports

Rules (spec §16, handoff §11):

- Synthetic data only; never commit real PII or secrets.
- Security-critical slices emphasize false negatives.
- Threshold changes require a fresh evaluation report and regression comparison.
