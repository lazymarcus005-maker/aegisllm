# Evals

Labelled datasets, baselines, and reports for the security gateway.

- `datasets/` — versioned JSONL datasets (format defined by ticket 10)
- `baselines/` — frozen baseline artifacts per checkpoint/question schema
- `reports/` — dated evaluation reports
- `reports/calibration-report.schema.json` — machine-readable calibration report contract

Rules (spec §16, handoff §11):

- Synthetic data only; never commit real PII or secrets.
- Security-critical slices emphasize false negatives.
- Threshold changes require a fresh evaluation report and regression comparison.
- `go run ./cmd/evaltool -action calibrate -provider laya -url <operator-laya>`
  writes a non-promoted candidate; `-action verify` checks hashes, coverage,
  metrics, and configured FNR/FPR/sample criteria; `-action promote` writes the
  reviewed artifact only. The committed noop/synthetic example is never
  production-ready.
