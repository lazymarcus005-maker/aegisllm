# Semantic model lifecycle and drift runbook (P2.4)

This control plane manages signed semantic model metadata and references to
external threshold/calibration artifacts. It never stores model weights,
prompts, embeddings, labels, PII, secrets, or dataset content. Synthetic
Laya/model fixtures are contract evidence only and cannot promote in
production.

## Promotion checklist

1. Confirm the immutable model ID/version/digest, detector/task, API/runtime
   compatibility, owner, signed provenance digests, training window, expiry,
   signer/key ID, and threshold artifact ID/version/digest.
2. Verify the artifact with the current rotating trust store and confirm the
   signer is approved. Retain old keys until all live artifacts expire.
3. Validate schema, threshold coverage, evaluation provenance, calibration,
   and the existing fail-closed fallback matrix. A policy snapshot must bind
   a `promoted` model and the exact threshold digest.
4. Register, validate, shadow, and canary using a fresh expected revision and
   idempotency key. Cohorts derive from verified tenant/application identity;
   client cohort headers are ignored.
5. Compare bounded aggregate disagreement, latency, failure, and confusion
   metrics. Shadow/canary evidence never changes enforcement decisions.
6. Promote only after the canary window and evaluation gates pass, with an
   operator role and explicit confirmation. The gateway swaps the complete
   policy/question/model/threshold snapshot atomically.

## Drift response

The monitor accepts only pre-aggregated allowlisted buckets and trusted tenant
scopes. It uses configurable PSI, Jensen-Shannon, and KS distances, minimum
sample/label counts, confidence guardrails, fixed windows, sustained breach
counts, cooldown, and hysteresis. Low-volume or missing-label windows are
suppressed, not treated as healthy.

`warning` is informational; `freeze_promotion` blocks new promotion;
`pause_canary` stops candidate exposure; `rollback_champion` is optional and
requires policy authorization, a healthy retained target, sustained breach,
minimum samples, cooldown, and corroboration from at least two tenant scopes.
One tenant cannot cause fleet rollback. Optional quarantine still passes the
existing quarantine policy and audit gates.

Use `/api/semantic/status`, `/api/semantic/models`, `/api/semantic/history`,
and `/api/semantic/drift` with operator RBAC. Outputs are bounded projections.
Durable audit/SIEM records contain exact model and threshold references plus
actors/provenance, never request content.

Failure or invalidity of Laya, a model, a threshold pair, a rollback target,
the registry revision, or audit durability leaves production unready or uses
the existing policy fallback; it never silently enables semantic enforcement.

Evidence class: contract, deterministic fake, unit, race/fuzz, and gateway
integration tests. Real model quality, production distributions, signer
governance, external Laya connectivity, PKI, SIEM durability, and production
label quality remain promotion dependencies.
