# Signed policy bundles (P1.5)

The gateway can consume an immutable signed bundle from `POLICY_BUNDLE_PATH`/
`POLICY_BUNDLE_DIR` or poll a control plane with `POLICY_CONTROL_PLANE_URL`.
Remote distribution is HTTPS-only in the manager and production deployments
must configure `POLICY_TRUST_STORE_FILE`; an unsigned or unknown-key bundle is
never a valid fallback.

## Format

A bundle directory contains `manifest.json`, `signature.ed25519`,
`policy.yaml`, and optional `questions.yaml`, `thresholds.yaml`, and evaluation
artifacts. The manifest is canonical JSON (sorted object keys) and contains a
format version, bundle ID, monotonic sequence, artifact versions and SHA-256
hashes, validity timestamps, issuer/key ID, minimum gateway version, target
selectors, and evaluation artifact hashes. The Ed25519 signature covers the
canonical manifest, including every file hash. Private keys are signing-tool
inputs only and are never copied into a bundle.

`policytool bundle create` writes an unsigned deterministic directory;
`policytool bundle sign` reads an Ed25519 PKCS#8 PEM, raw hex/base64 key, or
stdin; `verify` requires a JSON/YAML trust store; and `inspect` prints only
sanitized manifest metadata and file names.

Trust stores support multiple key IDs with `not_before`, `expires`, and
`revoked`. Adding a new key before signing with it, then removing/revoking the
old key after fleet rotation, is the normal rotation sequence. Trust-store
reload is atomic at the file level and a last-known-good active bundle remains
in service after a failed fetch or verification.

## Runtime contract

The manager validates policy/question/threshold syntax and provenance,
minimum gateway version, target selectors, and artifact hashes before putting a
candidate into canary. It persists the highest accepted sequence and bundle
hash using fsync plus atomic rename. A lower sequence or conflicting replay is
rejected. Previous verified snapshots are retained in bounded memory for
operator rollback; rollback requires a signed, role-bound authorization and a
reason.

The pipeline swaps one immutable runtime snapshot containing policy, question
schema, and thresholds. Candidate evaluation is shadow-only and can never
change enforcement until the operator promotion API succeeds.
