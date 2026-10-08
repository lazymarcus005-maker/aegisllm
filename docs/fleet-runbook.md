# Fleet operations runbook

Provision real trust domains, CA/client certificates, signer policy, and
one-time bootstrap issuers outside this repository. Enroll only through
verified mTLS, then confirm the opaque ID and authority-derived tenant,
environment, and region. Publish a digest-only desired state after checking
approved policy/model/build/SBOM/release evidence. Start with shadow, then
canary and bounded waves; require explicit promotion approval.

Watch `/api/fleet/status`, `/ready`, bounded inventory/compliance projections,
low-cardinality metrics, and durable audit/SIEM. Control-plane outages must
not add request latency. Required state becomes fail-closed only after the
signed state's explicit offline grace; invalid, revoked, or expired state is
never silently accepted.

Use the opaque gateway detail view when investigating one gateway; do not
request or export prompts, documents, credentials, raw logs, embeddings, or
user identifiers. Remote actions are signed, revision-bound and expiring;
only the declarative allowlist is accepted, and each action is idempotently
audited.

Pause on readiness, conformance, provider-health, drift, quarantine, or
error-budget failure. Roll back only to a retained verified digest, record an
operator reason, and revoke identities whose certificate or scope is no
longer trusted. The fake Compose profile proves contracts only and must never
be promoted.
