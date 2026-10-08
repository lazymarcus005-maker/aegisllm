# Automated incident quarantine runbook

Quarantine is a containment control, not evidence deletion. Signals are
server-derived and use only bounded reason codes plus digests. Prompts,
documents, credentials, tokens, tool arguments, and audit records remain
outside the quarantine state.

## Triage

1. Query `GET /api/quarantine` with an authenticated `aegis.operator`
   principal. The response is aggregate-only. Use the opaque ID from an
   approved operator workflow with `GET /api/quarantine/{id}`; do not search
   by tenant, prompt, resource ID, or attacker label.
2. Correlate the quarantine ID with durable audit/SIEM event IDs and the
   provider/RAG/MCP conformance and health records. The local memory store,
   fake Redis, fake SIEM, fake IdP, and fake RAG/MCP services are evidence for
   contract tests only, not production validation.
3. Preserve the original audit WAL, SIEM records, vault records, and provider
   evidence. Never delete or rewrite them.

## Lifecycle

Operator mutations require `expected_revision`; a stale release returns
`409`. Acknowledge first, narrow scope when safe, extend only with a bounded
TTL, and release only after the relevant provider health, conformance, policy,
IdP, and RAG gates are green. Expired provider/tool/route containment enters
probation and does not silently restore traffic.

Emergency containment requires an authenticated operator, a non-empty reason,
and `confirm: true`. Tenant and provider actions must satisfy the policy
threshold and are always tenant-bound; an operator cannot target another
tenant by putting a tenant value in the request body.

If the shared quarantine store is unavailable in production, `/ready` becomes
degraded and relevant traffic fails closed. Restore Redis/TLS/ACL health first;
do not bypass the check or switch production to the memory implementation.

## Recovery evidence

Record the operator, reason digest, policy snapshot, revision, health and
conformance evidence, staged probation result, and rollback decision in the
durable audit/SIEM workflow. A restart must recover state from the shared
store; process-local memory is an explicit development/shadow test seam only.
