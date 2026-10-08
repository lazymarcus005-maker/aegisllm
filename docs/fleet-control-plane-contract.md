# P2.5 enterprise fleet control-plane contract

P2.5 adds a gateway-side fleet agent and a deterministic control-plane seam
for operating gateways across tenants, environments, and regions. It is not
a hosted SaaS service. Existing signed policy distribution, semantic
lifecycle, quarantine, routing/provider health, RAG/MCP, audit/SIEM,
readiness, and release-evidence systems remain authoritative for their own
artifacts.

`fleet.Identity` is immutable after enrollment and contains an opaque gateway
ID, authority-derived scope, software/build/SBOM/provenance digests,
capabilities, trust domain, certificate/key IDs, and a monotonic revision.
Production enrollment binds verified mTLS to signed, one-time, expiring
bootstrap material. Self-asserted scope, duplicate IDs, replay, expiry,
downgrade, and cross-fleet enrollment are rejected.

Desired state is canonical signed JSON with validity windows, rotating trust
key ID, monotonic revision, selectors, minimum version/capabilities, bounded
offline grace, rollout constraints, and digest-only policy/model/route/tool/
RAG/quarantine references. It contains no secrets or model weights. The agent
uses HTTPS/mTLS, ETags, bounded responses/timeouts, atomic application,
mode-0600 last-known-good persistence, restart recovery, and explicit
fail-closed expiry. No remote shell, plugin upload, file read, secret export,
prompt collection, or log scraping is representable.

Rollouts are shadow/canary/wave stages with identity-derived cohorts,
concurrency/error budgets, readiness/conformance/release-evidence gates,
pause/rollback, and approval. The operator surface exposes sanitized
inventory, opaque gateway details, compliance, desired-state validation and
publication, and confirmed rollout/enrollment actions. Gateway actions are
delivered as signed envelopes and are limited to sync, pause, verified
rollback, quarantine scope, trust-reference rotation, and upgrade-required
transitions. Heartbeats are fixed-shape, privacy-safe aggregates and claims,
not attestation. `cmd/fleetctl` provides the bounded operator client.

`cmd/fakefleetcontrolplane`, `docker-compose.fake-fleet.yml`, and
`scripts/fleet-compose-smoke.sh` are contract/integration fixtures only. Real
PKI/HSM/IdP, external attestation, signer governance, multi-region consistency
and scale, and production rollout validation remain external dependencies.
