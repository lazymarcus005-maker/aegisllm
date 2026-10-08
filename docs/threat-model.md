# Threat Model — Laya LLM Security Gateway

Scope: the MVP gateway as implemented (tickets 01–13). Trust boundaries follow
`architecture.md` §5. Review status: reviewed during the MVP DoD sweep.

P1.6 adds a metadata-only durable audit boundary. The WAL is integrity chained
and optionally encrypted at rest; an HTTPS exporter is at-least-once and uses
stable event IDs for receiver deduplication. Corruption fails production
readiness and is quarantined only by explicit operator repair. Trace context is
validated and only `traceparent` is propagated. Prompts, credentials,
authorization headers, tool payloads, token originals, decoded evasion content,
and stack traces remain out of the event schema, SIEM batch, metrics, and
operator endpoints.

## Trust boundaries

- **TB-1 Client → Gateway**: fully untrusted. In protected deployments the
  gateway verifies a bearer JWT and derives identity only from selected claims;
  inbound identity and Authorization headers are stripped before proxying. The
  development-only `AUTH_MODE=off` mode retains trusted-header compatibility.
- **TB-2 Gateway → Laya**: local, non-internet-facing. Laya is a classifier,
  never an enforcement authority (INV-002).
- **TB-3 Gateway → LLM Gateway**: only policy-approved or transformed content.
- **TB-4 LLM Gateway → provider**: policy varies by provider class
  (cloud stricter than local).
- **TB-5 Tool runtime / MCP**: credentials live outside model context
  (INV-007); this gateway inspects intent and content only.

## Threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Secret leakage to LLM | deterministic secret detectors + policy BLOCK before forwarding (AS-001); bounded stateful outbound SSE scan with holdback blocks split model-emitted secrets (AS-005) | encoded/homoglyph evasions and candidates longer than the configured holdback remain limitations |
| Secret leakage to Laya | planner skips semantics on deterministic secret findings (SEC-002) | none deterministic-path |
| Secret leakage to logs | findings carry HMAC value hashes only; audit events are whitelisted-field structs; leak tests over audit + logs | operator-added logging must follow the same rule |
| PII leakage to cloud providers | PII/span detection + policy TOKENIZE/REDACT per provider (AS-002); private NER only, minimized text, TLS/mTLS, bounded/sanitized adapters | provider model quality and private-service compromise remain deployment risks |
| PII re-identification abuse | vault: envelope encryption, TTL, namespace isolation, issuance-time application authorization; model-invented placeholders never resolve (T-023) | vault compromise requires the master key (KEK) — external secret management required in production |
| Prompt injection / jailbreak | Laya semantic evidence + calibrated policy slices; deterministic fast path unaffected | pattern-based deterministic detection only for known phrases; semantic enforcement requires calibration evidence (INV-010) |
| System-prompt extraction | security-v1 question + semantic policy | same calibration gate |
| Credential exfiltration intent | security-v1 question on request and tool_call directions; policy block/restrict | classifier false negatives — eval corpus emphasizes FNR |
| Tool abuse | InspectToolCall / InspectToolResult reuse the full pipeline; RESTRICT_TOOLS strips tools physically; the MCP proxy applies registry allowlists and schema validation before execution | upstream tool descriptions remain untrusted |
| Policy bypass | policy-as-code with strict schema validation; corruption fails startup (fail closed) | policy repo compromise = config poisoning; protect with review + CI |
| Caller identity spoofing | RS256/ES256 JWT verification, strict algorithm/key matching, issuer/audience/time checks, and route RBAC; inbound identity headers are stripped | development/off mode and the explicit unauthenticated shadow waiver remain spoofable |
| Client credential forwarding | proxy forwards only content negotiation headers and applies upstream credentials from gateway configuration | a compromised gateway host can access configured upstream credentials |
| Laya outage | circuit breaker + risk-sensitive policy fallback; high-risk routes fail closed (AS-004, INV-008); never catch→ALLOW | availability impact on high-risk routes is deliberate (policy-controlled) |
| Classifier false negatives/positives | eval harness with FNR-emphasized slices; regression CI gates promotion (§17) | thresholds are only as good as the labelled data |
| Audit-log leakage | audit struct cannot carry raw content by construction (ticket 02 tests) | downstream log sinks must be access-controlled |
| Configuration poisoning | KnownFields-strict YAML loaders; validated declarative actions, thresholds, count rules, operator-only effective-policy summary, and versioned policy files | supply chain of those files — protect the repo and require policy review |
| Semantic calibration poisoning/tampering | SHA-256-bound question/dataset provenance, provider/checkpoint binding, strict slice coverage and explicit reviewed promotion | operators must protect reviewed artifacts and the real Laya image |
| Malformed semantic evidence | missing/extra decisions, unknown questions, schema/checkpoint mismatch, and non-finite/out-of-range confidence are rejected; fallback matrix is policy-controlled | high-risk availability impact is deliberate |
| Supply-chain dependency risk | small dependency surface: yaml.v3, go-redis, miniredis (test), prometheus client | pin versions in go.sum; review updates |
| Oversized request / DoS | MaxBytesReader → 413 before inspection; read-header timeout; Laya circuit breaker | volumetric DDoS protection belongs to the edge |
| Tenant/application abuse and cost amplification | verified-identity token bucket and concurrency semaphore, normalized prompt budget, bounded response/stream lifetime, global Laya semaphore, bounded key cleanup | process-local limits do not enforce a global budget across instances; distributed limiter is deferred |
| Upstream stall or connection exhaustion | dial/TLS/header/request/idle timeouts, bounded pool, response byte cap, no automatic POST retry, circuit breaker and sanitized readiness | provider-side overload and volumetric attacks still need edge controls |
| Dependency link interception or downgrade | shared TLS 1.2+ transport, system/custom CA bundles, strict hostname verification, optional mTLS, production rejection of `http://`/`redis://` | CA/private-key lifecycle remains an operator responsibility |
| Forced-local escape to cloud | immutable route snapshots, unconditional local-class filter, verified provider claims, explicit-only fallback chains, fail-closed `ROUTE_LOCAL_UNAVAILABLE` | operators must keep local health probes and capabilities accurate |
| Registry disclosure or malicious reload | strict known-field validation, last-known-good atomic reload, operator-only sanitized route status, file-backed credentials | registry file permissions and deployment review remain operator responsibilities |
| Credential/certificate/key rotation failure | atomic file reload, last-known-good retention, bounded polling, sanitized readiness and reload/expiry metrics | a bad replacement can make production unready until rollback or repair |
| Ingress identity spoofing | direct mTLS verifies client certificate against an operator CA and derives principal identity; identity headers are stripped; trusted-edge mode is an explicit deployment contract | certificate subject mapping must be governed by the issuing PKI |
| Vault key compromise or unsafe removal | versioned opaque key IDs, active seal key plus retained decrypt-only keys, legacy envelope support, default removal rejection, tenant/application authorization | external secret manager/HSM and retention inventory are still required |
| Unicode/encoding evasions | bounded NFKC/control/confusable projection, standard/raw/URL-safe Base64, percent/JSON Unicode decoding, structured traversal, and rolling SSE state; unsafe decoded/cross-part findings fail closed | unsupported encodings, candidates over configured work/depth/expansion budgets, and malformed structured data are rejected or remain limitations |
| Canonicalization offset confusion | maintained Unicode normalization plus per-byte source maps; only reversible same-part spans can be transformed | decoded, cross-part, and structured escaped spans are BLOCK/REVIEW policy evidence and are never partially redacted |
| Cross-tenant token collision | token namespace is per-request ID; vault keys carry namespace + token label | multi-tenant session namespaces are a V1.1 item |
| Model context carries tool credentials | out of scope for the gateway (TB-5) — credential broker is Phase 2 | deployment must route tool creds outside model context |

## Failure modes (architecture §16)

- Deterministic scanner unavailable → fail closed for protected routes.
- Laya unavailable → risk-sensitive fallback: high-risk routes take
  `fallback.laya_unavailable.high_risk` (BLOCK by default), others continue
  deterministic-only.
- Semantic enforcement cannot be enabled with the committed noop/synthetic
  artifact: startup requires a real reachable provider, promoted provenance,
  complete eligible slices, and passing criteria.
- Policy engine failure → fail closed (500 on pipeline error; BLOCK on
  unknown action).
- Audit sink failure → console sink; production deployments should buffer
  minimal sanitized events and alert.
- Streaming responses are inspected through bounded SSE parsing. Production
  requires a 4096-byte minimum holdback, 64 KiB default event limit, and 1 MiB
  default queued-byte budget. On BLOCK/REVIEW the upstream body is closed and
  the client receives only a sanitized error; shadow records a prediction but
  forwards the original event. A provider that emits malformed or oversized
  events is rejected in production.
# P1.7 dashboard threats

The dashboard is an operator-only read surface. RBAC covers the page and every
v2 API route; the page does not accept state-changing actions, store bearer
tokens, or put credentials in URLs. Strict CSP, same-origin requests, DOM text
construction, no-store responses, and clickjacking/MIME/referrer headers reduce
browser injection and caching risk. The rolling aggregator has fixed buckets,
allowlisted labels, cardinality caps, bounded windows, and an `OTHER` bucket.
It does not contain raw prompts, findings, identities, tenant labels, token
mappings, or durable audit payloads. Stale, disconnected, unavailable, and
disabled states are distinct so a telemetry gap cannot be mistaken for a
healthy zero. The remaining limitation is process-local reset; operators must
not treat the dashboard as the durable audit source.

# P1.8 conformance-lab threats

# P1.10 release and supply-chain threats

# P2.1 multimodal/document DLP

Attachment references are normalized before forwarding and inspected under
encoded/decoded byte, count/page/text, archive expansion, timeout, and
cancellation budgets. MIME is checked against magic bytes. URL sources require
HTTPS, host allowlisting, DNS/IP validation on every redirect, bounded reads,
response MIME verification, and a separate fetch client with no caller or
extractor mTLS credentials. `file://`, credentials, query-bearing URLs, and
unallowlisted/private destinations fail closed. Extracted text joins the
existing detector/PII/evasion/semantic/policy path, including cross-part
state; audit and metrics contain only bounded metadata and hashes. Unsupported
binary reconstruction blocks rather than claiming REDACT/TOKENIZE succeeded.

Remaining promotion risks are the real OCR/document engine, private PKI and
rotation, network DNS/redirect operations, and production data calibration.

# P2.2 retrieval authorization

RAG metadata and retrieved results are treated as client-controlled until
bound to the verified ingress principal. The gateway enforces a content-free
request/result contract across tenant, application, subject, roles, groups,
document/chunk, collection/index, classification/labels, purpose, operation,
query digest, policy snapshot, and expiry. Each result receives an independent
decision binding; mixed or unauthorized sets fail closed before normalization
or upstream forwarding. Unsupported shapes, result injection, stale/replayed
decisions, oversized traversal, timeouts, malformed responses, and service
outage are rejection conditions. Redaction is not offered for arbitrary RAG
documents because it cannot be proven to preserve chunk semantics.

The private adapter uses the shared verified TLS/mTLS transport with bounded
response reads and no caller credentials or identity headers. SSRF controls
reject production plaintext, credentials, query strings, and fragments in the
authorization endpoint. Audit and metrics expose only bounded outcome/reason,
chunk count, policy, and trace metadata; query/document text, sensitive labels,
tokens, and high-cardinality resource IDs are excluded. The deterministic fake
service and Compose profile prove contract behavior only. Real IdP claims,
vector-store result provenance, authorization-service policy correctness,
production PKI/rotation, replay protection at the service boundary, and
tenant/classification calibration are external promotion dependencies.

The release boundary treats tool/database outages as blockers, not passes. A
pinned Debian Go image supplies the race compiler; reproducible hash comparison,
CycloneDX SBOM, final-image vulnerability scan, secret scan, least-privilege
CI, and evidence hashes reduce substitution and omission risk. The scratch
runtime has no shell/package manager and runs non-root with only an explicit
audit writable mount. Shared-host performance data is advisory so host noise
cannot silently weaken the 25 ms SLO.

Conformance traffic is synthetic by contract. The runner accepts credentials
only through environment/file descriptors, uses TLS/mTLS file material, and
stores only hashes, byte counts, bounded semantic shapes, and allowlisted
headers. Fake providers never log bodies. Reports are validated before
certification and required skips fail the run. Differential mode is intended
for lab traffic only and must not be pointed at production. A capability
declaration is a reviewed, SHA-256-bound artifact; a remote report cannot
automatically enable streaming or tools. Deviations not represented in the
versioned spec require an explicit profile update and review.

# P2.3 automated quarantine threats

The quarantine threat model assumes request bodies, headers, tool arguments,
RAG metadata, provider responses, and client-supplied labels are hostile.
Only trusted detector/RAG/MCP/provider findings and verified identity claims
can produce automated signals. The signal validator rejects unknown reasons,
raw evidence, missing tenant identity, forged provenance, and oversized
collections. Digest-keyed state, per-tenant key construction, bounded state
capacity, and fixed-cardinality metrics prevent evidence disclosure, cross-
tenant containment, and state/label exhaustion.

Broad tenant/provider isolation is not a single-event response: policy must
explicitly authorize the scope and threshold, and operator emergency actions
require confirmation and a reason. Redis outages fail closed in production.
Expiry is followed by health/conformance/policy-gated probation, so recovery
cannot silently restore a compromised dependency. Fakes and local memory
prove contracts and failure paths only; IdP, Redis ACL/TLS, SIEM durability,
provider conformance, and production signal calibration remain external
validation requirements.

# P1.5 distribution threats

Policy distribution treats the control plane as untrusted transport: Ed25519
signatures, a rotating multi-key trust store, validity windows, artifact
hashes, target gates, and durable sequence/hash state protect against tamper,
unknown/revoked signer, replay, and rollback. HTTPS/mTLS protects transport
confidentiality and endpoint identity but is not a substitute for signing.

Canary candidates run shadow-only, stable assignment prevents cohort churn,
and promotion is an authenticated operator action. A signed rollback
authorization is required to restore a retained complete snapshot. Bundle
manifests and operational metrics intentionally contain no prompts, traffic,
secrets, private keys, or sensitive policy conditions.

# P2.4 semantic lifecycle and drift threats

The model registry treats metadata, signatures, timestamps, digests, signer
keys, policy bindings, and lifecycle requests as hostile. Ed25519 verification
uses the existing rotating trust store; future/expired, replayed, downgraded,
incompatible, digest-mismatched, unapproved, revoked, or synthetic production
artifacts are rejected. Immutable records, CAS revisions, idempotency, signed
policy binding, and atomic runtime snapshots prevent mixed model/threshold
activation and stale operator writes.

Drift inputs are trusted aggregate buckets rather than raw traffic. Validation,
fixed cardinality, minimum samples, confidence guardrails, fixed windows,
sustained breach/cooldown/hysteresis, healthy-target checks, and two-scope
corroboration prevent one tenant, a label outage, or a transient distribution
from causing fleet rollback. Durable audit/SIEM and metrics contain bounded
references/action classes only. Fixtures are contract/fake evidence; real model
quality, production distributions, label trust, signer governance, and Laya
connectivity remain external promotion dependencies.
