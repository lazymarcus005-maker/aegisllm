# P1.9 Session-Scoped Token Vault

## Threat model and scope semantics

The vault protects reversible PII mappings from cross-tenant, cross-application,
cross-user, cross-session, policy-confused-deputy, replay, and uncontrolled
retention attacks. A production scope is version `1` and is derived only after
the gateway verifies tenant, application, subject, and a session binding. The
scope also contains the policy bundle ID/version, purpose, and data category.
Subjects and session bindings are keyed digests in vault records; raw identity
is not a Redis key, index member, metric, audit field, or placeholder.

JWT callers must provide the configured `sid` claim (override with
`JWT_SESSION_CLAIM`). SSO refreshes must preserve the same `sid` for the
authenticated session and issue a new binding after logout. mTLS callers are
bound to a digest of the verified public key. Service accounts are
non-interactive principals: they must use a short-lived signed JWT with a
unique `sid`, or a verified mTLS key binding; a client header is never a valid
substitute. Production `TOKENIZE` fails closed when no binding is present.

The default placeholder is `<v1.random-id.checksum.mac>`. It is random,
opaque, non-enumerable, and carries no identity or PII. Category visibility is
disabled by default and can only be enabled by policy/configuration. Parsing,
MAC, checksum, version, lookup, scope, and AAD failures use bounded generic
errors.

## Encryption and storage

Each mapping uses AES-256-GCM envelope encryption. The active versioned
keyring seals new records; retained keys can read live records after rotation.
The complete scope and token metadata are authenticated as GCM AAD. Records
carry creation/absolute expiry, optional bounded idle expiry, purpose,
single-use/max-retrieval policy, and key metadata. Redis and memory implement
the same atomic retrieval and revocation-index contract. Redis record,
retrieval-counter, and session-index keys are HMAC-derived and contain no raw
scope or token strings.

Absolute TTL is mandatory. Idle TTL, when configured, must be shorter than the
absolute TTL and is never allowed to slide beyond it. Value-size, record,
session, and retrieval quotas are enforced before re-identification. Redis
outage is a strict failure in production; there is no memory fallback and no
upstream request may receive a restored value.

Key removal is conservative: `KeyringFile` rejects removal of a previously
retained key unless the configured removal policy is explicitly enabled after
all dependent records have expired. `vaulttool rotate-plan` is a dry-run
operator check; deploy the new active key while retaining the old key until
the maximum absolute TTL plus an operational safety interval has elapsed.

## Authorization and delivery paths

The only runtime restore path is the configured trusted response path, or a
trusted MCP/tool-return path whose purpose includes the verified server ID.
The request scope, purpose, policy version, session binding, and data category
must match. Tokens from another tenant, app, subject, session, policy,
purpose, category, or MCP server are denied. No general detokenize endpoint is
provided. `/api/token-vault/status` exposes aggregate counters only to the
operator role; it never exposes token IDs, values, ciphertext, keys, or scope
components.

`POST /v1/session/logout` is the session-end hook. It uses the verified
principal and removes the session's indexed records. MCP `DELETE` session
lifecycle must use the same hook when the transport is configured for scoped
tokenization. Streaming inspection keeps the verified request context and
bounded holdback while reconstructing split placeholders; it never accepts a
scope supplied in a stream chunk or client header.

## Operations and rollback

Use the CLI without printing secrets:

```text
vaulttool status
vaulttool verify-keyring -file /secure/token-vault-keyring.json
vaulttool rotate-plan -file /secure/token-vault-keyring.json
vaulttool revoke-session -redis-url rediss://... -index-hash <derived-index>
```

The revocation command accepts only a pre-derived session index hash or a
secure file containing that hash. It never accepts or prints an original,
placeholder, ciphertext, key, tenant, user, or session value. During incident
response, revoke the verified session first, then rotate the active key if
compromise is suspected. Retain the previous key for live-record reads unless
the incident requires invalidating those records; invalidation is a deliberate
expiry/revocation action, not a silent fallback.

Legacy request-ID/type/ordinal mappings remain only for development and test
compatibility. Production mounts `ScopedVault`, rejects missing session
bindings, and does not silently broaden access to an unscoped record. A future
migration mode must be explicitly short-lived, separately audited, and
disabled by default.

## Roadmap delivery

P1.9 is delivered across the verified-auth context, production pipeline
integration, memory/Redis backends, AES-GCM AAD/keyring rotation, stream and
MCP purpose propagation, session revocation, privacy-safe status, and
`cmd/vaulttool`. Follow-on work may add policy-authorized deterministic alias
indexes and durable audit event types without changing the scope contract.
