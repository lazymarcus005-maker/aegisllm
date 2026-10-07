# P1.6 durable audit operations

The gateway writes versioned `aegisllm.audit/v1` events to an append-only
local WAL before an audit-required decision is acknowledged. Events contain
metadata only: IDs, UTC time, W3C trace correlation, bounded verified
principal projections, counts, policy/routing/tool identifiers, reason IDs,
latencies, and frame integrity metadata. Prompts, responses, tool arguments or
results, credentials, authorization headers, token originals, decoded payloads,
and stack traces have no production schema field.

## Delivery contract

The local WAL is the durable source of truth. Each frame has a length bound,
CRC-32, a SHA-256 hash chained to the previous frame, and an HMAC over the
record hash. Optional AES-GCM encryption uses the active key from a file-backed
keyring; the key ID is stored in the encrypted envelope and old keys must be
retained until all records using them expire. The gateway does not claim
exactly-once delivery. SIEM delivery is at-least-once: a process restart can
replay a batch, and the stable event IDs plus batch `Idempotency-Key` let the
receiver deduplicate.

The exporter sends bounded HTTPS JSON batches. 2xx responses checkpoint the
batch; timeouts and 5xx/429 responses retry with bounded exponential
backoff/jitter and `Retry-After`. Permanent errors or exhausted retries are
written to a mode-0600 dead-letter file and checkpointed as quarantined. The
DLQ is an incident artifact, not a successful SIEM delivery.

`AUDIT_FAILURE_MODE=fail_closed` is required for audit-required/high-risk
production decisions: if the WAL cannot append, the upstream or MCP action is
not attempted. `degrade` is for explicitly bounded non-production operation.
Exporter failure alone does not silently discard the WAL; readiness exposes
the condition and the backlog remains replayable.

## Operator procedures

Metadata-only inspection and bounded verification:

```bash
go run ./cmd/audittool inspect --dir /var/lib/aegisllm/audit
go run ./cmd/audittool verify --dir /var/lib/aegisllm/audit
```

`repair` never rewrites a WAL without an explicit confirmation flag. It emits
a quarantine report and, with `--confirm`, moves affected segment files to a
timestamped `.quarantine-*` name. Stop the gateway, preserve the original
directory, capture the report, and open an incident before using it.

`GET /api/audit/status` and `POST /api/audit/verify` are operator-role-only.
They expose queue bytes, record count, oldest age, exporter state, corruption,
and readiness; they never return event payloads. `/ready` is not ready when a
production WAL is unavailable or has an integrity failure.

## Backup, restore, capacity, and key rotation

Stop the gateway or take a filesystem snapshot that includes all WAL segments,
`checkpoint.json`, `export.checkpoint`, `hmac.key` when auto-generated, and the
encryption keyring. Restore the complete directory and key material together;
never restore segments with a different HMAC key. Run `audittool verify` before
starting traffic. Restoring an older exporter checkpoint intentionally causes
at-least-once replay.

Size `AUDIT_MAX_BYTES` for peak event rate × retention window × average framed
event size, with at least 30% free disk. `AUDIT_SEGMENT_BYTES` bounds recovery
and quarantine units. Quota pressure returns an explicit failure rather than
silently deleting unexported events; retention may remove old non-current
segments only according to the configured retention policy.

Add a new encryption key without removing old keys, make it active, verify a
restart and replay, then remove expired keys only after the retention window
and backup window have elapsed. HMAC key rotation is a migration: retain the
old key for verification or archive the old WAL and start a new directory.

## Incident handling

On corruption, preserve the directory read-only, record the reported segment
and sequence, and compare the SHA/HMAC chain with the last trusted backup.
Do not skip a segment or manually edit frames. Use `repair --confirm` only
after evidence capture; quarantine reports are the handoff to the incident
response process. Search is intentionally not provided by the gateway; any
future search contract must be separately authorized and sanitized.
