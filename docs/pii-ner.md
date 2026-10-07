# Production PII / NER span engine

The gateway keeps `pii.SpanProvider` as the stable seam. Deterministic
validators run first; configured private NER providers add entity spans; the
existing `pii.Plan` precedence resolver then chooses non-overlapping
transformations. Laya is semantic evidence only and cannot produce spans.

## Contract and providers

`aegisllm.pii-ner/v1` registries are strict YAML documents with version 1.
Each provider declares an id, type (`presidio_http` or `aegis_ner_http`), URL,
languages, entity mappings, per-entity and per-language confidence floors,
priority, timeout,
character/chunk limits, concurrency/breaker limits, fail behavior, and TLS or
file-backed auth references. The Aegis service receives `{schema, version,
text, language, correlation_id}` and returns `{schema, version, spans}`. A
span has `entity`, `start`, `end`, `confidence`, and `offset_unit`; offsets may
be `byte`, `codepoint`, or `utf16`. Presidio requests use `/analyze` and its
standard `entity/start/end/score` response.

Only the required text part and an opaque correlation id are sent. Tenant,
user, application, URL credentials, provider payloads, and raw samples are
not sent or logged. Production requires HTTPS to a private service address;
TLS and optional mTLS use `securetransport`, and bearer auth is file-backed.

Responses are rejected if offsets are invalid, split UTF-8 boundaries, out of
range, overlapping within one provider response, or confidence is invalid.
UTF-16 conversion rejects offsets inside a surrogate pair. Long text is
chunked by rune count with bounded overlap and reassembled in byte offsets;
overlap duplicates are deduplicated deterministically.

## Coverage and fallback

The deterministic registry continues to cover existing validated PII such as
Thai citizen IDs, phone, email, credit card, and IP address. NER mappings
support at least `PERSON`, `ADDRESS`, `ORGANIZATION`, `TH_TAX_ID`,
`TH_PASSPORT`, `HEALTH_ID`, `MEDICAL_RECORD`, `BANK_ACCOUNT`, and
`DATE_OF_BIRTH`; a provider owns model quality for free-form entities. Regex
is not presented as NER.

`PII_NER_REQUIRED=true` makes provider outage, timeout, malformed response,
breaker open, or cancellation a sanitized `PII_NER_UNAVAILABLE` block. A
balanced/development route may set `fail_behavior: deterministic_only`; the
deterministic findings remain active and the audit event records
`pii_fallback=true`. There is no implicit allow path.

| profile/policy | NER available | NER unavailable |
|---|---|---|
| production strict protected route | deterministic + configured NER | block with `PII_NER_UNAVAILABLE`, readiness not ready |
| balanced governed route | deterministic + configured NER | deterministic-only, `pii_fallback` audit/metric |
| development | configured behavior | deterministic-only unless `PII_NER_REQUIRED=true` |

## Operations and threat model

The provider has bounded input, response body, timeout, concurrency, and
circuit-breaker limits. The registry manager validates a replacement fully
before atomically swapping it and retains the last-known-good snapshot on
failure. `/ready` reports only sanitized provider availability/breaker state.
Operator role `aegis.operator` may read `GET /api/pii/providers`; it exposes
provider id/type, bounded coverage, counters, and state, never URL,
credentials, payloads, or samples. Metrics are bounded by provider, entity,
language, confidence bucket, latency, error, and fallback labels and contain
no text or value hashes.

## Calibration and evaluation

`cmd/piieval` evaluates JSONL rows with `id`, `language`, `text`, and labeled
byte spans. It reports exact and overlap precision/recall/FNR by language and
entity, confidence calibration candidates, provider name, and dataset
SHA-256. `evals/datasets/pii-ner-synthetic.jsonl` and the fake NER Docker
profile are explicitly non-production and must not be used to claim model
quality or promote thresholds.

Example CI run:

```bash
docker compose -f docker-compose.fake-ner.yml --profile ner-ci up --build -d
go run ./cmd/piieval -provider fake -url http://127.0.0.1:8400 \
  -dataset evals/datasets/pii-ner-synthetic.jsonl \
  -json /tmp/pii-report.json -report /tmp/pii-report.md
```
