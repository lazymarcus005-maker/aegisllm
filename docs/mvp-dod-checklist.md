# MVP Definition of Done — audit against spec §18

Each item lists its implementation and the test/artifact that evidences it.

- [x] **OpenAI-compatible request proxy works** — `internal/gateway` (parser, server). Evidence: `TestCleanRequestProxiedUnchanged`, `TestParseTypicalRequest`, golden suite.
- [x] **Upstream LLM Gateway forwarding works** — `internal/gateway/proxy.go` (auth modes none/bearer/header, no inbound credential forwarding). Evidence: `TestForwardPreservesPathBodyAndContentType`, `TestForwardBearerAuthMode`.
- [x] **Deterministic secret scanner works** — `internal/detectors/secrets.go`. Evidence: per-detector corpus tests + `TestAS001SecretBlockedInEnforceMode`.
- [x] **Thai citizen ID checksum detection works** — `internal/detectors/pii.go` (`ThaiCitizenIDValid`). Evidence: `TestThaiCitizenIDDetection` (synthetic fixtures only).
- [x] **Email/phone/JWT/private-key detection works** — evidence: `TestEmailDetection`, `TestPhoneDetection`, `TestJWTDetector`, `TestPEMPrivateKeyDetector`.
- [x] **PII span interface exists** — `internal/pii` `SpanProvider` + regex/composite providers (FR-006). Evidence: `TestRegexSpanProvider*`.
- [x] **Laya local service integration works** — `internal/decision` `LayaProvider` + adapter normalization. Evidence: `TestLayaProviderHTTPRoundTrip`, `TestUC004ShadowLayaEvidenceAndPredictedBlock`.
- [x] **Thai/English routing is tested** — multilingual question schema + eval corpus slices th/en/mixed; route/checkpoint recorded in audit. Evidence: `TestUC004*`, `evals/datasets/security-v1.jsonl`. (Checkpoint choice itself requires a real laya-serve run — documented in operations.md.)
- [x] **Security question schema v1 is versioned** — `questions/security-v1.yaml` + strict loader. Evidence: `TestLoadQuestionsValid/Invalid`.
- [x] **Policy engine is deterministic** — `internal/policy/engine.go` (spec §7 precedence, severity-max conflict resolution). Evidence: `TestEngineDeterministicRepeats`, conflict tests.
- [x] **ALLOW/BLOCK/TOKENIZE/REDACT work** — end to end. Evidence: golden suite (UC-001/002/003, AS-005).
- [x] **Shadow/enforce modes work** — `SecurityPipeline` + server mode application. Evidence: `TestAS006ShadowPredictsBlockWithoutBlocking`, `TestShadowOutboundPassesThroughWithPrediction`.
- [x] **Outbound response is scanned** — `ProcessResponse` + server outbound path. Evidence: `TestAS005OutboundSecretBlocked`, `TestOutboundPIIRedacted`.
- [x] **Sanitized audit logs work** — `internal/audit` whitelisted Event. Evidence: `TestEventSerializationCarriesNoRawContent`, leak assertions in pipeline tests.
- [x] **Metrics exist** — `internal/observability` Prometheus set on `GET /metrics` (spec §15). Evidence: live smoke test; `Metrics` registered set.
- [x] **Labelled evaluation dataset exists** — `evals/datasets/security-v1.jsonl` (1400 synthetic rows, T-029 counts). Evidence: `TestLoadDatasetFileOnDisk`.
- [x] **Laya baseline report exists** — `evals/baselines/security-v1-noop.json` + `evals/reports/security-v1-2026-10-05.md`; semantic baseline honestly pending a real laya-serve run.
- [x] **Docker Compose local stack exists** — `docker-compose.yml` (gateway, mock upstream, redis, prometheus; laya-serve stub documented).
- [x] **Threat model is reviewed** — `docs/threat-model.md` (handoff §14 checklist), reviewed in this sweep.
- [x] **No raw secret appears in test logs** — assertions over audit output and server logs. Evidence: `TestGatewayLogsCarryNoSecret`, `TestAS001*` leak checks; `go test ./...` passes with leak assertions active.

Deferred by design (spec §19): streaming enforcement, image/document PII, full
MCP proxy, credential broker, Vault/workload-identity integration, admin UI,
central policy distribution, Jev provider, Laya fine-tuning.

## Known gaps found in the code review (2026-10-05)

- **FORCE_LOCAL_MODEL** is representable in the policy engine and audited, but
  is not enforced (no local-upstream routing exists). Spec §18's DoD list does
  not include it; FR-011's "SHALL implement" is only partially met. Deferred
  to V1.1 with local-upstream config as the first step. (server.go
  applyDecision documents this at the decision site.)
- **Semantic calibration is not done.** The threshold-policy mechanism ships
  with tests, but every record in `policies/thresholds-security-v1.yaml` is
  `evaluated: false` (min_confidence 0.00) — by design, because fitting
  thresholds requires a real laya-serve run against the held-out slices
  (`go run ./cmd/evaltool -provider laya -calibrate`). Until then AS-003
  cannot fire in a production deployment; semantic enforcement is
  deliberately unreachable (INV-010).
- **laya-serve is a compose stub** (commented service block) because the
  official image reference could not be verified at build time. Wire
  `LAYA_URL` + the service block when running the calibration above.
- **Encoded/split/homoglyph secret evasions are not detected** — pinned as
  documented-limitation tests in `tests/security` (TestKnownEvasionLimitations)
  so any detection change is a conscious decision.
- **Metrics naming**: spec §15 names are provided verbatim
  (`requests_total`, `blocked_total`, `tokenized_total`, `redacted_total`,
  `review_total`, `false_positive_sample_total`, …); `requests_total` carries
  {action,mode} labels and the action counters are redundant-but-explicit.
