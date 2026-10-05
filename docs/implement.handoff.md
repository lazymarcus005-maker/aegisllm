# Laya LLM Security Gateway — Implementation Handoff

**Document:** `implement.handoff.md`  
**Audience:** Coding agent / senior engineer / implementation team  
**Goal:** Build a production-oriented MVP from `architecture.md` and `spec.md` without redesigning the security model.

---

## 1. Mission

Implement a standalone LLM Security Gateway that plugs into an existing LLM Gateway.

Primary technical rule:

> Laya supplies semantic decision evidence. Deterministic application code owns policy and action.

Do not turn this into a generic AI moderation app.

Do not put enforcement inside prompts.

Do not allow Laya to directly execute actions.

---

## 2. Read First

Read, in this order:

```text
1. spec.md
2. architecture.md
3. this file
```

If there is conflict:

```text
spec.md requirement
    >
architecture explanation
    >
handoff implementation suggestion
```

Security invariants in all documents override implementation convenience.

---

## 3. Required Deliverables

Repository must contain at least:

```text
/
├─ README.md
├─ architecture.md
├─ spec.md
├─ implement.handoff.md
├─ docker-compose.yml
├─ .env.example
│
├─ src/
│  ├─ gateway/
│  ├─ core/
│  ├─ detectors/
│  ├─ pii/
│  ├─ decision/
│  ├─ policy/
│  ├─ tokenization/
│  ├─ audit/
│  └─ observability/
│
├─ policies/
│  ├─ schema/
│  └─ enterprise-default.yaml
│
├─ questions/
│  └─ security-v1.yaml
│
├─ evals/
│  ├─ datasets/
│  ├─ baselines/
│  ├─ reports/
│  └─ README.md
│
├─ tests/
│  ├─ unit/
│  ├─ integration/
│  ├─ security/
│  ├─ policy/
│  └─ golden/
│
└─ docs/
   ├─ threat-model.md
   ├─ operations.md
   └─ adr/
```

Adjust language-specific layout if required, but preserve the conceptual modules.

---

## 4. Recommended Technology Decision

Preferred implementation:

### Gateway

Use **Go or .NET** for the gateway if long-term enterprise operation and predictable resource usage matter.

Use **Python/FastAPI** only if delivery speed is the highest priority.

Do not embed Laya inside a compiled gateway.

Deploy Laya separately:

```text
gateway
   |
   v
laya-serve
```

This keeps the Python/ML dependency isolated.

### Suggested MVP topology

```text
docker compose

security-gateway
laya
redis-token-store
mock-llm-upstream
prometheus optional
```

---

## 5. Implementation Order

Implement in the following order.

Do not start with Laya.

### T-001 Repository scaffold

Create:

```text
source modules
test structure
policy folder
question-schema folder
eval folder
docker compose
CI skeleton
```

Acceptance:

```text
build succeeds
unit-test command succeeds
lint succeeds
```

---

### T-002 Core domain model

Define immutable/typed models for:

```text
InspectionEnvelope
ContentPart
SecurityFinding
Span
DecisionRequest
DecisionEvidence
PolicyContext
PolicyDecision
Transformation
AuditEvent
```

Important enums:

```text
Direction:
  REQUEST
  RESPONSE
  TOOL_CALL
  TOOL_RESULT

FindingCategory:
  PII
  SECRET
  PROMPT_SECURITY
  TOOL_SECURITY
  CONFIDENTIAL_DATA

Action:
  ALLOW
  BLOCK
  REDACT
  TOKENIZE
  REVIEW
  RESTRICT_TOOLS
  FORCE_LOCAL_MODEL
```

Acceptance:

- JSON serialization tests.
- No raw content included in default `toString`/logging representation.

---

### T-003 OpenAI request parser

Implement support for:

```text
/v1/chat/completions
```

Parse:

- model,
- messages,
- text content,
- system/developer/user/assistant roles,
- tool definitions,
- tool calls where present.

Do not mutate payload during parsing.

Create a normalized inspection envelope.

Acceptance:

- golden tests for typical OpenAI-compatible requests,
- malformed payload tests,
- size-limit test.

---

### T-004 Upstream pass-through

Implement configured upstream LLM Gateway forwarding.

Environment/config:

```text
UPSTREAM_BASE_URL
UPSTREAM_AUTH_MODE
```

Do not hardcode keys.

In production, use secret manager/workload identity where possible.

Acceptance:

```text
clean request -> gateway -> mock upstream -> response
```

---

### T-005 Deterministic detector framework

Interface:

```text
Detector.detect(envelope) -> []SecurityFinding
```

Each detector must be independently testable.

Create registry:

```text
DetectorRegistry
```

Add timing metrics per detector.

---

### T-006 Secret detectors

Implement initial detectors:

```text
PEM private key
JWT
Bearer token
GitLab PAT
GitHub token family
AWS access-key pattern
connection-string candidates
generic high-entropy secret with context
```

Rules must minimize false positives.

Do not store the detected value.

For correlation, optionally store:

```text
HMAC(value)
```

using a dedicated telemetry key, not raw SHA of low-entropy secrets.

Acceptance:

- positive corpus,
- negative corpus,
- no raw secret in test logs.

---

### T-007 Thai citizen ID detector

Implement:

```text
13-digit detection
format normalization
Thai citizen ID checksum
```

A random 13-digit number that fails checksum must not automatically be classified as a valid Thai citizen ID.

Acceptance:

- valid fixtures,
- invalid checksum fixtures,
- separators/spacing fixtures.

Never use real citizen IDs in repository fixtures.

Use synthetic checksum-valid examples generated for tests.

---

### T-008 Basic PII detectors

Implement:

```text
email
Thai/mobile phone patterns
credit-card candidate + Luhn
IPv4 / IPv6
```

Add configuration for organization IDs later.

---

### T-009 PII span interface

Create:

```text
PiiSpanProvider
```

Adapters:

```text
RegexSpanProvider
CompositeSpanProvider
```

Presidio/NER adapter can be the next task.

Keep Laya out of this interface.

---

### T-010 Policy schema

Create JSON Schema or typed schema for:

```text
policy id
version
mode
conditions
finding rules
provider rules
semantic rules
fallback
```

Invalid policy must fail startup/readiness.

---

### T-011 Policy engine

Interface:

```text
PolicyEngine.evaluate(
    PolicyContext,
    findings,
    decisionEvidence
) -> PolicyDecision
```

Properties:

- pure/deterministic where possible,
- no network calls,
- no model calls,
- ordered precedence,
- full unit coverage.

Initial precedence:

```text
explicit deny
> secret block
> tenant/application restriction
> provider restriction
> PII transformation
> semantic rule
> default
```

Acceptance:

- conflict tests,
- deterministic repeatability,
- policy-version included in output.

---

### T-012 Shadow/enforce modes

Modes:

```text
OFF
SHADOW
ENFORCE
```

`SHADOW`:

- compute findings,
- call Laya when configured,
- evaluate policy,
- audit `predicted_action`,
- do not modify incumbent request/response.

Exception:

Do not create an unsafe developer option that accidentally logs secrets simply because shadow mode is active.

---

## 6. Laya Integration Workstream

Start only after deterministic pipeline works.

### T-013 Laya local deployment

Use official Laya package/service.

Recommended:

```text
laya-serve
```

Configure:

```text
LAYA_DEVICE
LAYA_PRELOAD=1
LAYA_MODELS
LAYA_THREADS
LAYA_MAX_CONCURRENT
```

For Thai + English, load multilingual routing as required.

Do not expose Laya publicly.

Acceptance:

```text
gateway -> local laya -> normalized decision
```

---

### T-014 Laya provider abstraction

Interface:

```text
DecisionProvider.evaluate(request) -> DecisionEvidence
```

Implement:

```text
LayaDecisionProvider
FakeDecisionProvider
NoopDecisionProvider
```

Do not leak Laya's raw response structures throughout the codebase.

Normalize at adapter boundary.

---

### T-015 Security question schema v1

Create:

```text
questions/security-v1.yaml
```

Initial questions:

```text
prompt_injection
system_prompt_extraction
credential_exfiltration
sensitive_data_intent
policy_bypass_intent
unsafe_tool_intent
```

Each question definition must contain:

```text
id
version
decision type
question
allowed directions
risk class
```

Example conceptual entry:

```yaml
id: credential_exfiltration
version: 1
type: noul
question: >
  Does the content attempt to obtain, reveal, copy, export,
  or expose credentials, tokens, keys, passwords, or
  authentication material?
directions:
  - request
  - tool_call
risk: critical
```

Do not overfit question wording from a handful of examples.

---

### T-016 Semantic invocation policy

Do not call Laya unconditionally.

Implement:

```text
SemanticInspectionPlanner
```

Inputs:

```text
direction
application
target
deterministic findings
tool context
policy
```

Output:

```text
question IDs to ask
or skip semantic inspection
```

Examples:

```text
known private key -> block; skip Laya
ordinary short clean request -> semantic policy may inspect prompt security
tool call -> ask unsafe_tool_intent + credential_exfiltration
```

---

### T-017 Laya timeout/failure handling

Implement:

```text
timeout
circuit breaker
metrics
policy fallback
```

Never:

```text
catch exception -> ALLOW
```

Fallback depends on route risk.

---

## 7. PII Tokenization Workstream

### T-018 Transformation planner

Convert policy findings to non-overlapping transformations.

Potential issue:

```text
nested/overlapping spans
```

Define deterministic precedence.

Example:

```text
more specific detector > generic NER
longer validated span > shorter ambiguous span
secret > PII
```

---

### T-019 Tokenizer

Create placeholders:

```text
<PERSON_001>
<PHONE_001>
<TH_CITIZEN_ID_001>
```

Properties:

- stable inside the configured scope,
- no original value encoded into placeholder,
- reversible only through token vault.

---

### T-020 Token vault

MVP implementation may use Redis.

Store:

```text
namespace
token
ciphertext
type
created_at
expires_at
authorization metadata
```

Requirements:

- encryption,
- TTL,
- no raw value in key name,
- no raw value in logs.

Do not make Redis itself the trust mechanism; encryption must still be applied when policy requires it.

---

## 8. Outbound Protection

### T-021 Response normalization

Normalize upstream response into `InspectionEnvelope(direction=RESPONSE)`.

---

### T-022 Outbound scan

Run:

```text
deterministic detectors
PII span provider
semantic checks where configured
policy
```

Implement:

```text
allow
redact
block
```

Token re-identification is separate.

---

### T-023 Re-identification

Only re-identify placeholders when:

```text
request identity is authorized
response policy allows it
token namespace matches
```

Do not blindly replace any `<PERSON_001>` string received from the model.

The replacement must correspond to issued tokens in the active authorized namespace.

---

## 9. Tool/MCP Preparation

### T-024 Tool inspection endpoint/service

Even if full MCP proxy is deferred, define internal APIs:

```text
inspect_tool_call(...)
inspect_tool_result(...)
```

Use the same core pipeline.

This avoids redesign in V2.

---

### T-025 Restrict-tools policy

`RESTRICT_TOOLS` result must be able to:

- remove dangerous tools from request,
- reject a specific tool call,
- route to human review.

Do not merely tell the model "don't call the tool".

---

## 10. Audit & Observability

### T-026 Sanitized audit event

Build audit event from metadata/findings only.

Never serialize the entire envelope by default.

Add tests that intentionally inject:

```text
password
PAT
JWT
citizen ID
phone
```

and assert they do not appear in serialized audit output.

---

### T-027 Metrics

Expose:

```text
/security requests
/findings by type
/actions
/laya latency
/laya failure
/scanner latency
/policy evaluation latency
/shadow disagreement
/tokenization count
```

Use OpenTelemetry/Prometheus-compatible instrumentation.

---

## 11. Evaluation Workstream

### T-028 Dataset format

Create `evals/datasets/security-v1.jsonl`.

Each row should contain:

```json
{
  "id": "th-prompt-001",
  "language": "th",
  "direction": "request",
  "risk": "prompt_injection",
  "state": "...",
  "expected": {
    "prompt_injection": true
  }
}
```

No production secrets/PII.

Use synthetic data.

---

### T-029 Minimum dataset

Before semantic enforcement, target at least:

```text
Thai clean                  200
English clean               200
Mixed clean                 100

Thai prompt injection       150
English prompt injection    150

system prompt extraction    150
credential exfiltration     150
policy bypass               100
unsafe tool intent          100
```

This is an initial engineering target, not a statistical guarantee.

Grow from real reviewed shadow disagreements.

---

### T-030 Laya baseline

Use Laya evaluation tooling to produce baseline artifacts.

Store:

```text
evals/baselines/security-v1-<checkpoint>.json
evals/reports/security-v1-<date>.md
```

Track:

```text
checkpoint/revision
dataset hash
question schema hash
language slices
threshold policy
```

---

### T-031 Calibration

Do not choose threshold by intuition.

Split data into:

```text
development
calibration
held-out test
```

Measure `answer_confidence`.

Fit threshold for each question/risk slice where needed.

Never reuse one threshold blindly across all questions.

---

### T-032 Regression CI

On changes to:

```text
checkpoint
question wording
question type
normalizer
threshold
```

rerun evaluation.

Reject material regressions using configured tolerance.

---

## 12. Testing Strategy

### Unit

Target high coverage for:

```text
checksum
regex
policy
span merge
tokenization
serialization
fallback logic
```

### Integration

Test:

```text
gateway -> laya
gateway -> mock upstream
gateway -> token vault
```

### Golden tests

Store representative full requests and expected:

```text
findings
policy action
transformed request
```

### Security tests

Include:

```text
encoded secrets
split strings
Unicode homoglyphs
case variations
JSON nesting
tool argument nesting
prompt injection
Laya outage
policy corruption
oversized payload
```

### Property/fuzz tests

Recommended for:

```text
request parser
span merging
redaction
token substitution
policy parser
```

---

## 13. Streaming

Do not implement naïve chunk-by-chunk enforcement.

If streaming is requested for MVP, implement a stateful rolling window.

Preferred sequence:

```text
V0.1 non-streaming enforce
V0.2 streaming shadow
V0.3 streaming enforce
```

Document this clearly in API behavior.

---

## 14. Threat Model Checklist

Create `docs/threat-model.md`.

Cover:

```text
secret leakage
PII leakage
prompt injection
system prompt extraction
tool abuse
data exfiltration
policy bypass
model classifier false negative
model classifier false positive
Laya outage
token-vault compromise
audit-log leakage
configuration poisoning
policy repository compromise
supply-chain dependency risk
oversized request / DoS
Unicode/encoding evasions
cross-tenant token collision
```

---

## 15. Mandatory Security Invariants

The implementation agent MUST NOT violate these.

### INV-001

Policy action comes from deterministic code.

### INV-002

Laya output is evidence, not permission.

### INV-003

Known secrets are not forwarded to the target model.

### INV-004

Known secrets are not included in ordinary logs.

### INV-005

System prompts contain no operational credentials.

### INV-006

The target LLM does not own authorization decisions.

### INV-007

Token-vault mapping is inaccessible to the target LLM.

### INV-008

High-risk Laya failure cannot silently become allow.

### INV-009

Tool credentials do not enter model context.

### INV-010

Every enforced semantic threshold has evaluation evidence.

---

## 16. Suggested Milestones

### M0 — Skeleton

Tasks:

```text
T-001..T-004
```

Exit:

```text
working passthrough proxy
```

### M1 — Deterministic Security

Tasks:

```text
T-005..T-012
```

Exit:

```text
known secrets + PII
policy
shadow/enforce
```

### M2 — Laya Shadow

Tasks:

```text
T-013..T-017
T-028..T-030
```

Exit:

```text
Laya evaluates real/synthetic traffic
no semantic enforcement yet
baseline report exists
```

### M3 — PII Transformation

Tasks:

```text
T-018..T-023
```

Exit:

```text
tokenize/redact
outbound scan
controlled re-identification
```

### M4 — Evaluated Semantic Enforcement

Tasks:

```text
T-031..T-032
```

Exit:

```text
calibrated bounded policy slices
semantic enforcement canary
```

### M5 — Tool Security

Tasks:

```text
T-024..T-025
```

Exit:

```text
tool call/result security hooks ready
```

---

## 17. Rollout Procedure

### Step 1 — Offline

Synthetic evaluation only.

### Step 2 — Dev shadow

Run against developer traffic.

No blocking from Laya.

### Step 3 — UAT shadow

Collect:

```text
false positives
false negatives
language-route behavior
latency
Laya failures
disagreements
```

### Step 4 — Deterministic enforcement

Enable secret and validated structured-PII policies.

### Step 5 — Semantic canary

Enable one bounded rule, e.g.:

```text
credential_exfiltration
application=internal-agent
language=en/th evaluated
```

### Step 6 — Expand

Only after measured review.

---

## 18. Coding-Agent Rules

When implementing:

1. Do not make broad architectural changes without updating ADR/docs.
2. Implement one task at a time.
3. Add tests before considering task complete.
4. Never commit real secrets.
5. Never use real customer PII in fixtures.
6. Prefer synthetic generated values.
7. Preserve raw upstream behavior for `ALLOW`.
8. Keep security transformations explicit.
9. Avoid hidden magic thresholds.
10. Every threshold must be configuration/policy.
11. Every policy decision must be explainable from sanitized evidence.
12. Do not use target LLM calls to implement security classification.
13. Do not add Jev in MVP unless explicitly requested.
14. Do not fine-tune Laya in MVP.
15. Do not assume Laya confidence is calibrated by default.

---

## 19. Definition of Done for Each Task

A task is done only if:

```text
implementation complete
unit tests added
integration/golden tests added where relevant
no known secret leakage
docs/config updated
lint passes
tests pass
observability added where relevant
```

---

## 20. First Agent Execution Prompt

Use the following instruction to start implementation:

```text
Implement Milestone M0 only from implement.handoff.md.

Read spec.md and architecture.md first.

Do not implement Laya yet.
Do not add PII tokenization yet.
Do not add speculative features.

Deliver:
- repository scaffold
- core domain models
- OpenAI-compatible /v1/chat/completions parser/proxy
- configurable mock/upstream forwarding
- health/readiness endpoints
- unit + integration tests
- docker compose for gateway + mock upstream
- README run instructions

Preserve the security invariants in implement.handoff.md.
At completion, report:
1. files changed,
2. tests run,
3. test results,
4. design decisions,
5. open risks,
6. exact next task.
```

Then continue milestone-by-milestone.

---

## 21. Recommended First Production Experiment

Do not begin production validation with prompt injection.

Start with the easiest measurable categories:

```text
1. known secret detection
2. Thai citizen ID
3. phone/email
4. shadow Laya credential-exfiltration
5. shadow Laya system-prompt extraction
6. shadow Laya prompt injection
```

This gives deterministic controls early while gathering evidence for semantic enforcement.

---

## 22. Laya Operational Notes

Based on current Laya documentation:

- use `Router` for mixed/non-English traffic,
- preload checkpoints for a server deployment,
- use the local HTTP service when isolating ML runtime is useful,
- track checkpoint/question versions,
- use the evaluation harness,
- treat thresholds as application policy,
- use held-out data for calibration,
- use staged adoption,
- retain explicit fallback/review boundaries.

Do not encode a static universal confidence threshold into the source code.

---

## 23. Final Target

The desired final flow is:

```text
Agent / Application
        |
        v
LLM Security Gateway
        |
        +--> deterministic scan
        +--> PII span detection
        +--> local Laya semantic evidence
        +--> deterministic policy
        +--> tokenize/redact/block
        |
        v
Existing LLM Gateway
        |
        v
Model
        |
        v
LLM Security Gateway
        |
        +--> output scan
        +--> policy
        |
        v
Client
```

Future:

```text
tool call
   |
   v
Tool Security Gateway
   |
   v
Credential Broker
   |
   v
Vault / Workload Identity
```

That future phase must preserve the same fundamental rule:

> The model requests a capability. Infrastructure holds and applies the credential.
