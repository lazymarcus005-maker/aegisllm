# Laya LLM Security Gateway — Architecture

**Status:** Proposed  
**Version:** 0.1  
**Primary decision model:** Laya  
**Primary integration style:** OpenAI-compatible reverse-proxy / middleware  
**Security model:** Deterministic enforcement + Laya semantic decision signals  
**Deployment target:** Local / on-prem first, cloud-compatible  
**Languages:** Thai, English, mixed-language traffic

---

## 1. Purpose

This system is a pluggable security layer positioned in front of an existing LLM Gateway. Its purpose is to prevent or reduce:

- PII leakage into or out of LLMs.
- Secret and credential leakage.
- Prompt injection and jailbreak attempts.
- System-prompt extraction attempts.
- Credential/data exfiltration intent.
- Unsafe tool calls and unsafe tool results.
- Unauthorized sensitive-data retrieval.
- Sensitive data leaking into logs, traces, or model training datasets.

The system is deliberately **not** an LLM safety prompt. It is an application security control outside the target LLM.

The core design principle is:

> Deterministic code enforces policy. Laya contributes semantic classification and risk signals. The LLM being protected never gets authority to override security policy.

This follows the OWASP recommendation that strict security controls should be enforced independently from the LLM and that system prompts should not contain credentials or be treated as a security boundary.

---

## 2. Architecture Goals

### 2.1 Goals

1. Plug into an existing LLM Gateway without requiring application changes where possible.
2. Support OpenAI-compatible APIs first.
3. Protect all four major LLM data boundaries:
   - inbound request,
   - tool call,
   - tool result,
   - outbound model response.
4. Detect known secrets deterministically.
5. Detect PII using deterministic rules and entity/span detection.
6. Use Laya for semantic decisions that regex cannot reliably make.
7. Keep raw enterprise data local by default.
8. Support Thai, English, and mixed-language traffic.
9. Support shadow mode before enforcement.
10. Keep policies versioned and testable as code.
11. Provide auditable decisions without logging raw secrets.
12. Keep Laya replaceable through a decision-provider abstraction.
13. Fail safely when scanners or Laya are unavailable.
14. Keep latency low enough for inline use.
15. Support future MCP/tool credential brokering without redesigning the gateway.

### 2.2 Non-goals for V1

- Full enterprise DLP replacement.
- Full IAM system.
- Full SIEM.
- Autonomous incident response.
- Storing or distributing application secrets.
- Replacing Vault, cloud secret managers, or workload identity.
- Training/fine-tuning Laya in the first release.
- Guaranteed prevention of every prompt-injection technique.
- Re-identifying PII inside Laya itself.
- Letting Laya directly execute actions.

---

## 3. External Context

Laya is a local, non-autoregressive System 1 decision engine that supports typed decisions such as:

- `choice`
- `score`
- `noul`

Its current documentation describes:

- multilingual routing,
- local/self-hosted inference,
- HTTP serving through `laya-serve`,
- confidence-related outputs,
- an evaluation harness,
- staged adoption,
- guardrail use cases,
- LangChain/LangGraph integration.

For this project, Laya is used as a **semantic decision service**, not as a policy authority.

---

## 4. Top-Level Architecture

```mermaid
flowchart LR
    A[Application / Agent] --> B[LLM Security Gateway]
    B --> C[Existing LLM Gateway]
    C --> D1[Local LLM]
    C --> D2[Cloud LLM]
    C --> D3[Other Provider]

    B --> E[Deterministic Scanner]
    B --> F[PII Span Detector]
    B --> G[Laya Decision Service]
    B --> H[Policy Engine]
    B --> I[Tokenization Service]
    B --> J[Audit / Metrics]

    H --> K{Decision}
    K -->|allow| C
    K -->|redact| C
    K -->|tokenize| C
    K -->|block| L[Security Response]
    K -->|review| M[Review / Fallback]
```

Recommended request path:

```text
Client
  |
  v
LLM Security Gateway
  |
  +--> normalize request
  |
  +--> deterministic secret/PII scan
  |
  +--> PII entity/span detection
  |
  +--> invoke Laya only when semantic evidence is useful
  |
  +--> deterministic policy evaluation
  |
  +--> allow / tokenize / redact / block / review
  |
  v
Existing LLM Gateway
  |
  v
Target LLM
```

---

## 5. Trust Boundaries

### TB-1: Client → Security Gateway

Input is untrusted.

Possible threats:

- PII submission.
- Secret submission.
- Prompt injection.
- oversized payloads.
- malformed OpenAI messages.
- malicious tool definitions.
- encoded/obfuscated secrets.

### TB-2: Security Gateway → Laya

Laya is trusted as a classifier but **not as an enforcement authority**.

Raw content may be sent to Laya because Laya runs locally. The gateway must still minimize data where possible.

### TB-3: Security Gateway → LLM Gateway

Only policy-approved or sanitized data crosses this boundary.

### TB-4: LLM Gateway → External Provider

This is a higher-risk boundary for cloud providers.

Policy can vary by target:

```text
local model -> raw confidential data may be allowed by policy
cloud model -> tokenize PII / block restricted data
```

### TB-5: Tool Runtime / MCP

Tool credentials must remain outside model context.

The security gateway inspects tool intent and content, but actual credentials belong to a separate tool runtime / credential broker.

---

## 6. Core Components

### 6.1 Gateway Adapter

Responsibilities:

- expose OpenAI-compatible endpoints,
- parse request structures,
- preserve provider-compatible semantics,
- normalize messages into internal inspection objects,
- reconstruct safe provider requests,
- scan streaming and non-streaming responses.

Initial endpoints:

```text
POST /v1/chat/completions
POST /v1/responses
GET  /health
GET  /ready
GET  /metrics
```

Later:

```text
Anthropic native Messages API
MCP traffic
custom agent protocol
```

---

### 6.2 Request Normalizer

Converts provider-specific data into:

```text
InspectionEnvelope
```

Conceptual structure:

```json
{
  "request_id": "req-...",
  "direction": "request",
  "application": "claude-code",
  "tenant": "engineering",
  "user": {
    "subject": "user-123",
    "roles": ["developer"]
  },
  "target": {
    "provider": "local",
    "model": "qwen..."
  },
  "content": [],
  "tools": [],
  "metadata": {}
}
```

The normalizer must distinguish:

- system/developer/user/assistant messages,
- text,
- image references,
- tool definitions,
- tool calls,
- tool results,
- structured JSON arguments.

---

### 6.3 Deterministic Scanner

This is the first security layer.

It handles cases where a deterministic detector is more reliable than an ML model.

#### Secret categories

Examples:

- PEM private keys.
- GitLab PAT.
- GitHub tokens.
- AWS keys.
- API keys with known prefixes.
- JWT.
- bearer tokens.
- passwords in structured config.
- database connection strings.
- service-account credentials.
- SSH keys.
- certificate private material.

Detection techniques:

```text
known prefix
+ regex
+ entropy
+ contextual keyword
+ structure validation
```

#### PII categories

Initial Thai/enterprise set:

- Thai citizen ID + checksum.
- telephone number.
- email.
- account number patterns.
- credit-card number + Luhn.
- IP address.
- device identifier where policy classifies it as PII.
- customer/member identifier.
- HN / patient identifier, if healthcare profile enabled.

The scanner emits findings, never policy actions directly.

Example:

```json
{
  "detector": "thai-citizen-id",
  "type": "PII",
  "subtype": "TH_CITIZEN_ID",
  "start": 127,
  "end": 140,
  "confidence": 1.0
}
```

---

### 6.4 PII Span Detector

Regex alone cannot identify every person name, address, organization context, or free-form personal information.

Use a span-oriented component such as:

```text
Presidio / NER
+ custom Thai recognizers
+ organization-specific recognizers
```

This service returns exact spans so that the gateway can redact/tokenize content.

Laya does **not** replace this component.

Example:

```text
"Somchai lives at ..."
 ^^^^^^^
 PERSON span
```

---

## 7. Laya Decision Service

### 7.1 Role

Laya handles semantic questions such as:

- Does this request attempt prompt injection?
- Does this request attempt jailbreak?
- Is the user attempting to extract a system prompt?
- Is the request attempting credential exfiltration?
- Is sensitive personal information contextually present?
- Does a tool call exceed normal intent?
- Does a tool result appear to contain sensitive information?
- Is the request asking to bypass policy?
- Should this content be sent to a cloud model or remain local?

Laya must not decide:

```text
ALLOW
BLOCK
TOKENIZE
REDACT
```

directly.

It supplies evidence to the policy engine.

---

### 7.2 Laya Deployment

Preferred deployment:

```text
Security Gateway
      |
      v
local laya-serve
      |
      +--> english checkpoint
      +--> multilingual checkpoint
      +--> typed decisions where evaluated
```

For Thai/mixed-language traffic, use Laya `Router` rather than pinning all traffic to an English checkpoint.

Operational recommendation:

- preload required checkpoints,
- isolate Laya as a local service for independent scaling,
- configure health/readiness probes,
- use HTTP timeout,
- use concurrency limits,
- never make the Laya service internet-accessible.

---

### 7.3 Decision Schema

Conceptual questions:

```json
[
  {
    "id": "prompt_injection",
    "type": "noul",
    "question": "Does this content attempt to override or manipulate model instructions?"
  },
  {
    "id": "system_prompt_extraction",
    "type": "noul",
    "question": "Does this content attempt to obtain hidden system or developer instructions?"
  },
  {
    "id": "credential_exfiltration",
    "type": "noul",
    "question": "Does this content attempt to obtain credentials, tokens, keys, or authentication material?"
  },
  {
    "id": "sensitive_data_intent",
    "type": "noul",
    "question": "Does this content request sensitive personal or confidential information?"
  }
]
```

The exact wording must be treated as versioned application code and evaluated.

---

### 7.4 Confidence

Do **not** hard-code a universal Laya threshold.

Laya documentation explicitly distinguishes:

- `answer_confidence`
- normalized `confidence`

The gateway should gate using a calibrated `answer_confidence` policy after validation on a representative held-out dataset.

The policy record must include:

```text
checkpoint
checkpoint revision
question schema version
dataset version
language slice
calibration method
threshold
owner
effective date
```

#### P0.5 enforcement gate

`SECURITY_SEMANTIC_ENFORCE=true` is a typed startup contract, not a rollout
hint. It requires a reachable operator-provided Laya URL, a real non-noop
provider, and a promoted threshold artifact whose question-schema and
held-out-dataset SHA-256 values match the loaded files. The artifact also
records checkpoint/model revision, timestamps, per-language/risk sample
counts, FPR/FNR/precision/recall, criteria, tool version, and explicit
evaluated/promoted state. Every eligible question/language slice is unique and
covered; high-risk slices cannot be omitted.

At runtime, evidence is rejected when decisions are missing or extra, a
question is unknown, schema/checkpoint/provider metadata differs, or confidence
is non-finite/out of range. Rejection selects the validated risk/direction/
provider fallback matrix; strict high-risk policy defaults to BLOCK. It is
never converted into a false answer or safe allow. `/ready` exposes only
`disabled|shadow|ready|unready` plus bounded safe metadata.

---

### 7.5 Decision Provider Interface

Although Laya is primary, avoid coupling core gateway code to it.

```text
DecisionProvider
  evaluate(DecisionRequest) -> DecisionEvidence
```

Implementations:

```text
LayaProvider       # V1 default
NoopProvider       # tests / bypass
JevProvider        # future optional
```

This allows Jev or another classifier later without changing policy semantics.

---

## 8. Policy Engine

The Policy Engine is authoritative.

Input:

```text
request metadata
identity/role
target provider
deterministic findings
PII spans
Laya evidence
deployment mode
policy version
```

Output:

```text
ALLOW
REDACT
TOKENIZE
BLOCK
REVIEW
RESTRICT_TOOLS
FORCE_LOCAL_MODEL
```

Example:

```yaml
version: enterprise-v1

secrets:
  PRIVATE_KEY:
    action: block
  GITLAB_PAT:
    action: block
  JWT:
    action: block

pii:
  TH_CITIZEN_ID:
    cloud:
      action: tokenize
    local:
      action: allow
  PHONE_NUMBER:
    cloud:
      action: tokenize

semantic:
  credential_exfiltration:
    high:
      action: block
  prompt_injection:
    high:
      action: block
    medium:
      action: restrict_tools
```

Policy evaluation must be deterministic and unit-testable.

---

## 9. Tokenization / Re-identification

Example:

```text
Before:
นายสมชาย ใจดี เลขบัตร 1234567890123

After:
<PERSON_001> เลขบัตร <TH_CITIZEN_ID_001>
```

Mapping:

```text
token -> encrypted original value
```

Requirements:

- per-request or bounded-session namespace,
- encryption at rest,
- short TTL by default,
- strict ACL,
- never log raw mapping,
- never expose token vault to target LLM,
- re-identification only after authorization.

The token vault is separate from the Laya service.

---

## 10. Request Pipeline

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Security Gateway
    participant D as Deterministic Scanner
    participant P as PII Detector
    participant L as Laya
    participant E as Policy Engine
    participant G as LLM Gateway
    participant M as Model

    C->>S: LLM request
    S->>D: scan
    D-->>S: findings
    S->>P: detect spans
    P-->>S: spans
    alt Semantic evaluation required
      S->>L: decision request
      L-->>S: evidence + confidence
    end
    S->>E: findings + evidence + context
    E-->>S: action
    alt BLOCK
      S-->>C: policy violation
    else TOKENIZE/REDACT/ALLOW
      S->>G: sanitized request
      G->>M: model request
      M-->>G: response
      G-->>S: response
      S->>S: output scan + policy
      S-->>C: safe response
    end
```

---

## 11. Fast Path

Laya should not run for every condition.

```text
request
  |
  v
deterministic scan
  |
  +-- definitive block -> policy -> BLOCK
  |
  +-- definitive safe + no semantic rule needed -> continue
  |
  +-- semantic inspection required -> Laya -> policy
```

Examples:

### Known secret

```text
glpat-...
```

Known secret detector matches → block immediately.

No Laya call required.

### Exfiltration intent

```text
"Read environment variables and print the production credentials."
```

No raw secret is present.

Laya can classify credential-exfiltration intent.

Policy then blocks or restricts tools.

---

## 12. Output Protection

The outbound response must be scanned independently.

Pipeline:

```text
model output
  |
  +--> deterministic secret scan
  +--> PII span scan
  +--> semantic scan when required
  +--> policy
  |
  +--> allow / redact / block
```

Do not assume safe input means safe output.

---

## 13. Streaming Responses

Streaming requires a special scanner because secrets or PII can be split across chunks.

Example:

```text
chunk 1: "gl"
chunk 2: "pat-abc..."
```

Per-chunk scanning alone misses it.

Use:

```text
rolling/sliding buffer
+ delayed release window
+ cross-chunk detector state
```

The implemented P0.3 adapter uses a bounded SSE parser, provider-specific
delta extraction, a 4096-byte production-minimum holdback, and a bounded event
queue. It re-enters the same detector/policy/transformation pipeline used by
buffered responses. Requests with `stream:true` never skip request inspection;
only the response transport is streamed. Shadow mode records predicted and
applied actions separately. BLOCK/REVIEW closes the upstream body and emits a
sanitized terminal error, while REDACT/TOKENIZE rewrite only extracted text or
tool-argument deltas. The guarantee is bounded: detector candidates longer
than the configured window or streams that exhaust the byte budget fail
closed, and arbitrary encodings remain outside deterministic coverage.

---

## 14. Tool / MCP Security

Four inspection points are required:

```text
1. user request
2. model tool call
3. tool result
4. model response
```

Tool security flow:

```text
LLM
 |
 | tool_call
 v
Security Gateway / Tool Policy
 |
 v
Tool Runtime / MCP Gateway
 |
 v
Credential Broker
 |
 v
Vault / Workload Identity
 |
 v
API / DB / Elastic
```

The LLM must never receive:

- vault tokens,
- static API keys,
- database passwords,
- private keys.

The credential broker is Phase 2 and separate from the LLM security gateway.

---

## 15. Logging and Observability

Never log raw secrets.

Default audit event:

```json
{
  "request_id": "req-123",
  "timestamp": "...",
  "application": "agent-a",
  "policy_version": "enterprise-v1",
  "mode": "shadow",
  "action": "tokenize",
  "finding_types": [
    "TH_CITIZEN_ID",
    "PROMPT_INJECTION"
  ],
  "laya": {
    "checkpoint": "multilingual",
    "question_schema": "security-v1",
    "decision_ids": ["prompt_injection"],
    "answer_confidence": {
      "prompt_injection": 0.91
    }
  },
  "latency_ms": {
    "deterministic": 2,
    "pii": 8,
    "laya": 150,
    "total_security": 164
  }
}
```

Allowed:

- hashes,
- finding type,
- span count,
- policy action,
- confidence,
- model revision,
- request ID,
- latency,
- outcome.

Restricted:

- raw prompt,
- raw response,
- raw PII,
- secrets,
- token-vault mappings.

If raw samples are needed for evaluation, create a separately governed sampling path.

---

## 16. Failure Modes

### Deterministic scanner unavailable

Default: fail closed for protected routes.

### Laya unavailable

Use risk-sensitive fallback:

```text
low-risk route     -> deterministic policy only
medium/high-risk   -> review/block/fallback
```

Never silently treat Laya failure as “safe”.

### PII detector unavailable

Cloud-bound protected route: fail closed or force local model.

### Policy engine failure

Fail closed.

### Audit sink unavailable

Configurable:

- security decisions continue,
- buffer minimal sanitized events,
- alert operators.

Audit sink must not be allowed to block every request indefinitely unless compliance requires it.

---

## 17. Deployment Modes

### Mode A — Embedded

```text
App -> gateway library -> Laya local
```

Useful for prototypes.

### Mode B — Sidecar

```text
App Pod
 ├─ Application
 └─ Security Gateway Sidecar
       |
       +--> Laya sidecar/service
```

Useful for Kubernetes.

### Mode C — Central Security Gateway

```text
many apps
   |
   v
central security gateway
   |
   v
central LLM gateway
```

Recommended enterprise target.

---

## 18. Rollout

### Stage 0 — Offline evaluation

Build labelled datasets.

### Stage 1 — Shadow

```text
real traffic
  +-> normal production action remains authoritative
  +-> security gateway records predicted decision
```

No blocking.

### Stage 2 — Deterministic enforcement

Enforce:

- private keys,
- known tokens,
- known secrets,
- high-confidence structured PII where policy is explicit.

Keep Laya semantic policies in shadow.

### Stage 3 — Bounded semantic enforcement

Enable evaluated slices only:

```text
language
application
question schema
risk class
target provider
```

### Stage 4 — Full supported production scope

Maintain:

- canary,
- rollback,
- sampling,
- periodic evaluation.

This follows Laya's documented staged-adoption model: Laya returns decision evidence; the application controls execution, thresholds, fallback, and rollback.

---

## 19. Security Principles

1. No secret in a system prompt.
2. No secret in Laya questions.
3. No secret in audit logs.
4. LLM never authorizes itself.
5. Laya never authorizes itself.
6. Policy is code.
7. Identity and authorization are checked outside models.
8. Retrieval ACLs execute before RAG retrieval.
9. Credentials are injected only in tool/runtime boundaries.
10. Cloud-model policy is stricter than local-model policy by default.
11. Raw PII is minimized.
12. Detection and enforcement are separate components.
13. Every semantic threshold must be measured.
14. High-confidence model output is evidence, not permission.

---

## 20. Recommended Initial Technology Shape

Suggested stack, not a hard requirement:

```text
Gateway:       Go / .NET / Python FastAPI
Policy:        YAML + typed compiler + deterministic evaluator
Secret scan:   native rules + entropy + checksums
PII spans:     Presidio + custom Thai recognizers / NER
Laya:          local laya-serve
Token vault:   Redis or DB + envelope encryption + TTL
Metrics:       Prometheus/OpenTelemetry
Audit:         structured sanitized events
Packaging:     container images
Deployment:    Docker Compose first, Kubernetes later
```

If low latency and enterprise service operation are priorities, use a compiled gateway runtime (Go or .NET) and keep Laya as a Python inference service.

---

## 21. Future Architecture

```text
AI Security Platform
|
+-- LLM Security Gateway
|   +-- PII
|   +-- Secret scanning
|   +-- Prompt security
|   +-- Output security
|
+-- Tool / MCP Security Gateway
|   +-- tool authorization
|   +-- schema validation
|   +-- tool-result DLP
|
+-- Credential Broker
|   +-- Vault
|   +-- workload identity
|   +-- short-lived credentials
|
+-- Evaluation Platform
|   +-- labelled datasets
|   +-- Laya evaluation
|   +-- regression gates
|
+-- Policy Repository
    +-- versioning
    +-- MR review
    +-- testing
```

---

## 22. Architecture Decision Records to Create During Implementation

- ADR-001: Central reverse proxy vs sidecar.
- ADR-002: Gateway implementation language.
- ADR-003: PII span engine.
- ADR-004: Token vault implementation.
- ADR-005: Fail-open/fail-closed matrix.
- ADR-006: Laya deployment topology.
- ADR-007: Streaming security strategy.
- ADR-008: Audit retention.
- ADR-009: Policy language/schema.
- ADR-010: MCP/tool gateway boundary.

---

## 23. References

- Laya documentation: https://nandhakishorm.github.io/laya/
- Laya staged adoption: https://nandhakishorm.github.io/laya/staged-adoption/
- Laya evaluation harness: https://nandhakishorm.github.io/laya/evals/
- Laya benchmarks/limits: https://nandhakishorm.github.io/laya/benchmarks/
- Laya HTTP API: https://github.com/NandhaKishorM/laya/blob/main/docs/http-api.md
- Laya GitHub: https://github.com/NandhaKishorM/laya
- OWASP LLM02: Sensitive Information Disclosure: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/
- OWASP LLM07: System Prompt Leakage: https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/
# P0.7 encrypted service links and rotation

All outbound HTTPS and `rediss://` links are constructed through
`internal/securetransport`. It combines system trust with an optional
dependency-specific CA bundle, enforces TLS 1.2 or newer, verifies the server
name, and optionally presents a client certificate. The inbound listener uses
the same reloadable certificate material and can require a client CA. A
trusted-edge termination mode is an explicit production contract; it does not
disable verification on dependency links.

Mounted certificates, JWT public keys, credentials, and vault keyrings are
polled with bounded intervals and replaced atomically. The active value is
kept on malformed replacement. Readiness and metrics expose only generation,
reload timestamps, bounded failure state, and certificate expiry. Vault
envelopes carry an opaque key ID and version; the active key seals new values
while retained previous keys decrypt existing values. The default keyring
reload policy refuses removal of a retained key until an operator explicitly
proves expiry and enables the controlled removal flag.

## MCP gateway boundary

MCP requests enter through the authenticated `/mcp/{server}` route. A strict
versioned registry selects the HTTPS endpoint, allowed methods/tools, schema
limits, transport TLS, and opaque credential profile. The gateway fetches and
sanitizes `tools/list`, removes policy-restricted tools, validates arguments,
then calls `InspectToolCall` before acquiring credentials and opening the tool
execution request. Results, including bounded SSE data, pass through
`InspectToolResult` before re-entry. Sessions are keyed by an opaque random ID
but bound in memory to the verified tenant/application/subject and server.
Registry and secure-material reloads publish only validated candidates.
