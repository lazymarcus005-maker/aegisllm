# Policy authoring and effective-policy contract

Policies are versioned YAML and are loaded with strict known-field validation.
The gateway and `cmd/policytool` use the same `internal/policy.Engine`; the
CLI is a simulator, not a second enforcement implementation.

## Contract

The existing v7 sections (`secrets`, `pii`, `targets`, `roles`, and
`semantic`) remain valid. New policies should use the additive effective
contract:

```yaml
id: example
version: 8
owner: security-team
effective_date: "2026-10-07"
default: {action: allow}       # clean traffic
safe_default: {action: block}  # an unconfigured finding or boundary

category_actions:
  SECRET: {action: redact}
  PII: {action: redact}
subtype_actions:
  SECRET:
    GITLAB_PAT: block
  PII:
    EMAIL: redact
provider_overrides:
  cloud:
    categories:
      PII: {action: tokenize}
    subtypes:
      TH_CITIZEN_ID: {action: tokenize}
confidence_escalation:
  - id: high-confidence-secret
    category: SECRET
    min_confidence: 0.90
    action: block
finding_count_escalation:
  - id: multiple-pii
    category: PII
    min_count: 3
    action: review
```

Actions are `allow`, `block`, `redact`, `tokenize`, `review`,
`restrict_tools`, and `force_local_model`. Thresholds must be within `[0,1]`
and counts must be positive. Every rule has a stable identifier; duplicate
escalation IDs and unknown fields/actions fail policy load.

For a finding, the engine resolves provider subtype, provider category,
global subtype, global category, then `safe_default`. Matching confidence and
count escalation rules are considered at the same finding stage, with the
more severe action winning and stable rule ID breaking ties. The overall
precedence remains explicit deny, secret protection, tenant/application,
identity/role, provider boundary, PII transformation, semantic risk, and
clean-traffic default.

The effective result is sanitized to category, subtype, count, confidence
bucket, matched rule, precedence stage, action, code, and reason. Raw values,
value hashes, exact detector confidence, request text, and credentials are not
part of the explanation or audit API.

## Reviewed profiles

| Profile | Cloud PII | Local PII | Secrets | Fallback |
| --- | --- | --- | --- | --- |
| `strict-cloud.yaml` | tokenize; dense payload review | redact | high-risk/block, lower-risk redact | block |
| `balanced-cloud.yaml` | tokenize; dense payload review | allow; dense payload review | high-risk/block, lower-risk redact | block |
| `trusted-local.yaml` | tokenize | allow; dense payload review | block | block |

Use strict-cloud for a cloud-only production boundary, balanced-cloud after a
shadow/UAT review, and trusted-local only when the local provider is isolated,
authenticated, and governed. All profiles explicitly cover the registered
secret and PII detector subtypes for both provider classes; their `safe_default`
still blocks future or unknown finding classes.

## Migration from v7/default

The v7 enterprise policy continues to load. Its legacy sections are normalized
at load time into the effective contract, including `MULTIPLE_PII` as a
three-finding count rule and `targets` as provider category rules. The shipped
enterprise policy also declares `safe_default`, category/subtype actions, and
the high-confidence secret threshold, while retaining the v7 sections for
stable rule IDs and a non-breaking rollout.

To migrate a tenant:

1. Copy the policy and increment `version`.
2. Move any subtype actions into `subtype_actions` and boundary rules into
   `provider_overrides`.
3. Declare `safe_default`, confidence rules, and count rules explicitly.
4. Run `policytool validate` and `policytool explain` with synthetic or
   redacted request fixtures, then deploy in shadow mode.

## CLI and endpoint

Request content is supplied by file or stdin, never a command argument:

```bash
go run ./cmd/policytool validate -policy policies/strict-cloud.yaml
go run ./cmd/policytool effective -policy policies/strict-cloud.yaml
cat redacted-request.json | go run ./cmd/policytool explain \
  -policy policies/strict-cloud.yaml -request - -provider cloud
```

`GET /api/effective-policy` is operator-authenticated (`aegis.operator`) and
returns policy identity plus a sanitized rule summary. It does not expose the
loaded YAML, credentials, or request data. The endpoint is useful for runtime
attestation; the CLI remains suitable for offline review.

