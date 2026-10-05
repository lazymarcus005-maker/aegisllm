package policy

import (
	"testing"

	"github.com/aegisllm/gateway/internal/core"
)

const validPolicy = `
id: enterprise-default
version: 1
owner: security-team
effective_date: "2026-10-05"
default:
  action: allow
secrets:
  GITLAB_PAT:
    action: block
  JWT:
    action: block
`

func mustLoad(t *testing.T, doc string) *Policy {
	t.Helper()
	p, err := Load([]byte(doc))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}

func TestLoadValidPolicy(t *testing.T) {
	p := mustLoad(t, validPolicy)
	if p.ID != "enterprise-default" || p.Version != 1 {
		t.Fatalf("identity fields wrong: %+v", p)
	}
	if len(p.Secrets) != 2 || p.Secrets["GITLAB_PAT"].Action != core.ActionBlock {
		t.Fatalf("secrets rules wrong: %+v", p.Secrets)
	}
}

func TestLoadInvalidPolicies(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"malformed yaml", "id: [unclosed"},
		{"missing id", "version: 1\ndefault:\n  action: allow\n"},
		{"version zero", "id: p\nversion: 0\ndefault:\n  action: allow\n"},
		{"unknown default action", "id: p\nversion: 1\ndefault:\n  action: deny_everything\n"},
		{"unknown secret action", "id: p\nversion: 1\ndefault:\n  action: allow\nsecrets:\n  JWT:\n    action: maybe\n"},
		{"unknown field rejected", "id: p\nversion: 1\ndefault:\n  action: allow\nmystery:\n  nope: true\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load([]byte(tc.doc)); err == nil {
				t.Fatal("expected load error")
			}
		})
	}
}

func secretFinding(subtype string) core.SecurityFinding {
	return core.SecurityFinding{
		ID: "finding-1", Category: core.CategorySecret, Subtype: subtype,
		Detector: "pattern", Confidence: 1.0,
		Location: core.Span{MessageIndex: 0, PartIndex: 0, Start: 0, End: 5},
	}
}

func TestEngineBlocksOnSecretRule(t *testing.T) {
	e := NewEngine(mustLoad(t, validPolicy))
	dec := e.Evaluate(Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-1"},
		Findings: []core.SecurityFinding{secretFinding("GITLAB_PAT")},
	})
	if dec.Action != core.ActionBlock {
		t.Fatalf("action: %s", dec.Action)
	}
	if dec.Code != "SECRET_DETECTED" {
		t.Fatalf("code: %s", dec.Code)
	}
	if dec.MatchedRule != "secrets.GITLAB_PAT" {
		t.Fatalf("rule: %s", dec.MatchedRule)
	}
	if dec.PolicyVersion != 1 || dec.PolicyID != "enterprise-default" {
		t.Fatalf("policy identity missing: %+v", dec)
	}
}

func TestEngineDefaultsToAllowOnClean(t *testing.T) {
	e := NewEngine(mustLoad(t, validPolicy))
	dec := e.Evaluate(Context{Envelope: &core.InspectionEnvelope{RequestID: "req-1"}})
	if dec.Action != core.ActionAllow || dec.MatchedRule != "default" {
		t.Fatalf("decision: %+v", dec)
	}
}

func TestEngineUnknownSecretSubtypeFallsToDefault(t *testing.T) {
	e := NewEngine(mustLoad(t, validPolicy))
	dec := e.Evaluate(Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-1"},
		Findings: []core.SecurityFinding{secretFinding("SOME_UNKNOWN_SECRET")},
	})
	if dec.Action != core.ActionAllow {
		t.Fatalf("unknown subtype must fall through to default, got %s", dec.Action)
	}
}

func TestEngineDeterministicRepeats(t *testing.T) {
	e := NewEngine(mustLoad(t, validPolicy))
	ctx := Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-1", Target: core.Target{Provider: "cloud"}},
		Findings: []core.SecurityFinding{secretFinding("JWT"), secretFinding("GITLAB_PAT")},
	}
	first := e.Evaluate(ctx)
	for i := 0; i < 5; i++ {
		again := e.Evaluate(ctx)
		if again != first {
			t.Fatalf("non-deterministic decision:\n first %+v\n again %+v", first, again)
		}
	}
}

// --- ticket 03: full precedence chain ---

func piiFinding(subtype string) core.SecurityFinding {
	return core.SecurityFinding{
		ID: "finding-2", Category: core.CategoryPII, Subtype: subtype,
		Detector: "pattern", Confidence: 1.0,
		Location: core.Span{MessageIndex: 0, PartIndex: 0, Start: 0, End: 5},
	}
}

func mustLoadFile(t *testing.T) *Policy {
	t.Helper()
	p, err := LoadFile("../../policies/enterprise-default.yaml")
	if err != nil {
		t.Fatalf("load enterprise-default: %v", err)
	}
	return p
}

func TestExplicitDenyBeatsEverything(t *testing.T) {
	doc := `
id: p
version: 1
default:
  action: allow
deny:
  - when_application: rogue-app
    action: block
secrets:
  GITLAB_PAT:
    action: block
`
	e := NewEngine(mustLoad(t, doc))
	dec := e.Evaluate(Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-1", Application: "rogue-app"},
		Findings: []core.SecurityFinding{secretFinding("GITLAB_PAT")},
	})
	if dec.Action != core.ActionBlock || dec.MatchedRule != "deny[0]" {
		t.Fatalf("deny must win: %+v", dec)
	}
}

func TestSecretBlockBeatsPIITokenize(t *testing.T) {
	e := NewEngine(mustLoadFile(t))
	dec := e.Evaluate(Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-1", Target: core.Target{Provider: "cloud"}},
		Findings: []core.SecurityFinding{piiFinding("TH_CITIZEN_ID"), secretFinding("GITLAB_PAT")},
	})
	if dec.Action != core.ActionBlock || dec.MatchedRule != "secrets.GITLAB_PAT" {
		t.Fatalf("spec §7 example (secret > PII) violated: %+v", dec)
	}
}

func TestTenantRestrictionBeatsProviderBoundary(t *testing.T) {
	doc := `
id: p
version: 1
default:
  action: allow
tenants:
  suspended-tenant:
    action: block
targets:
  cloud:
    confidential_data: tokenize
`
	e := NewEngine(mustLoad(t, doc))
	dec := e.Evaluate(Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-1", Tenant: "suspended-tenant", Target: core.Target{Provider: "cloud"}},
		Findings: []core.SecurityFinding{piiFinding("PHONE_NUMBER")},
	})
	if dec.Action != core.ActionBlock || dec.MatchedRule != "tenants.suspended-tenant" {
		t.Fatalf("tenant restriction must win: %+v", dec)
	}
}

func TestProviderBoundaryAppliesToUnconfiguredPIISubtype(t *testing.T) {
	e := NewEngine(mustLoadFile(t))
	dec := e.Evaluate(Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-1", Target: core.Target{Provider: "cloud"}},
		Findings: []core.SecurityFinding{piiFinding("EMAIL")},
	})
	if dec.Action != core.ActionTokenize || dec.MatchedRule != "targets.cloud" {
		t.Fatalf("provider baseline must apply: %+v", dec)
	}
}

func TestPIISubtypeRuleOverridesProviderBaseline(t *testing.T) {
	e := NewEngine(mustLoadFile(t))
	// AS-002: Thai citizen ID to cloud is tokenized.
	cloud := e.Evaluate(Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-1", Target: core.Target{Provider: "cloud"}},
		Findings: []core.SecurityFinding{piiFinding("TH_CITIZEN_ID")},
	})
	if cloud.Action != core.ActionTokenize || cloud.MatchedRule != "pii.TH_CITIZEN_ID.cloud" {
		t.Fatalf("AS-002 violated: %+v", cloud)
	}
	// UC-003: governed PII to a local model is allowed.
	local := e.Evaluate(Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-2", Application: "approved-internal", Target: core.Target{Provider: "local"}},
		Findings: []core.SecurityFinding{piiFinding("TH_CITIZEN_ID")},
	})
	if local.Action != core.ActionAllow || local.MatchedRule != "pii.TH_CITIZEN_ID.local" {
		t.Fatalf("UC-003 violated: %+v", local)
	}
}

func TestRoleRestriction(t *testing.T) {
	doc := `
id: p
version: 1
default:
  action: allow
roles:
  intern:
    action: review
`
	e := NewEngine(mustLoad(t, doc))
	dec := e.Evaluate(Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-1", User: core.User{Roles: []string{"developer", "intern"}}},
	})
	if dec.Action != core.ActionReview || dec.MatchedRule != "roles.intern" {
		t.Fatalf("role restriction: %+v", dec)
	}
}

func TestSemanticRulesByRisk(t *testing.T) {
	e := NewEngine(mustLoadFile(t))
	hi := e.Evaluate(Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-1"},
		Semantic: []SemanticSignal{{QuestionID: "prompt_injection", Triggered: true, Risk: "high", Confidence: 0.94}},
	})
	if hi.Action != core.ActionBlock || hi.Code != "PROMPT_INJECTION_RISK" {
		t.Fatalf("semantic high: %+v", hi)
	}
	med := e.Evaluate(Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-2"},
		Semantic: []SemanticSignal{{QuestionID: "prompt_injection", Triggered: true, Risk: "medium", Confidence: 0.6}},
	})
	if med.Action != core.ActionRestrictTools {
		t.Fatalf("semantic medium: %+v", med)
	}
}

func TestSemanticSeverityMaxAcrossQuestions(t *testing.T) {
	e := NewEngine(mustLoadFile(t))
	dec := e.Evaluate(Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-1"},
		Semantic: []SemanticSignal{
			{QuestionID: "prompt_injection", Triggered: true, Risk: "medium"},
			{QuestionID: "credential_exfiltration", Triggered: true, Risk: "high"},
		},
	})
	if dec.Action != core.ActionBlock || dec.MatchedRule != "semantic.credential_exfiltration.high" {
		t.Fatalf("severity max violated: %+v", dec)
	}
}

func TestSemanticNotTriggeredIgnored(t *testing.T) {
	e := NewEngine(mustLoadFile(t))
	dec := e.Evaluate(Context{
		Envelope: &core.InspectionEnvelope{RequestID: "req-1"},
		Semantic: []SemanticSignal{{QuestionID: "prompt_injection", Triggered: false, Risk: "high"}},
	})
	if dec.Action != core.ActionAllow {
		t.Fatalf("untriggered signal must not fire: %+v", dec)
	}
}

func TestValidationExtendedSchema(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"deny rule without matcher", "id: p\nversion: 1\ndefault:\n  action: allow\ndeny:\n  - action: block\n"},
		{"deny rule without action", "id: p\nversion: 1\ndefault:\n  action: allow\ndeny:\n  - when_tenant: t\n"},
		{"missing default", "id: p\nversion: 1\n"},
		{"semantic without levels", "id: p\nversion: 1\ndefault:\n  action: allow\nsemantic:\n  prompt_injection: {}\n"},
		{"invalid fallback low_risk", "id: p\nversion: 1\ndefault:\n  action: allow\nfallback:\n  laya_unavailable:\n    low_risk: banana\n"},
		{"pii without providers", "id: p\nversion: 1\ndefault:\n  action: allow\npii:\n  EMAIL: {}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load([]byte(tc.doc)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestFullPolicyFileLoads(t *testing.T) {
	p := mustLoadFile(t)
	if p.Version != 2 {
		t.Fatalf("version: %d", p.Version)
	}
	if len(p.Semantic) == 0 || len(p.PII) == 0 || len(p.Targets) != 2 {
		t.Fatalf("extended sections missing: %+v", p)
	}
}
