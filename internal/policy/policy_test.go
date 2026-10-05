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
		{"unknown field rejected", "id: p\nversion: 1\ndefault:\n  action: allow\nsemantic:\n  prompt_injection:\n    high:\n      action: block\n"},
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
