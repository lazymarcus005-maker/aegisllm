package policy

import (
	"fmt"
	"testing"

	"github.com/aegisllm/gateway/internal/core"
)

func profilePolicy(t *testing.T, name string) *Policy {
	t.Helper()
	p, err := LoadFile("../../policies/" + name + ".yaml")
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return p
}

func contractFinding(category core.FindingCategory, subtype string, confidence float64) core.SecurityFinding {
	return core.SecurityFinding{Category: category, Subtype: subtype, Confidence: confidence}
}

func TestReviewedProfilesHaveExplicitEffectiveActions(t *testing.T) {
	secretSubtypes := []string{"GITLAB_PAT", "GITHUB_TOKEN", "PEM_PRIVATE_KEY", "JWT", "BEARER_TOKEN", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "SLACK_TOKEN", "GOOGLE_API_KEY", "GENERIC_API_KEY", "CONNECTION_STRING", "HIGH_ENTROPY_SECRET"}
	piiSubtypes := []string{"TH_CITIZEN_ID", "PHONE_NUMBER", "EMAIL", "CREDIT_CARD", "IP_ADDRESS"}
	for _, profile := range []string{"strict-cloud", "balanced-cloud", "trusted-local"} {
		t.Run(profile, func(t *testing.T) {
			p := profilePolicy(t, profile)
			e := NewEngine(p)
			for _, provider := range []string{"cloud", "local"} {
				for _, subtype := range secretSubtypes {
					dec := e.Evaluate(Context{Envelope: &core.InspectionEnvelope{Target: core.Target{Provider: provider}}, Findings: []core.SecurityFinding{contractFinding(core.CategorySecret, subtype, 0.5)}})
					if dec.MatchedRule == "safe_default" {
						t.Fatalf("%s/%s secret %s fell through safe default", provider, profile, subtype)
					}
				}
				for _, subtype := range piiSubtypes {
					dec := e.Evaluate(Context{Envelope: &core.InspectionEnvelope{Target: core.Target{Provider: provider}}, Findings: []core.SecurityFinding{contractFinding(core.CategoryPII, subtype, 0.5)}})
					if dec.MatchedRule == "safe_default" {
						t.Fatalf("%s/%s PII %s fell through safe default", provider, profile, subtype)
					}
				}
			}
		})
	}
}

func TestReviewedProfileGoldenActions(t *testing.T) {
	cases := []struct {
		profile, provider, category, subtype string
		confidence                           float64
		want                                 core.Action
	}{
		{"strict-cloud", "cloud", "PII", "EMAIL", 0.5, core.ActionTokenize},
		{"strict-cloud", "cloud", "SECRET", "GITLAB_PAT", 0.5, core.ActionBlock},
		{"balanced-cloud", "cloud", "PII", "EMAIL", 0.5, core.ActionTokenize},
		{"balanced-cloud", "cloud", "SECRET", "GENERIC_API_KEY", 0.5, core.ActionRedact},
		{"balanced-cloud", "cloud", "SECRET", "GENERIC_API_KEY", 0.95, core.ActionBlock},
		{"trusted-local", "local", "PII", "EMAIL", 0.5, core.ActionAllow},
		{"trusted-local", "local", "SECRET", "JWT", 0.5, core.ActionBlock},
	}
	for _, tc := range cases {
		t.Run(tc.profile+"/"+tc.provider+"/"+tc.subtype, func(t *testing.T) {
			p := profilePolicy(t, tc.profile)
			category := core.FindingCategory(tc.category)
			dec := NewEngine(p).Evaluate(Context{Envelope: &core.InspectionEnvelope{Target: core.Target{Provider: tc.provider}}, Findings: []core.SecurityFinding{contractFinding(category, tc.subtype, tc.confidence)}})
			if dec.Action != tc.want {
				t.Fatalf("action=%s want=%s decision=%+v", dec.Action, tc.want, dec)
			}
		})
	}
}

func TestConfidenceAndCountEscalationsAreDeclarative(t *testing.T) {
	p := mustLoad(t, `
id: p
version: 8
default: {action: allow}
safe_default: {action: block}
category_actions:
  SECRET: {action: redact}
  PII: {action: allow}
confidence_escalation:
  - id: secret-confidence
    category: SECRET
    min_confidence: 0.8
    action: block
finding_count_escalation:
  - id: dense-pii
    category: PII
    min_count: 2
    action: review
`)
	e := NewEngine(p)
	below := e.Evaluate(Context{Findings: []core.SecurityFinding{contractFinding(core.CategorySecret, "UNKNOWN", 0.79)}})
	above := e.Evaluate(Context{Findings: []core.SecurityFinding{contractFinding(core.CategorySecret, "UNKNOWN", 0.8)}})
	if below.Action != core.ActionRedact || above.Action != core.ActionBlock || above.MatchedRule != "confidence.secret-confidence" {
		t.Fatalf("confidence contract: below=%+v above=%+v", below, above)
	}
	count := e.Evaluate(Context{Envelope: &core.InspectionEnvelope{Target: core.Target{Provider: "local"}}, Findings: []core.SecurityFinding{contractFinding(core.CategoryPII, "EMAIL", 1), contractFinding(core.CategoryPII, "PHONE_NUMBER", 1)}})
	if count.Action != core.ActionReview || count.MatchedRule != "count.dense-pii" {
		t.Fatalf("count contract: %+v", count)
	}
}

func TestChangingYAMLActionChangesDecision(t *testing.T) {
	base := `
id: p
version: 8
default: {action: allow}
safe_default: {action: block}
subtype_actions:
  SECRET:
    DEMO: %s
`
	redact := NewEngine(mustLoad(t, fmtPolicy(base, "redact"))).Evaluate(Context{Findings: []core.SecurityFinding{contractFinding(core.CategorySecret, "DEMO", 0.5)}})
	block := NewEngine(mustLoad(t, fmtPolicy(base, "block"))).Evaluate(Context{Findings: []core.SecurityFinding{contractFinding(core.CategorySecret, "DEMO", 0.5)}})
	if redact.Action != core.ActionRedact || block.Action != core.ActionBlock {
		t.Fatalf("YAML action did not control decision: redact=%+v block=%+v", redact, block)
	}
}

func TestEffectiveContractRejectsUnknownFieldsAndRanges(t *testing.T) {
	cases := []string{
		"id: p\nversion: 8\ndefault: {action: allow}\nsafe_default: {action: block, typo: true}\n",
		"id: p\nversion: 8\ndefault: {action: allow}\nsafe_default: {action: block}\nconfidence_escalation:\n  - id: x\n    category: SECRET\n    min_confidence: 1.1\n    action: block\n",
		"id: p\nversion: 8\ndefault: {action: allow}\nsafe_default: {action: block}\nfinding_count_escalation:\n  - id: x\n    category: PII\n    min_count: 0\n    action: review\n",
	}
	for i, doc := range cases {
		if _, err := Load([]byte(doc)); err == nil {
			t.Fatalf("case %d unexpectedly loaded", i)
		}
	}
}

func fmtPolicy(format, action string) string {
	return fmt.Sprintf(format, action)
}
