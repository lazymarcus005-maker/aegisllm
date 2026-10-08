package gateway

import (
	"context"
	"testing"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/policy"
)

type malformedEvidenceProvider struct{ evidence decision.DecisionEvidence }

func (p malformedEvidenceProvider) Name() string { return "fake" }
func (p malformedEvidenceProvider) Evaluate(context.Context, decision.DecisionRequest, []string) (decision.DecisionEvidence, error) {
	return p.evidence, nil
}

func TestSemanticEvidenceBindingRejectsMissingAndMismatchedAnswers(t *testing.T) {
	pipe, _ := newRealPipeline(t)
	qs := &decision.QuestionSchema{Schema: "security-v1", Version: 1, Questions: []decision.Question{{ID: "prompt_injection", Version: 1, Type: "noul", Question: "injection", Directions: []string{"request"}, Risk: "high"}}}
	pipe.SetDecisionProvider(malformedEvidenceProvider{evidence: decision.DecisionEvidence{Provider: "fake", Checkpoint: "wrong", SchemaVersion: "security-v1", Decisions: map[string]decision.Decision{}}}, qs)
	pipe.SetSemanticThresholds(&policy.SemanticThresholds{QuestionSchema: "security-v1", QuestionSchemaID: "security-v1", Checkpoint: "expected", Provider: "fake"})
	_, _, _, err := pipe.evaluateSemantic(context.Background(), requestEnvelopeForGate(), nil)
	if err == nil {
		t.Fatal("missing decision and checkpoint mismatch accepted")
	}

	pipe.SetDecisionProvider(malformedEvidenceProvider{evidence: decision.DecisionEvidence{Provider: "fake", Checkpoint: "expected", SchemaVersion: "security-v1", Decisions: map[string]decision.Decision{"prompt_injection": {Value: true, Confidence: 1.5}}}}, qs)
	_, _, _, err = pipe.evaluateSemantic(context.Background(), requestEnvelopeForGate(), nil)
	if err == nil {
		t.Fatal("out-of-range confidence accepted")
	}
}

func requestEnvelopeForGate() *core.InspectionEnvelope {
	return &core.InspectionEnvelope{RequestID: "gate-test", Direction: core.DirectionRequest, Messages: []core.Message{{Role: core.RoleUser, Parts: []core.ContentPart{{Type: core.PartText, Text: "hello"}}}}}
}
