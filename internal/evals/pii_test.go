package evals

import (
	"context"
	"strings"
	"testing"

	"github.com/aegisllm/gateway/internal/pii"
)

type evalFake struct{}

func (evalFake) Name() string { return "fake" }
func (evalFake) SpansContext(_ context.Context, text string) ([]pii.EntitySpan, error) {
	i := strings.Index(text, "Somchai")
	if i < 0 {
		return nil, nil
	}
	return []pii.EntitySpan{{Label: "PERSON", Start: i, End: i + 7, Confidence: .91}}, nil
}

func TestPIIEvaluationDeterministicAndNonProductionMarked(t *testing.T) {
	examples := []PIIExample{{ID: "x", Language: "en", Text: "Mr Somchai", Spans: []LabeledSpan{{Entity: "PERSON", Start: 3, End: 10}}}}
	a, err := EvaluatePII(context.Background(), examples, evalFake{}, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EvaluatePII(context.Background(), examples, evalFake{}, false)
	if err != nil {
		t.Fatal(err)
	}
	ja, _ := MarshalPIIReport(a)
	jb, _ := MarshalPIIReport(b)
	if string(ja) != string(jb) {
		t.Fatal("evaluation JSON must be deterministic")
	}
	if strings.Contains(RenderPIIMarkdown(a), "Mr Somchai") || !strings.Contains(RenderPIIMarkdown(a), "NON-PRODUCTION") {
		t.Fatal("report leaked text or missed non-production marker")
	}
}
