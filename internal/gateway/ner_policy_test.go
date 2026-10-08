package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
)

type outageNER struct{}

func (outageNER) Name() string                  { return "outage-ner" }
func (outageNER) Spans(string) []pii.EntitySpan { return nil }
func (outageNER) SpansContext(context.Context, string) ([]pii.EntitySpan, error) {
	return nil, errors.New("provider unavailable")
}

func nerTestPipeline(t *testing.T, required bool) (*SecurityPipeline, *bytesBufferSink) {
	t.Helper()
	sink := &bytesBufferSink{}
	pol := &policy.Policy{ID: "ner-test", Version: 1, Default: policy.ActionRule{Action: core.ActionAllow}, SafeDefault: policy.ActionRule{Action: core.ActionBlock}, CategoryActions: map[string]policy.ActionRule{string(core.CategoryPII): {Action: core.ActionRedact}}}
	pipe := NewSecurityPipeline(detectors.NewRegistry(nil), policy.NewEngine(pol), sink)
	pipe.SetSecurityMode(ModeEnforce)
	pipe.SetSpanPolicy(required)
	pipe.SetSpanProvider(pii.NewCompositeSpanProvider(pii.NewRegexSpanProvider(), outageNER{}))
	return pipe, sink
}

func TestStrictNEROutageFailsClosed(t *testing.T) {
	pipe, _ := nerTestPipeline(t, true)
	env := &core.InspectionEnvelope{RequestID: "strict", Direction: core.DirectionRequest, Target: core.Target{Provider: "cloud"}, Messages: []core.Message{{Role: core.RoleUser, Parts: []core.ContentPart{{Type: core.PartText, Text: "hello"}}}}}
	dec, err := pipe.ProcessRequest(env, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != core.ActionBlock || dec.Code != "PII_NER_UNAVAILABLE" {
		t.Fatalf("strict outage: %+v", dec)
	}
}

func TestBalancedNEROutageKeepsDeterministicFindingsAndAuditsFallback(t *testing.T) {
	sink := &bytesBufferSink{}
	pol := &policy.Policy{ID: "ner-test", Version: 1, Default: policy.ActionRule{Action: core.ActionAllow}, SafeDefault: policy.ActionRule{Action: core.ActionBlock}, CategoryActions: map[string]policy.ActionRule{string(core.CategoryPII): {Action: core.ActionRedact}}}
	pipe := NewSecurityPipeline(detectors.NewRegistry(nil), policy.NewEngine(pol), sink)
	pipe.SetSecurityMode(ModeEnforce)
	pipe.SetSpanPolicy(false)
	pipe.SetSpanProvider(pii.NewCompositeSpanProvider(pii.NewRegexSpanProvider(), outageNER{}))
	env := &core.InspectionEnvelope{RequestID: "balanced", Direction: core.DirectionRequest, Target: core.Target{Provider: "cloud"}, Messages: []core.Message{{Role: core.RoleUser, Parts: []core.ContentPart{{Type: core.PartText, Text: "นายสมชาย"}}}}}
	dec, err := pipe.ProcessRequest(env, []byte("นายสมชาย"))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Action != core.ActionRedact {
		t.Fatalf("balanced outage: %+v", dec)
	}
	if !strings.Contains(sink.String(), `"pii_fallback":true`) {
		t.Fatalf("fallback was not audited: %s", sink.String())
	}
}
