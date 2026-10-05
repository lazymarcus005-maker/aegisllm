package gateway

import (
	"time"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
)

// SecurityPipeline is the production Pipeline: deterministic detection and
// span detection feed the deterministic policy engine, transformations apply
// per policy, and every run produces a sanitized audit event (tickets 02-06).
type SecurityPipeline struct {
	registry *detectors.Registry
	engine   *policy.Engine
	spans    pii.SpanProvider
	audit    audit.Sink
	mode     string
}

func NewSecurityPipeline(registry *detectors.Registry, engine *policy.Engine, sink audit.Sink, mode string) *SecurityPipeline {
	return &SecurityPipeline{registry: registry, engine: engine, audit: sink, mode: mode}
}

// SetSpanProvider attaches span-oriented PII detection (ticket 05).
func (p *SecurityPipeline) SetSpanProvider(sp pii.SpanProvider) { p.spans = sp }

// ProcessRequest runs the deterministic path. In shadow mode the predicted
// action is returned and audited, but the server keeps the incumbent path
// (FR-018). In off mode no inspection happens at all.
func (p *SecurityPipeline) ProcessRequest(env *core.InspectionEnvelope, raw []byte) (RequestDecision, error) {
	if p.mode == ModeOff {
		return RequestDecision{Action: core.ActionAllow}, nil
	}

	start := time.Now()
	findings := p.registry.RunAll(env)
	entityFindings := p.entityFindings(env)
	all := append(append([]core.SecurityFinding{}, findings...), entityFindings...)
	dec := p.engine.Evaluate(policy.Context{Envelope: env, Findings: all})

	var transformed []byte
	if dec.Action == core.ActionRedact || dec.Action == core.ActionTokenize {
		plan := pii.Plan(all, pii.RedactNamer)
		body, err := applyTransformationsToBody(raw, plan)
		if err != nil {
			return RequestDecision{}, err
		}
		transformed = body
	}
	elapsed := time.Since(start)

	p.audit.Record(audit.Event{
		RequestID:     env.RequestID,
		Timestamp:     time.Now().UTC(),
		Direction:     env.Direction,
		Application:   env.Application,
		Tenant:        env.Tenant,
		User:          env.User.Subject,
		PolicyID:      dec.PolicyID,
		PolicyVersion: dec.PolicyVersion,
		Mode:          p.mode,
		Action:        dec.Action,
		Code:          dec.Code,
		MatchedRule:   dec.MatchedRule,
		FindingTypes:  audit.FindingTypes(all),
		FindingCount:  len(all),
		LatencyMS: map[string]int64{
			"deterministic":  elapsed.Milliseconds(),
			"total_security": elapsed.Milliseconds(),
		},
	})

	return RequestDecision{Action: dec.Action, Code: dec.Code, TransformedBody: transformed}, nil
}

// entityFindings runs the span provider over every text part and projects the
// recognized entities into PII findings with exact spans.
func (p *SecurityPipeline) entityFindings(env *core.InspectionEnvelope) []core.SecurityFinding {
	if p.spans == nil {
		return nil
	}
	var out []core.SecurityFinding
	for _, lt := range env.TextParts() {
		for _, es := range p.spans.Spans(lt.Text) {
			out = append(out, core.SecurityFinding{
				Category:   core.CategoryPII,
				Subtype:    es.Label,
				Detector:   p.spans.Name(),
				Confidence: es.Confidence,
				Location: core.Span{
					MessageIndex: lt.MessageIndex,
					PartIndex:    lt.PartIndex,
					Start:        es.Start,
					End:          es.End,
				},
			})
		}
	}
	return out
}
