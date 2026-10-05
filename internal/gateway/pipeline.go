package gateway

import (
	"time"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/policy"
)

// SecurityPipeline is the production Pipeline: deterministic detection feeds
// the deterministic policy engine, and every run produces a sanitized audit
// event (ticket 02). Laya evidence joins later without changing this shape.
type SecurityPipeline struct {
	registry *detectors.Registry
	engine   *policy.Engine
	audit    audit.Sink
	mode     string
}

func NewSecurityPipeline(registry *detectors.Registry, engine *policy.Engine, sink audit.Sink, mode string) *SecurityPipeline {
	return &SecurityPipeline{registry: registry, engine: engine, audit: sink, mode: mode}
}

// ProcessRequest runs the deterministic path. In shadow mode the predicted
// action is returned and audited, but the server keeps the incumbent path
// (FR-018). In off mode no inspection happens at all.
func (p *SecurityPipeline) ProcessRequest(env *core.InspectionEnvelope, raw []byte) (RequestDecision, error) {
	if p.mode == ModeOff {
		return RequestDecision{Action: core.ActionAllow}, nil
	}

	start := time.Now()
	findings := p.registry.RunAll(env)
	dec := p.engine.Evaluate(policy.Context{Envelope: env, Findings: findings})
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
		FindingTypes:  audit.FindingTypes(findings),
		FindingCount:  len(findings),
		LatencyMS: map[string]int64{
			"deterministic":  elapsed.Milliseconds(),
			"total_security": elapsed.Milliseconds(),
		},
	})

	return RequestDecision{Action: dec.Action, Code: dec.Code}, nil
}
