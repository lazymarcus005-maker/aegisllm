package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/policy"
)

// languageOf classifies text into the calibrated language slices.
func languageOf(text string) string {
	var thai, latin int
	for _, r := range text {
		switch {
		case r >= 0x0E00 && r <= 0x0E7F:
			thai++
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			latin++
		}
	}
	switch {
	case thai > 0 && latin > 0:
		return "mixed"
	case thai > 0:
		return "th"
	default:
		return "en"
	}
}

// gateSignals admits only evaluated threshold slices whose confidence clears
// the fitted threshold. Without a threshold policy, semantic evidence cannot
// enforce.
func (p *SecurityPipeline) gateSignals(env *core.InspectionEnvelope, signals []policy.SemanticSignal, evidence decision.DecisionEvidence) []policy.SemanticSignal {
	if p.thresholds == nil {
		return nil
	}
	subject, _ := semanticSubject(env)
	lang := languageOf(subject)
	var gated []policy.SemanticSignal
	for _, sig := range signals {
		if !sig.Triggered {
			continue
		}
		rec, ok := p.thresholds.Match(sig.QuestionID, lang, env.Application, evidence.Provider)
		if !ok || !rec.Evaluated || sig.Confidence < rec.MinConfidence {
			continue
		}
		gated = append(gated, sig)
	}
	return gated
}

func lastUserText(env *core.InspectionEnvelope) string {
	for i := len(env.Messages) - 1; i >= 0; i-- {
		if env.Messages[i].Role != core.RoleUser {
			continue
		}
		for _, part := range env.Messages[i].Parts {
			if part.Type == core.PartText && part.Text != "" {
				return part.Text
			}
		}
	}
	return ""
}

// semanticSubject selects the payload appropriate to a boundary direction.
func semanticSubject(env *core.InspectionEnvelope) (string, core.Role) {
	if env.Direction == core.DirectionRequest {
		return lastUserText(env), core.RoleUser
	}
	for i := len(env.Messages) - 1; i >= 0; i-- {
		for _, part := range env.Messages[i].Parts {
			if part.Type == core.PartText && part.Text != "" {
				return part.Text, env.Messages[i].Role
			}
		}
	}
	return "", ""
}

// semanticStage consults the provider only when deterministic policy did not
// already produce a definitive block.
func (p *SecurityPipeline) semanticStage(ins *inspection) {
	env := ins.env
	layaStart := time.Now()
	evidence, signals, plan, err := p.evaluateSemantic(env, ins.findings)
	ins.layaMS = time.Since(layaStart).Milliseconds()
	if err != nil || evidence != nil {
		ins.laya = &audit.LayaInfo{}
		p.recorder.ObserveLaya(float64(ins.layaMS), err != nil)
	}
	if err != nil {
		ins.laya.Error = "unavailable"
		if plan.Ask && plan.MaxRisk == "high" {
			if fb, ok := p.engine.LayaUnavailableFallback(); ok {
				ins.dec = fb
				p.recorder.ObserveFallback()
			}
		}
		return
	}
	if evidence == nil {
		return
	}
	ins.laya = layaAuditInfo(evidence)
	switch {
	case p.mode == ModeShadow:
		ins.dec = p.engine.Evaluate(policy.Context{Envelope: env, Findings: ins.findings, Semantic: signals})
	case p.semanticEnforce:
		if gated := p.gateSignals(env, signals, *evidence); len(gated) > 0 {
			ins.dec = p.engine.Evaluate(policy.Context{Envelope: env, Findings: ins.findings, Semantic: gated})
		}
	}
}

func (p *SecurityPipeline) evaluateSemantic(env *core.InspectionEnvelope, findings []core.SecurityFinding) (*decision.DecisionEvidence, []policy.SemanticSignal, decision.Plan, error) {
	plan := p.planner.Plan(env.Direction, env.Application, env.Target, findings)
	if !plan.Ask {
		return nil, nil, plan, nil
	}
	content, role := semanticSubject(env)
	if content == "" {
		return nil, nil, plan, nil
	}
	req := decision.DecisionRequest{
		RequestID: env.RequestID, Direction: strings.ToLower(string(env.Direction)),
		Role: string(role), Content: content, Application: env.Application,
	}
	evidence, err := p.provider.Evaluate(context.Background(), req, plan.QuestionIDs)
	if err != nil {
		return nil, nil, plan, err
	}
	var signals []policy.SemanticSignal
	for _, id := range plan.QuestionIDs {
		d, ok := evidence.Decisions[id]
		if !ok {
			continue
		}
		signals = append(signals, policy.SemanticSignal{
			QuestionID: id, Triggered: d.Value, Confidence: d.Confidence, Risk: p.questions.RiskOf(id),
		})
	}
	return &evidence, signals, plan, nil
}

func layaAuditInfo(ev *decision.DecisionEvidence) *audit.LayaInfo {
	info := &audit.LayaInfo{Provider: ev.Provider, Checkpoint: ev.Checkpoint, SchemaVersion: ev.SchemaVersion, Route: ev.Route}
	for id, d := range ev.Decisions {
		if info.Decisions == nil {
			info.Decisions = map[string]audit.LayaDecision{}
		}
		info.Decisions[id] = audit.LayaDecision{Value: d.Value, Confidence: d.Confidence}
	}
	return info
}
