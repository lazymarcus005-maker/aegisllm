package gateway

import (
	"context"
	"fmt"
	"math"
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
func (p *SecurityPipeline) semanticStage(ctx context.Context, ins *inspection) {
	env := ins.env
	layaStart := time.Now()
	evidence, signals, plan, err := p.evaluateSemantic(ctx, env, ins.findings)
	ins.layaMS = time.Since(layaStart).Milliseconds()
	if err != nil || evidence != nil {
		ins.laya = &audit.LayaInfo{}
		if evidence != nil {
			ins.laya = layaAuditInfo(evidence, p.questions)
		}
		p.recorder.ObserveLaya(float64(ins.layaMS), err != nil)
	}
	if err != nil {
		if ins.laya.Error == "" {
			ins.laya.Error = "unavailable"
			if evidence != nil {
				ins.laya.Error = "rejected"
			}
		}
		if plan.Ask {
			provider := ""
			if p.provider != nil {
				provider = p.provider.Name()
			}
			var fb policy.Decision
			var ok bool
			if evidence == nil {
				// Preserve the established outage contract and its stable audit
				// code. Evidence-shape failures use the new reasoned matrix.
				if plan.MaxRisk == "high" {
					fb, ok = p.engine.LayaUnavailableFallback()
				}
			} else {
				fb, ok = p.engine.SemanticFallback(plan.MaxRisk, strings.ToLower(string(env.Direction)), provider, err.Error())
			}
			if ok {
				ins.dec = fb
				ins.explanation.Decision = fb
				if evidence == nil {
					p.recorder.ObserveFallbackReason("provider")
				} else {
					p.recorder.ObserveFallbackReason("semantic_evidence_rejected")
				}
			}
		}
		return
	}
	if evidence == nil {
		return
	}
	ins.laya = layaAuditInfo(evidence, p.questions)
	switch {
	case p.mode == ModeShadow:
		ins.explanation = p.engine.Explain(policy.Context{Envelope: env, Findings: ins.findings, Semantic: signals})
		ins.dec = ins.explanation.Decision
	case p.semanticEnforce:
		if gated := p.gateSignals(env, signals, *evidence); len(gated) > 0 {
			ins.explanation = p.engine.Explain(policy.Context{Envelope: env, Findings: ins.findings, Semantic: gated})
			ins.dec = ins.explanation.Decision
		}
	}
}

func (p *SecurityPipeline) evaluateSemantic(ctx context.Context, env *core.InspectionEnvelope, findings []core.SecurityFinding) (*decision.DecisionEvidence, []policy.SemanticSignal, decision.Plan, error) {
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
	evidence, err := p.provider.Evaluate(ctx, req, plan.QuestionIDs)
	if err != nil {
		return nil, nil, plan, err
	}
	if err := p.validateEvidence(evidence, plan.QuestionIDs); err != nil {
		return &evidence, nil, plan, err
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

func (p *SecurityPipeline) validateEvidence(evidence decision.DecisionEvidence, required []string) error {
	if strings.TrimSpace(evidence.Provider) == "" || strings.EqualFold(evidence.Provider, "noop") {
		p.recorder.ObserveSemanticRejected("provider")
		return fmt.Errorf("semantic provider is missing or noop")
	}
	if p.questions == nil {
		p.recorder.ObserveSemanticRejected("schema")
		return fmt.Errorf("question schema is not loaded")
	}
	if evidence.SchemaVersion != p.questions.Schema {
		p.recorder.ObserveSchemaMismatch()
		return fmt.Errorf("semantic schema mismatch")
	}
	if p.thresholds != nil && p.thresholds.QuestionSchema != "" && p.thresholds.QuestionSchema != "legacy" {
		if evidence.SchemaVersion != p.thresholds.QuestionSchemaID {
			p.recorder.ObserveSchemaMismatch()
			return fmt.Errorf("semantic schema mismatch")
		}
		if p.thresholds.Checkpoint != "" && evidence.Checkpoint != p.thresholds.Checkpoint {
			p.recorder.ObserveCheckpointMismatch()
			return fmt.Errorf("semantic checkpoint mismatch")
		}
		if p.thresholds.Provider != "" && p.thresholds.Provider != "legacy" && !strings.EqualFold(evidence.Provider, p.thresholds.Provider) {
			p.recorder.ObserveSemanticRejected("provider")
			return fmt.Errorf("semantic provider mismatch")
		}
	}
	wanted := make(map[string]bool, len(required))
	for _, id := range required {
		wanted[id] = true
	}
	for id := range evidence.Decisions {
		if !wanted[id] {
			p.recorder.ObserveSemanticRejected("unknown_question")
			return fmt.Errorf("semantic evidence contains unknown question")
		}
	}
	for _, id := range required {
		d, ok := evidence.Decisions[id]
		if !ok {
			p.recorder.ObserveMissingDecision()
			return fmt.Errorf("semantic evidence is missing a required decision")
		}
		if math.IsNaN(d.Confidence) || math.IsInf(d.Confidence, 0) || d.Confidence < 0 || d.Confidence > 1 {
			p.recorder.ObserveSemanticRejected("confidence")
			return fmt.Errorf("semantic evidence confidence is out of range")
		}
	}
	return nil
}

func layaAuditInfo(ev *decision.DecisionEvidence, schema *decision.QuestionSchema) *audit.LayaInfo {
	info := &audit.LayaInfo{Provider: safeSemanticMetadata(ev.Provider), Checkpoint: safeSemanticMetadata(ev.Checkpoint), SchemaVersion: safeSemanticMetadata(ev.SchemaVersion), Route: safeSemanticMetadata(ev.Route)}
	for id, d := range ev.Decisions {
		if schema == nil || schema.RiskOf(id) == "" {
			continue
		}
		if math.IsNaN(d.Confidence) || math.IsInf(d.Confidence, 0) || d.Confidence < 0 || d.Confidence > 1 {
			continue
		}
		if info.Decisions == nil {
			info.Decisions = map[string]audit.LayaDecision{}
		}
		info.Decisions[id] = audit.LayaDecision{Value: d.Value, Confidence: d.Confidence}
	}
	return info
}
