package gateway

import (
	"context"
	"time"
	"unicode/utf8"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
)

// inspection is the shared result of one request, response, tool-call, or
// tool-result boundary inspection.
type inspection struct {
	env            *core.InspectionEnvelope
	findings       []core.SecurityFinding
	dec            policy.Decision
	explanation    policy.Explanation
	laya           *audit.LayaInfo
	layaMS         int64
	detMS          int64
	piiFallback    bool
	piiUnavailable bool
	start          time.Time
}

// inspect is the single four-boundary inspection routine: deterministic scan,
// span detection, policy evaluation, optional semantics, and metrics.
func (p *SecurityPipeline) inspect(env *core.InspectionEnvelope) *inspection {
	return p.inspectContext(context.Background(), env)
}

func (p *SecurityPipeline) inspectContext(ctx context.Context, env *core.InspectionEnvelope) *inspection {
	ins := &inspection{env: env, start: time.Now()}
	scanStart := time.Now()
	findings := p.registry.RunAll(env)
	p.recorder.ObserveScanner(float64(time.Since(scanStart).Microseconds()) / 1000.0)
	entityFindings, entityErr, fallback := p.entityFindings(ctx, env)
	ins.piiFallback = fallback
	ins.piiUnavailable = entityErr != nil
	ins.findings = append(append([]core.SecurityFinding{}, findings...), entityFindings...)
	seenTypes := map[string]bool{}
	for _, f := range ins.findings {
		key := string(f.Category) + "/" + f.Subtype
		if !seenTypes[key] {
			seenTypes[key] = true
			p.recorder.ObserveFindings(string(f.Category), f.Subtype)
		}
	}
	ins.explanation = p.engine.Explain(policy.Context{Envelope: env, Findings: ins.findings})
	ins.dec = ins.explanation.Decision
	if entityErr != nil && p.spanRequired {
		ins.dec = policy.Decision{Action: core.ActionBlock, PolicyID: p.engine.Policy().ID, PolicyVersion: p.engine.Policy().Version,
			MatchedRule: "pii_ner_required", PrecedenceStage: policy.StageFallback, Code: "PII_NER_UNAVAILABLE",
			Reason: "required local PII recognizer unavailable"}
		ins.explanation.Decision = ins.dec
	}
	if env.Metadata["passthrough"] == "true" {
		ins.dec.Action = core.ActionAllow
		ins.dec.Code = ""
		ins.dec.MatchedRule = "passthrough"
		ins.dec.PrecedenceStage = "system_passthrough"
		ins.dec.Reason = "body-free endpoint was explicitly marked passthrough"
	}
	ins.explanation.Decision = ins.dec
	ins.detMS = time.Since(ins.start).Milliseconds()
	if p.provider != nil && p.planner != nil && ins.dec.Action != core.ActionBlock {
		p.semanticStage(ctx, ins)
	}
	p.recorder.ObserveSecurityLatency(float64(ins.detMS))
	if env.Direction == core.DirectionRequest {
		p.recorder.ObserveRequest(ins.dec.Action, p.mode)
	}
	if p.mode == ModeShadow {
		p.recorder.ObserveShadowDisagreement(ins.dec.Action)
		if ins.dec.Action == core.ActionBlock || ins.dec.Action == core.ActionReview {
			hasDeterministic := false
			for _, f := range ins.findings {
				if f.Category == core.CategorySecret || f.Category == core.CategoryPII {
					hasDeterministic = true
					break
				}
			}
			if !hasDeterministic {
				p.recorder.ObserveFalsePositiveSample()
			}
		}
	}
	return ins
}

func (p *SecurityPipeline) auditEvent(ins *inspection) audit.Event {
	latency := map[string]int64{"deterministic": ins.detMS, "total_security": time.Since(ins.start).Milliseconds()}
	if ins.layaMS > 0 {
		latency["laya"] = ins.layaMS
	}
	stream := ins.env.Metadata["stream"] == "true"
	applied := ins.dec.Action
	if p.mode != ModeEnforce {
		applied = core.ActionAllow
	}
	event := audit.Event{
		RequestID: ins.env.RequestID, Timestamp: time.Now().UTC(), Direction: ins.env.Direction,
		Application: ins.env.Application, Tenant: ins.env.Tenant, User: ins.env.User.Subject,
		Roles: append([]string(nil), ins.env.User.Roles...), Provider: ins.env.Target.Provider,
		PolicyID: ins.dec.PolicyID, PolicyVersion: ins.dec.PolicyVersion, Mode: p.mode,
		Action: ins.dec.Action,
		Code:   ins.dec.Code, MatchedRule: ins.dec.MatchedRule,
		PrecedenceStage: string(ins.dec.PrecedenceStage), Reason: ins.dec.Reason,
		FindingTypes: audit.FindingTypes(ins.findings), FindingCount: len(ins.findings), FindingSummary: ins.explanation.Findings,
		LatencyMS: latency, Laya: ins.laya,
		PIIFallback: ins.piiFallback, PIIUnavailable: ins.piiUnavailable,
	}
	if stream {
		event.PredictedAction = ins.dec.Action
		event.AppliedAction = applied
		event.Stream = true
		event.EndpointFamily = ins.env.Metadata["endpoint_family"]
		event.BytesInspected = inspectedBytes(ins.env)
		event.EventsInspected = 1
	}
	return event
}

func inspectedBytes(env *core.InspectionEnvelope) int64 {
	var n int64
	for _, part := range env.TextParts() {
		n += int64(len(part.Text))
	}
	return n
}

func (p *SecurityPipeline) entityFindings(ctx context.Context, env *core.InspectionEnvelope) ([]core.SecurityFinding, error, bool) {
	if p.spans == nil {
		return nil, nil, false
	}
	var out []core.SecurityFinding
	for _, lt := range env.TextParts() {
		var spans []pii.EntitySpan
		var err error
		if provider, ok := p.spans.(pii.ContextSpanProvider); ok {
			spans, err = provider.SpansContext(ctx, lt.Text)
		} else {
			spans = p.spans.Spans(lt.Text)
		}
		if err != nil {
			if p.spanRequired {
				return out, err, false
			}
		}
		for _, es := range spans {
			if es.Start < 0 || es.End <= es.Start || es.End > len(lt.Text) || !utf8.ValidString(lt.Text[es.Start:es.End]) {
				continue
			}
			out = append(out, core.SecurityFinding{
				Category: core.CategoryPII, Subtype: es.Label, Detector: p.spans.Name(), Confidence: es.Confidence,
				Location: core.Span{MessageIndex: lt.MessageIndex, PartIndex: lt.PartIndex, Start: es.Start, End: es.End},
			})
		}
		if err != nil {
			return out, nil, true
		}
	}
	return out, nil, false
}

// ToolCall is a model-emitted tool call offered for inspection.
type ToolCall struct {
	ID        string
	Name      string
	Arguments string
}

// ToolResult is a tool result offered for inspection before it re-enters model context.
type ToolResult struct {
	CallID  string
	Name    string
	Content string
}

// ToolDecision is the policy outcome for one tool inspection.
type ToolDecision struct {
	Action             core.Action
	Code               string
	PolicyID           string
	PolicyVersion      int
	PrecedenceStage    string
	MatchedRule        string
	Reason             string
	TransformedContent string
}

// InspectToolCall applies the shared inspection routine before tool execution.
func (p *SecurityPipeline) InspectToolCall(reqEnv *core.InspectionEnvelope, call ToolCall) (ToolDecision, error) {
	if p.mode == ModeOff {
		return ToolDecision{Action: core.ActionAllow}, nil
	}
	env := toolEnvelope(reqEnv, core.DirectionToolCall, call.Name, call.Arguments)
	ins := p.inspect(env)
	out := ToolDecision{Action: ins.dec.Action, Code: ins.dec.Code, PolicyID: ins.dec.PolicyID, PolicyVersion: ins.dec.PolicyVersion, PrecedenceStage: string(ins.dec.PrecedenceStage), MatchedRule: ins.dec.MatchedRule, Reason: ins.dec.Reason}
	if ins.dec.Action == core.ActionRedact || ins.dec.Action == core.ActionTokenize {
		out.TransformedContent = pii.ApplyToText(call.Arguments, pii.Plan(ins.findings, pii.RedactNamer))
	}
	p.audit.Record(p.auditEvent(ins))
	return out, nil
}

// InspectToolResult applies the shared inspection routine before model re-entry.
func (p *SecurityPipeline) InspectToolResult(reqEnv *core.InspectionEnvelope, result ToolResult) (ToolDecision, error) {
	if p.mode == ModeOff {
		return ToolDecision{Action: core.ActionAllow}, nil
	}
	env := toolEnvelope(reqEnv, core.DirectionToolResult, result.Name, result.Content)
	ins := p.inspect(env)
	out := ToolDecision{Action: ins.dec.Action, Code: ins.dec.Code, PolicyID: ins.dec.PolicyID, PolicyVersion: ins.dec.PolicyVersion, PrecedenceStage: string(ins.dec.PrecedenceStage), MatchedRule: ins.dec.MatchedRule, Reason: ins.dec.Reason}
	if ins.dec.Action == core.ActionRedact || ins.dec.Action == core.ActionTokenize {
		out.TransformedContent = pii.ApplyToText(result.Content, pii.Plan(ins.findings, pii.RedactNamer))
	}
	p.audit.Record(p.auditEvent(ins))
	return out, nil
}

func toolEnvelope(reqEnv *core.InspectionEnvelope, dir core.Direction, toolName, content string) *core.InspectionEnvelope {
	return &core.InspectionEnvelope{
		RequestID: reqEnv.RequestID, Direction: dir, Application: reqEnv.Application, Tenant: reqEnv.Tenant,
		User: reqEnv.User, Target: reqEnv.Target,
		Messages: []core.Message{{Role: core.RoleAssistant, Parts: []core.ContentPart{{Type: core.PartText, ToolName: toolName, Text: content}}}},
	}
}
