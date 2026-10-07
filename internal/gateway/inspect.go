package gateway

import (
	"time"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
)

// inspection is the shared result of one request, response, tool-call, or
// tool-result boundary inspection.
type inspection struct {
	env      *core.InspectionEnvelope
	findings []core.SecurityFinding
	dec      policy.Decision
	laya     *audit.LayaInfo
	layaMS   int64
	detMS    int64
	start    time.Time
}

// inspect is the single four-boundary inspection routine: deterministic scan,
// span detection, policy evaluation, optional semantics, and metrics.
func (p *SecurityPipeline) inspect(env *core.InspectionEnvelope) *inspection {
	ins := &inspection{env: env, start: time.Now()}
	scanStart := time.Now()
	findings := p.registry.RunAll(env)
	p.recorder.ObserveScanner(float64(time.Since(scanStart).Microseconds()) / 1000.0)
	ins.findings = append(append([]core.SecurityFinding{}, findings...), p.entityFindings(env)...)
	seenTypes := map[string]bool{}
	for _, f := range ins.findings {
		key := string(f.Category) + "/" + f.Subtype
		if !seenTypes[key] {
			seenTypes[key] = true
			p.recorder.ObserveFindings(string(f.Category), f.Subtype)
		}
	}
	ins.dec = p.engine.Evaluate(policy.Context{Envelope: env, Findings: ins.findings})
	if env.Metadata["passthrough"] == "true" || env.Metadata["skipped_stream"] == "true" {
		ins.dec.Action = core.ActionAllow
		ins.dec.Code = ""
		ins.dec.MatchedRule = "passthrough"
		if env.Metadata["skipped_stream"] == "true" {
			ins.dec.Code = "SKIPPED_STREAM"
			ins.dec.MatchedRule = "skipped_stream"
		}
	}
	ins.detMS = time.Since(ins.start).Milliseconds()
	if p.provider != nil && p.planner != nil && ins.dec.Action != core.ActionBlock {
		p.semanticStage(ins)
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
	return audit.Event{
		RequestID: ins.env.RequestID, Timestamp: time.Now().UTC(), Direction: ins.env.Direction,
		Application: ins.env.Application, Tenant: ins.env.Tenant, User: ins.env.User.Subject,
		Roles: append([]string(nil), ins.env.User.Roles...), Provider: ins.env.Target.Provider,
		PolicyID: ins.dec.PolicyID, PolicyVersion: ins.dec.PolicyVersion, Mode: p.mode,
		Action: ins.dec.Action, Code: ins.dec.Code, MatchedRule: ins.dec.MatchedRule,
		FindingTypes: audit.FindingTypes(ins.findings), FindingCount: len(ins.findings),
		LatencyMS: latency, Laya: ins.laya,
	}
}

func (p *SecurityPipeline) entityFindings(env *core.InspectionEnvelope) []core.SecurityFinding {
	if p.spans == nil {
		return nil
	}
	var out []core.SecurityFinding
	for _, lt := range env.TextParts() {
		for _, es := range p.spans.Spans(lt.Text) {
			out = append(out, core.SecurityFinding{
				Category: core.CategoryPII, Subtype: es.Label, Detector: p.spans.Name(), Confidence: es.Confidence,
				Location: core.Span{MessageIndex: lt.MessageIndex, PartIndex: lt.PartIndex, Start: es.Start, End: es.End},
			})
		}
	}
	return out
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
	out := ToolDecision{Action: ins.dec.Action, Code: ins.dec.Code, MatchedRule: ins.dec.MatchedRule, Reason: ins.dec.Reason}
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
	out := ToolDecision{Action: ins.dec.Action, Code: ins.dec.Code, MatchedRule: ins.dec.MatchedRule, Reason: ins.dec.Reason}
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
