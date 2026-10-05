package gateway

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/decision"
	"github.com/aegisllm/gateway/internal/detectors"
	"github.com/aegisllm/gateway/internal/observability"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
	"github.com/aegisllm/gateway/internal/tokenization"
)

// SecurityPipeline is the production Pipeline: deterministic detection and
// span detection feed the deterministic policy engine, transformations apply
// per policy, and every run produces a sanitized audit event (tickets 02-08).
type SecurityPipeline struct {
	registry        *detectors.Registry
	engine          *policy.Engine
	spans           pii.SpanProvider
	audit           audit.Sink
	mode            string
	vault           tokenization.Vault
	crypto          *tokenization.Crypto
	vaultTTL        time.Duration
	provider        decision.DecisionProvider
	questions       *decision.QuestionSchema
	planner         *decision.Planner
	thresholds      *policy.SemanticThresholds
	semanticEnforce bool
	recorder        observability.Recorder
}

func NewSecurityPipeline(registry *detectors.Registry, engine *policy.Engine, sink audit.Sink, mode string) *SecurityPipeline {
	return &SecurityPipeline{registry: registry, engine: engine, audit: sink, mode: mode, recorder: observability.Noop{}}
}

// SetRecorder attaches the metrics recorder (ticket 13). Never receives raw
// content — only actions, categories, and latencies.
func (p *SecurityPipeline) SetRecorder(r observability.Recorder) { p.recorder = r }

// SetSpanProvider attaches span-oriented PII detection (ticket 05).
func (p *SecurityPipeline) SetSpanProvider(sp pii.SpanProvider) { p.spans = sp }

// SetTokenStore attaches the encrypted vault used by TOKENIZE (ticket 06).
func (p *SecurityPipeline) SetTokenStore(vault tokenization.Vault, crypto *tokenization.Crypto, ttl time.Duration) {
	p.vault, p.crypto, p.vaultTTL = vault, crypto, ttl
}

// SetDecisionProvider attaches the semantic engine and question schema
// (ticket 08). Semantic evidence never enforces until calibration gates are
// met: it feeds policy in shadow only unless EnableSemanticEnforce is set
// (INV-010, rollout stage 2).
func (p *SecurityPipeline) SetDecisionProvider(dp decision.DecisionProvider, qs *decision.QuestionSchema) {
	p.provider = dp
	p.questions = qs
	p.planner = decision.NewPlanner(qs)
}

// EnableSemanticEnforce opts into semantic enforcement for calibrated slices
// (ticket 11). Default is false.
func (p *SecurityPipeline) EnableSemanticEnforce() { p.semanticEnforce = true }

// SetSemanticThresholds attaches the calibrated threshold policy (ticket 11).
// Without it, no semantic slice is eligible for enforcement.
func (p *SecurityPipeline) SetSemanticThresholds(t *policy.SemanticThresholds) { p.thresholds = t }

// languageOf classifies request text into the schema's language slices.
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

// gateSignals keeps only signals whose question has an evaluated threshold
// record matching this traffic slice AND whose confidence clears the fitted
// threshold (INV-010). Without a threshold policy nothing enforces.
func (p *SecurityPipeline) gateSignals(env *core.InspectionEnvelope, signals []policy.SemanticSignal, evidence decision.DecisionEvidence) []policy.SemanticSignal {
	if p.thresholds == nil {
		return nil
	}
	lang := languageOf(lastUserText(env))
	var gated []policy.SemanticSignal
	for _, sig := range signals {
		if !sig.Triggered {
			continue
		}
		rec, ok := p.thresholds.Match(sig.QuestionID, lang, env.Application, evidence.Provider)
		if !ok || !rec.Evaluated {
			continue // slice not evaluated: evidence only, never enforcement
		}
		if sig.Confidence < rec.MinConfidence {
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

// ProcessRequest runs the deterministic path. In shadow mode the predicted
// action is returned and audited, but the server keeps the incumbent path
// (FR-018). In off mode no inspection happens at all.
func (p *SecurityPipeline) ProcessRequest(env *core.InspectionEnvelope, raw []byte) (RequestDecision, error) {
	if p.mode == ModeOff {
		return RequestDecision{Action: core.ActionAllow}, nil
	}

	start := time.Now()
	findings := p.registry.RunAll(env)
	p.recorder.ObserveScanner(float64(time.Since(start).Microseconds()) / 1000.0)
	entityFindings := p.entityFindings(env)
	all := append(append([]core.SecurityFinding{}, findings...), entityFindings...)
	seenTypes := map[string]bool{}
	for _, f := range all {
		key := string(f.Category) + "/" + f.Subtype
		if !seenTypes[key] {
			seenTypes[key] = true
			p.recorder.ObserveFindings(string(f.Category), f.Subtype)
		}
	}
	dec := p.engine.Evaluate(policy.Context{Envelope: env, Findings: all})

	// Semantic evidence (ticket 08): called only when deterministic rules
	// did not already produce a definitive block — a known secret never
	// reaches Laya (SEC-002, NFR-PERF-004). Evidence feeds policy in shadow
	// only until semantic enforcement is explicitly enabled.
	var layaInfo *audit.LayaInfo
	var layaMS int64
	if p.provider != nil && p.planner != nil && dec.Action != core.ActionBlock {
		layaStart := time.Now()
		evidence, signals, plan, err := p.evaluateSemantic(env, all)
		layaMS = time.Since(layaStart).Milliseconds()
		// Metrics and audit record the provider only when it was actually
		// invoked — planner skips (fast path) mean laya_calls = 0 (AS-001,
		// spec §15). Errors here are provider invocation failures.
		if err != nil || evidence != nil {
			layaInfo = &audit.LayaInfo{}
			p.recorder.ObserveLaya(float64(layaMS), err != nil)
		}
		if err != nil {
			// Provider unavailable (error or open circuit): policy-controlled
			// fallback — high-risk routes never silently allow (AS-004,
			// INV-008, NFR-AVAIL-002/003).
			layaInfo.Error = "unavailable"
			if plan.Ask && plan.MaxRisk == "high" {
				if fb, ok := p.engine.LayaUnavailableFallback(); ok {
					dec = fb
					p.recorder.ObserveFallback()
				}
			}
		} else if evidence != nil {
			layaInfo = layaAuditInfo(evidence)
		}
		// Shadow predicts with all evidence; enforce acts only on gated,
		// calibrated slices (rollout stage 3, ticket 11).
		if err == nil && evidence != nil {
			switch {
			case p.mode == ModeShadow:
				dec = p.engine.Evaluate(policy.Context{Envelope: env, Findings: all, Semantic: signals})
			case p.semanticEnforce:
				if gated := p.gateSignals(env, signals, *evidence); len(gated) > 0 {
					dec = p.engine.Evaluate(policy.Context{Envelope: env, Findings: all, Semantic: gated})
				}
			}
		}
	}

	var transformed []byte
	if dec.Action == core.ActionRedact || dec.Action == core.ActionTokenize {
		namer := pii.RedactNamer
		if dec.Action == core.ActionTokenize {
			namer = pii.TokenNamer
		}
		plan := pii.Plan(all, namer)
		if dec.Action == core.ActionTokenize && p.vault != nil && p.crypto != nil {
			if err := p.storeTokenMappings(env, plan); err != nil {
				return RequestDecision{}, err
			}
		}
		body, err := applyTransformationsToBody(raw, plan)
		if err != nil {
			return RequestDecision{}, err
		}
		transformed = body
	}
	if dec.Action == core.ActionRestrictTools {
		// T-025: RESTRICT_TOOLS physically removes restricted tools from the
		// request — never a prompt-level "please don't".
		body, err := stripRestrictedTools(raw, p.engine.RestrictedTools())
		if err != nil {
			return RequestDecision{}, err
		}
		transformed = body
	}
	elapsed := time.Since(start)
	p.recorder.ObserveSecurityLatency(float64(elapsed.Microseconds()) / 1000.0)
	p.recorder.ObserveRequest(dec.Action, p.mode)
	if p.mode == ModeShadow {
		p.recorder.ObserveShadowDisagreement(dec.Action)
		// FP sample: a semantic-only predicted block over content with no
		// deterministic finding is the highest-value FP review candidate.
		if dec.Action == core.ActionBlock || dec.Action == core.ActionReview {
			hasDeterministic := false
			for _, f := range all {
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
	if transformed != nil {
		switch dec.Action {
		case core.ActionTokenize:
			p.recorder.ObserveTokens(strings.Count(string(transformed), "<"), "tokenize")
		case core.ActionRedact:
			p.recorder.ObserveTokens(strings.Count(string(transformed), "[REDACTED:"), "redact")
		}
	}

	latency := map[string]int64{
		"deterministic":  elapsed.Milliseconds(),
		"total_security": elapsed.Milliseconds(),
	}
	if layaMS > 0 {
		latency["laya"] = layaMS
	}

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
		LatencyMS:     latency,
		Laya:          layaInfo,
	})

	return RequestDecision{Action: dec.Action, Code: dec.Code, TransformedBody: transformed}, nil
}

// evaluateSemantic asks the configured questions for the request direction.
// The semantic subject is the last user text (the model-bound payload); the
// evidence is normalized by the provider adapter before this method sees it.
func (p *SecurityPipeline) evaluateSemantic(env *core.InspectionEnvelope, findings []core.SecurityFinding) (*decision.DecisionEvidence, []policy.SemanticSignal, decision.Plan, error) {
	// The planner decides whether semantics are worth their latency for this
	// request (T-016): deterministic secret findings skip Laya entirely
	// (SEC-002), and directions without configured questions skip too.
	plan := p.planner.Plan(env.Direction, env.Application, env.Target, findings)
	if !plan.Ask {
		return nil, nil, plan, nil
	}

	content := lastUserText(env)
	if content == "" {
		return nil, nil, plan, nil // nothing semantic to ask about
	}
	role := string(core.RoleUser)

	direction := strings.ToLower(string(env.Direction))
	req := decision.DecisionRequest{
		RequestID:   env.RequestID,
		Direction:   direction,
		Role:        role,
		Content:     content,
		Application: env.Application,
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
			QuestionID: id,
			Triggered:  d.Value,
			Confidence: d.Confidence,
			Risk:       p.questions.RiskOf(id),
		})
	}
	return &evidence, signals, plan, nil
}

// storeTokenMappings seals each transformed span's original value into the
// vault under the request namespace. Values are read from the envelope's own
// text parts and are never logged (FR-014, T-020).
func (p *SecurityPipeline) storeTokenMappings(env *core.InspectionEnvelope, plan []pii.Transformation) error {
	texts := map[string]string{}
	for _, lt := range env.TextParts() {
		texts[fmt.Sprintf("%d/%d", lt.MessageIndex, lt.PartIndex)] = lt.Text
	}
	now := time.Now()
	ctx := context.Background()
	for _, t := range plan {
		text, ok := texts[fmt.Sprintf("%d/%d", t.MessageIndex, t.PartIndex)]
		if !ok || t.Start < 0 || t.End > len(text) || t.Start >= t.End {
			continue
		}
		value := text[t.Start:t.End]
		ct, err := p.crypto.Seal([]byte(value))
		if err != nil {
			return fmt.Errorf("seal token value: %w", err)
		}
		err = p.vault.Put(ctx, tokenization.VaultRecord{
			Namespace:   env.RequestID,
			Token:       tokenization.TokenLabel(t.Replacement),
			Type:        t.Subtype,
			Ciphertext:  ct,
			CreatedAt:   now,
			ExpiresAt:   now.Add(p.vaultTTL),
			Application: env.Application,
			Subject:     env.User.Subject,
		})
		if err != nil {
			return fmt.Errorf("store token mapping: %w", err)
		}
	}
	return nil
}

// ResponseOutcome is the pipeline outcome for the outbound direction.
type ResponseOutcome struct {
	Action          core.Action
	Code            string
	TransformedBody []byte
}

// ProcessResponse scans the upstream response before it reaches the client
// (FR-015, architecture §12). Secret findings block per policy (AS-005);
// PII findings are redacted regardless of the request-side transformation
// flavor (UC-008). Token placeholders the model echoed back are re-identified
// only when they resolve against tokens issued in this request's namespace
// for the calling application (T-023); invented markers stay untouched.
func (p *SecurityPipeline) ProcessResponse(reqEnv *core.InspectionEnvelope, raw []byte) (ResponseOutcome, error) {
	if p.mode == ModeOff {
		return ResponseOutcome{Action: core.ActionAllow}, nil
	}
	start := time.Now()

	respEnv, err := ParseChatCompletionsResponse(raw)
	if err != nil {
		return ResponseOutcome{}, err
	}
	respEnv.Application = reqEnv.Application
	respEnv.Tenant = reqEnv.Tenant
	respEnv.User = reqEnv.User
	respEnv.Target.Provider = reqEnv.Target.Provider

	findings := p.registry.RunAll(respEnv)
	entityFindings := p.entityFindings(respEnv)
	all := append(append([]core.SecurityFinding{}, findings...), entityFindings...)
	dec := p.engine.Evaluate(policy.Context{Envelope: respEnv, Findings: all})

	outcome := ResponseOutcome{Action: dec.Action, Code: dec.Code}
	switch dec.Action {
	case core.ActionBlock, core.ActionReview:
		// Server rejects the response; nothing is transformed.
	case core.ActionRedact, core.ActionTokenize:
		var ts []responseTransform
		for _, f := range all {
			if f.Category != core.CategoryPII || f.Location.End <= f.Location.Start {
				continue
			}
			ts = append(ts, responseTransform{
				ChoiceIndex: f.Location.MessageIndex,
				PartIndex:   f.Location.PartIndex,
				Start:       f.Location.Start,
				End:         f.Location.End,
				Replacement: "[REDACTED:" + f.Subtype + "]",
			})
		}
		body, terr := applyTransformationsToResponseBody(raw, ts)
		if terr != nil {
			return ResponseOutcome{}, terr
		}
		outcome.TransformedBody = body
		raw = body
	default:
	}

	if dec.Action != core.ActionBlock && dec.Action != core.ActionReview && p.vault != nil && p.crypto != nil {
		reid := tokenization.NewReidentifier(p.vault, p.crypto)
		body, changed, rerr := replacePlaceholdersInBody(raw, func(label string) (string, bool) {
			value, rerr := reid.Reidentify(context.Background(), reqEnv.RequestID, label,
				tokenization.Caller{Application: reqEnv.Application, Subject: reqEnv.User.Subject})
			if rerr != nil {
				return "", false
			}
			return value, true
		})
		if rerr != nil {
			return ResponseOutcome{}, rerr
		}
		if changed {
			outcome.TransformedBody = body
		}
	}
	elapsed := time.Since(start)

	p.audit.Record(audit.Event{
		RequestID:     reqEnv.RequestID,
		Timestamp:     time.Now().UTC(),
		Direction:     core.DirectionResponse,
		Application:   reqEnv.Application,
		Tenant:        reqEnv.Tenant,
		User:          reqEnv.User.Subject,
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

	return outcome, nil
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

// --- ticket 12: tool call/result inspection (FR-016/017, T-024) ---

// ToolCall is a model-emitted tool call offered for inspection.
type ToolCall struct {
	ID        string
	Name      string
	Arguments string // raw arguments payload (JSON or text)
}

// ToolResult is a tool result offered for inspection before it re-enters
// model context.
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
	TransformedContent string // redacted content for REDACT decisions
}

// InspectToolCall inspects a tool call before execution (UC-006): the same
// detectors, planner, and policy engine run with direction TOOL_CALL. Secret
// material in arguments is caught deterministically; exfiltration or unsafe
// intent is evaluated semantically when a provider is configured.
func (p *SecurityPipeline) InspectToolCall(reqEnv *core.InspectionEnvelope, call ToolCall) (ToolDecision, error) {
	env := p.toolEnvelope(reqEnv, core.DirectionToolCall, call.Name, call.Arguments)
	start := time.Now()

	findings := p.registry.RunAll(env)
	all := append([]core.SecurityFinding{}, findings...)
	dec := p.engine.Evaluate(policy.Context{Envelope: env, Findings: all})

	var layaInfo *audit.LayaInfo
	if p.provider != nil && p.planner != nil && dec.Action != core.ActionBlock {
		plan := p.planner.Plan(core.DirectionToolCall, env.Application, env.Target, all)
		if plan.Ask {
			ev, err := p.provider.Evaluate(context.Background(), decision.DecisionRequest{
				RequestID:   env.RequestID,
				Direction:   "tool_call",
				Role:        "assistant",
				Content:     call.Arguments,
				Application: env.Application,
			}, plan.QuestionIDs)
			if err != nil {
				layaInfo = &audit.LayaInfo{Error: "unavailable"}
				if plan.MaxRisk == "high" {
					if fb, ok := p.engine.LayaUnavailableFallback(); ok {
						dec = fb
					}
				}
			} else {
				layaInfo = layaAuditInfo(&ev)
				var signals []policy.SemanticSignal
				for _, id := range plan.QuestionIDs {
					if d, ok := ev.Decisions[id]; ok {
						signals = append(signals, policy.SemanticSignal{
							QuestionID: id, Triggered: d.Value, Confidence: d.Confidence,
							Risk: p.questions.RiskOf(id),
						})
					}
				}
				// Same gating as the request path: shadow predicts with all
				// evidence; enforce acts only on calibrated slices.
				switch {
				case p.mode == ModeShadow:
					dec = p.engine.Evaluate(policy.Context{Envelope: env, Findings: all, Semantic: signals})
				case p.semanticEnforce:
					if gated := p.gateSignals(env, signals, ev); len(gated) > 0 {
						dec = p.engine.Evaluate(policy.Context{Envelope: env, Findings: all, Semantic: gated})
					}
				}
			}
		}
	}

	p.audit.Record(p.toolAuditEvent(env, dec, all, start, layaInfo))
	return ToolDecision{Action: dec.Action, Code: dec.Code, MatchedRule: dec.MatchedRule, Reason: dec.Reason}, nil
}

// InspectToolResult inspects a tool result before it re-enters model context
// (UC-007): credentials in results are blocked or redacted per policy — the
// raw value never re-enters model context.
func (p *SecurityPipeline) InspectToolResult(reqEnv *core.InspectionEnvelope, result ToolResult) (ToolDecision, error) {
	env := p.toolEnvelope(reqEnv, core.DirectionToolResult, result.Name, result.Content)
	start := time.Now()

	findings := p.registry.RunAll(env)
	all := append([]core.SecurityFinding{}, findings...)
	dec := p.engine.Evaluate(policy.Context{Envelope: env, Findings: all})

	out := ToolDecision{Action: dec.Action, Code: dec.Code, MatchedRule: dec.MatchedRule, Reason: dec.Reason}
	if dec.Action == core.ActionRedact || dec.Action == core.ActionTokenize {
		plan := pii.Plan(all, pii.RedactNamer)
		out.TransformedContent = pii.ApplyToText(result.Content, plan)
	}

	p.audit.Record(p.toolAuditEvent(env, dec, all, start, nil))
	return out, nil
}

// toolEnvelope builds the inspection envelope for one tool boundary crossing.
func (p *SecurityPipeline) toolEnvelope(reqEnv *core.InspectionEnvelope, dir core.Direction, toolName, content string) *core.InspectionEnvelope {
	return &core.InspectionEnvelope{
		RequestID:   reqEnv.RequestID,
		Direction:   dir,
		Application: reqEnv.Application,
		Tenant:      reqEnv.Tenant,
		User:        reqEnv.User,
		Target:      reqEnv.Target,
		Messages: []core.Message{{
			Role: core.RoleAssistant,
			Parts: []core.ContentPart{{
				Type:     core.PartText,
				ToolName: toolName,
				Text:     content,
			}},
		}},
	}
}

func (p *SecurityPipeline) toolAuditEvent(env *core.InspectionEnvelope, dec policy.Decision, findings []core.SecurityFinding, start time.Time, laya *audit.LayaInfo) audit.Event {
	return audit.Event{
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
			"deterministic":  time.Since(start).Milliseconds(),
			"total_security": time.Since(start).Milliseconds(),
		},
		Laya: laya,
	}
}

func layaAuditInfo(ev *decision.DecisionEvidence) *audit.LayaInfo {
	info := &audit.LayaInfo{
		Provider:      ev.Provider,
		Checkpoint:    ev.Checkpoint,
		SchemaVersion: ev.SchemaVersion,
		Route:         ev.Route,
	}
	for id, d := range ev.Decisions {
		if info.Decisions == nil {
			info.Decisions = map[string]audit.LayaDecision{}
		}
		info.Decisions[id] = audit.LayaDecision{Value: d.Value, Confidence: d.Confidence}
	}
	return info
}
