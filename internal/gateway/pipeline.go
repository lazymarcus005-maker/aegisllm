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
//
// One inspection routine (inspect) serves all four data boundaries — request,
// response, tool call, tool result — so detection, spans, semantics, metrics,
// and audit cannot drift apart per direction. The exported methods are thin
// direction adapters owning only envelope construction, body transformation,
// and the response contract. The pipeline predicts and audits; the Server is
// the single owner of the security mode (FR-018) and propagates it via
// SetSecurityMode, so a pipeline can never disagree with its deployment.
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

func NewSecurityPipeline(registry *detectors.Registry, engine *policy.Engine, sink audit.Sink) *SecurityPipeline {
	return &SecurityPipeline{registry: registry, engine: engine, audit: sink, mode: ModeOff, recorder: observability.Noop{}}
}

// SetSecurityMode sets the deployment mode (off | shadow | enforce). Called
// by Server.SetPipeline: the server owns the mode, the pipeline never states
// it independently.
func (p *SecurityPipeline) SetSecurityMode(mode string) { p.mode = mode }

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
// threshold (INV-010). Without a threshold policy nothing enforces. The
// slice language is classified from the boundary's own semantic subject, so
// tool payloads are not misread as the request's language.
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

// semanticSubject returns the content and role the semantic stage evaluates
// for this direction: the last user text on the request path, the tool
// payload on tool boundaries, the model text on responses.
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

// inspection is one boundary crossing's result from the shared routine.
type inspection struct {
	env      *core.InspectionEnvelope
	findings []core.SecurityFinding
	dec      policy.Decision
	laya     *audit.LayaInfo
	layaMS   int64 // semantic provider latency; 0 when not invoked
	detMS    int64 // deterministic phase (scan + spans + policy), excludes Laya
	start    time.Time
}

// inspect runs the shared inspection core for any direction: deterministic
// scan, span detection, policy evaluation, and — when the planner asks for
// it and no definitive deterministic block exists — semantic evidence.
// Shadow re-evaluates with all evidence; enforce acts only on gated
// calibrated slices (INV-010). Detection, provider, and shadow metrics fire
// here for every direction, so no boundary drifts silent.
func (p *SecurityPipeline) inspect(env *core.InspectionEnvelope) *inspection {
	ins := &inspection{env: env, start: time.Now()}

	scanStart := time.Now()
	findings := p.registry.RunAll(env)
	p.recorder.ObserveScanner(float64(time.Since(scanStart).Microseconds()) / 1000.0)
	entityFindings := p.entityFindings(env)
	ins.findings = append(append([]core.SecurityFinding{}, findings...), entityFindings...)
	seenTypes := map[string]bool{}
	for _, f := range ins.findings {
		key := string(f.Category) + "/" + f.Subtype
		if !seenTypes[key] {
			seenTypes[key] = true
			p.recorder.ObserveFindings(string(f.Category), f.Subtype)
		}
	}
	ins.dec = p.engine.Evaluate(policy.Context{Envelope: env, Findings: ins.findings})
	ins.detMS = time.Since(ins.start).Milliseconds()

	if p.provider != nil && p.planner != nil && ins.dec.Action != core.ActionBlock {
		p.semanticStage(ins)
	}

	// gateway_security_latency_ms is the deterministic-phase latency: the
	// semantic provider has its own histogram (spec §15).
	p.recorder.ObserveSecurityLatency(float64(ins.detMS))
	if env.Direction == core.DirectionRequest {
		// requests_total counts HTTP request boundaries; response and tool
		// boundaries are visible in the audit trail and findings metrics.
		p.recorder.ObserveRequest(ins.dec.Action, p.mode)
	}
	if p.mode == ModeShadow {
		p.recorder.ObserveShadowDisagreement(ins.dec.Action)
		// FP sample: a semantic-only predicted block over content with no
		// deterministic finding is the highest-value FP review candidate.
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

// semanticStage consults the decision provider for one inspected boundary.
// Called only when the deterministic decision is not already a definitive
// block — a known secret never reaches Laya (SEC-002, NFR-PERF-004).
func (p *SecurityPipeline) semanticStage(ins *inspection) {
	env := ins.env
	layaStart := time.Now()
	evidence, signals, plan, err := p.evaluateSemantic(env, ins.findings)
	ins.layaMS = time.Since(layaStart).Milliseconds()
	// Metrics and audit record the provider only when it was actually
	// invoked — planner skips (fast path) mean laya_calls = 0 (AS-001,
	// spec §15). Errors here are provider invocation failures.
	if err != nil || evidence != nil {
		ins.laya = &audit.LayaInfo{}
		p.recorder.ObserveLaya(float64(ins.layaMS), err != nil)
	}
	if err != nil {
		// Provider unavailable (error or open circuit): policy-controlled
		// fallback — high-risk routes never silently allow (AS-004,
		// INV-008, NFR-AVAIL-002/003).
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
	// Shadow predicts with all evidence; enforce acts only on gated,
	// calibrated slices (rollout stage 3, ticket 11).
	switch {
	case p.mode == ModeShadow:
		ins.dec = p.engine.Evaluate(policy.Context{Envelope: env, Findings: ins.findings, Semantic: signals})
	case p.semanticEnforce:
		if gated := p.gateSignals(env, signals, *evidence); len(gated) > 0 {
			ins.dec = p.engine.Evaluate(policy.Context{Envelope: env, Findings: ins.findings, Semantic: gated})
		}
	}
}

// evaluateSemantic asks the configured questions for one boundary. The
// semantic subject is the direction's model-bound payload; the evidence is
// normalized by the provider adapter before this method sees it.
func (p *SecurityPipeline) evaluateSemantic(env *core.InspectionEnvelope, findings []core.SecurityFinding) (*decision.DecisionEvidence, []policy.SemanticSignal, decision.Plan, error) {
	// The planner decides whether semantics are worth their latency for this
	// boundary (T-016): deterministic secret findings skip Laya entirely
	// (SEC-002), and directions without configured questions skip too.
	plan := p.planner.Plan(env.Direction, env.Application, env.Target, findings)
	if !plan.Ask {
		return nil, nil, plan, nil
	}

	content, role := semanticSubject(env)
	if content == "" {
		return nil, nil, plan, nil // nothing semantic to ask about
	}

	req := decision.DecisionRequest{
		RequestID:   env.RequestID,
		Direction:   strings.ToLower(string(env.Direction)),
		Role:        string(role),
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

// auditEvent builds the sanitized audit event for one inspected boundary.
// The latency split is real: deterministic excludes the semantic provider,
// which is reported separately when it ran (architecture §15).
func (p *SecurityPipeline) auditEvent(ins *inspection) audit.Event {
	latency := map[string]int64{
		"deterministic":  ins.detMS,
		"total_security": time.Since(ins.start).Milliseconds(),
	}
	if ins.layaMS > 0 {
		latency["laya"] = ins.layaMS
	}
	return audit.Event{
		RequestID:     ins.env.RequestID,
		Timestamp:     time.Now().UTC(),
		Direction:     ins.env.Direction,
		Application:   ins.env.Application,
		Tenant:        ins.env.Tenant,
		User:          ins.env.User.Subject,
		PolicyID:      ins.dec.PolicyID,
		PolicyVersion: ins.dec.PolicyVersion,
		Mode:          p.mode,
		Action:        ins.dec.Action,
		Code:          ins.dec.Code,
		MatchedRule:   ins.dec.MatchedRule,
		FindingTypes:  audit.FindingTypes(ins.findings),
		FindingCount:  len(ins.findings),
		LatencyMS:     latency,
		Laya:          ins.laya,
	}
}

// ProcessRequest runs the request-direction adapter. In shadow mode the
// predicted action is returned and audited, but the server keeps the
// incumbent path (FR-018). In off mode no inspection happens at all.
func (p *SecurityPipeline) ProcessRequest(env *core.InspectionEnvelope, raw []byte) (RequestDecision, error) {
	if p.mode == ModeOff {
		return RequestDecision{Action: core.ActionAllow}, nil
	}
	ins := p.inspect(env)

	var transformed []byte
	switch ins.dec.Action {
	case core.ActionRedact, core.ActionTokenize:
		namer := pii.RedactNamer
		if ins.dec.Action == core.ActionTokenize {
			namer = pii.TokenNamer
		}
		plan := pii.Plan(ins.findings, namer)
		if ins.dec.Action == core.ActionTokenize && p.vault != nil && p.crypto != nil {
			if err := p.storeTokenMappings(env, plan); err != nil {
				return RequestDecision{}, err
			}
		}
		body, err := applyTransformationsToBody(raw, plan)
		if err != nil {
			return RequestDecision{}, err
		}
		transformed = body
		if ins.dec.Action == core.ActionTokenize {
			p.recorder.ObserveTokens(strings.Count(string(transformed), "<"), "tokenize")
		} else {
			p.recorder.ObserveTokens(strings.Count(string(transformed), "[REDACTED:"), "redact")
		}
	case core.ActionRestrictTools:
		// T-025: RESTRICT_TOOLS physically removes restricted tools from the
		// request — never a prompt-level "please don't".
		body, err := stripRestrictedTools(raw, p.engine.RestrictedTools())
		if err != nil {
			return RequestDecision{}, err
		}
		transformed = body
	}

	p.audit.Record(p.auditEvent(ins))
	return RequestDecision{Action: ins.dec.Action, Code: ins.dec.Code, TransformedBody: transformed}, nil
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
// (FR-015, architecture §12). Secret and PII findings are transformed per
// policy: BLOCK/REVIEW rejects the whole response (AS-005 under block
// policy); REDACT masks every matched span before the client sees it. Token
// placeholders the model echoed back are re-identified
// only when they resolve against tokens issued in this request's namespace
// for the calling application (T-023); invented markers stay untouched.
func (p *SecurityPipeline) ProcessResponse(reqEnv *core.InspectionEnvelope, raw []byte) (ResponseOutcome, error) {
	if p.mode == ModeOff {
		return ResponseOutcome{Action: core.ActionAllow}, nil
	}

	respEnv, err := ParseChatCompletionsResponse(raw)
	if err != nil {
		return ResponseOutcome{}, err
	}
	deriveResponseEnvelope(respEnv, reqEnv)

	ins := p.inspect(respEnv)

	outcome := ResponseOutcome{Action: ins.dec.Action, Code: ins.dec.Code}
	switch ins.dec.Action {
	case core.ActionBlock, core.ActionReview:
		// Server rejects the response; nothing is transformed.
	case core.ActionRedact, core.ActionTokenize:
		// Outbound masking reuses the request path's Plan seam: overlap
		// resolution and detector precedence are identical in both
		// directions (T-018).
		plan := pii.Plan(ins.findings, pii.RedactNamer)
		body, terr := applyPlanToResponseBody(raw, plan)
		if terr != nil {
			return ResponseOutcome{}, terr
		}
		outcome.TransformedBody = body
		raw = body
	default:
	}

	if ins.dec.Action != core.ActionBlock && ins.dec.Action != core.ActionReview && p.vault != nil && p.crypto != nil {
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

	p.audit.Record(p.auditEvent(ins))
	return outcome, nil
}

// deriveResponseEnvelope copies caller identity from the request envelope so
// response-direction policy sees the same subject, tenant, and target; the
// request id carries across so audit and re-identification stay correlated.
func deriveResponseEnvelope(respEnv, reqEnv *core.InspectionEnvelope) {
	respEnv.RequestID = reqEnv.RequestID
	respEnv.Application = reqEnv.Application
	respEnv.Tenant = reqEnv.Tenant
	respEnv.User = reqEnv.User
	respEnv.Target.Provider = reqEnv.Target.Provider
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
// detectors, span provider, planner, and policy engine run with direction
// TOOL_CALL. Secret material in arguments is caught deterministically;
// exfiltration or unsafe intent is evaluated semantically when a provider is
// configured.
func (p *SecurityPipeline) InspectToolCall(reqEnv *core.InspectionEnvelope, call ToolCall) (ToolDecision, error) {
	if p.mode == ModeOff {
		return ToolDecision{Action: core.ActionAllow}, nil
	}
	env := toolEnvelope(reqEnv, core.DirectionToolCall, call.Name, call.Arguments)
	ins := p.inspect(env)

	out := ToolDecision{Action: ins.dec.Action, Code: ins.dec.Code, MatchedRule: ins.dec.MatchedRule, Reason: ins.dec.Reason}
	if ins.dec.Action == core.ActionRedact || ins.dec.Action == core.ActionTokenize {
		// UC-006 hard mask: secret-bearing arguments are returned masked so
		// the raw material never reaches the tool executor.
		plan := pii.Plan(ins.findings, pii.RedactNamer)
		out.TransformedContent = pii.ApplyToText(call.Arguments, plan)
	}
	p.audit.Record(p.auditEvent(ins))
	return out, nil
}

// InspectToolResult inspects a tool result before it re-enters model context
// (UC-007): credentials and PII in results are masked per policy — the raw
// value never re-enters model context.
func (p *SecurityPipeline) InspectToolResult(reqEnv *core.InspectionEnvelope, result ToolResult) (ToolDecision, error) {
	if p.mode == ModeOff {
		return ToolDecision{Action: core.ActionAllow}, nil
	}
	env := toolEnvelope(reqEnv, core.DirectionToolResult, result.Name, result.Content)
	ins := p.inspect(env)

	out := ToolDecision{Action: ins.dec.Action, Code: ins.dec.Code, MatchedRule: ins.dec.MatchedRule, Reason: ins.dec.Reason}
	if ins.dec.Action == core.ActionRedact || ins.dec.Action == core.ActionTokenize {
		plan := pii.Plan(ins.findings, pii.RedactNamer)
		out.TransformedContent = pii.ApplyToText(result.Content, plan)
	}
	p.audit.Record(p.auditEvent(ins))
	return out, nil
}

// toolEnvelope builds the inspection envelope for one tool boundary crossing.
func toolEnvelope(reqEnv *core.InspectionEnvelope, dir core.Direction, toolName, content string) *core.InspectionEnvelope {
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
