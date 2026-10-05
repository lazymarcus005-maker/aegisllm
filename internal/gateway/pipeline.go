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
	semanticEnforce bool
}

func NewSecurityPipeline(registry *detectors.Registry, engine *policy.Engine, sink audit.Sink, mode string) *SecurityPipeline {
	return &SecurityPipeline{registry: registry, engine: engine, audit: sink, mode: mode}
}

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
}

// EnableSemanticEnforce opts into semantic enforcement for calibrated slices
// (ticket 11). Default is false.
func (p *SecurityPipeline) EnableSemanticEnforce() { p.semanticEnforce = true }

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

	// Semantic evidence (ticket 08): called only when deterministic rules
	// did not already produce a definitive block — a known secret never
	// reaches Laya (SEC-002, NFR-PERF-004). Evidence feeds policy in shadow
	// only until semantic enforcement is explicitly enabled.
	var layaInfo *audit.LayaInfo
	var layaMS int64
	if p.provider != nil && p.questions != nil && dec.Action != core.ActionBlock {
		layaStart := time.Now()
		evidence, signals, err := p.evaluateSemantic(env)
		layaMS = time.Since(layaStart).Milliseconds()
		layaInfo = &audit.LayaInfo{}
		if err != nil {
			layaInfo.Error = "evaluation failed"
		} else if evidence != nil {
			layaInfo.Provider = evidence.Provider
			layaInfo.Checkpoint = evidence.Checkpoint
			layaInfo.SchemaVersion = evidence.SchemaVersion
			layaInfo.Route = evidence.Route
			for id, d := range evidence.Decisions {
				if layaInfo.Decisions == nil {
					layaInfo.Decisions = map[string]audit.LayaDecision{}
				}
				layaInfo.Decisions[id] = audit.LayaDecision{Value: d.Value, Confidence: d.Confidence}
			}
		}
		// Feed evidence into the policy engine only when shadow-mode or when
		// semantic enforcement has been enabled (rollout stage 3, ticket 11).
		if err == nil && evidence != nil && (p.mode == ModeShadow || p.semanticEnforce) {
			dec = p.engine.Evaluate(policy.Context{
				Envelope: env,
				Findings: all,
				Semantic: signals,
			})
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
	elapsed := time.Since(start)

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

// semanticEval bundles the outcome of one semantic evaluation.
type semanticEval struct {
	evidence *decision.DecisionEvidence
	signals  []policy.SemanticSignal
}

// evaluateSemantic asks the configured questions for the request direction.
// The semantic subject is the last user text (the model-bound payload); the
// evidence is normalized by the provider adapter before this method sees it.
func (p *SecurityPipeline) evaluateSemantic(env *core.InspectionEnvelope) (*decision.DecisionEvidence, []policy.SemanticSignal, error) {
	content, role := "", ""
	for i := len(env.Messages) - 1; i >= 0; i-- {
		if env.Messages[i].Role == core.RoleUser {
			for _, part := range env.Messages[i].Parts {
				if part.Type == core.PartText && part.Text != "" {
					content = part.Text
					break
				}
			}
			if content != "" {
				role = string(env.Messages[i].Role)
				break
			}
		}
	}
	if content == "" {
		return nil, nil, nil // nothing semantic to ask about
	}

	direction := strings.ToLower(string(env.Direction))
	questionIDs := p.questions.ForDirection(direction)
	if len(questionIDs) == 0 {
		return nil, nil, nil
	}

	req := decision.DecisionRequest{
		RequestID:   env.RequestID,
		Direction:   direction,
		Role:        role,
		Content:     content,
		Application: env.Application,
	}
	evidence, err := p.provider.Evaluate(context.Background(), req, questionIDs)
	if err != nil {
		return nil, nil, err
	}

	var signals []policy.SemanticSignal
	for _, id := range questionIDs {
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
	return &evidence, signals, nil
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
