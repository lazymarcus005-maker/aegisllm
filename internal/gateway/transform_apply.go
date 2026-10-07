package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/tokenization"
)

// ProcessRequest applies the policy result to the request body. The server
// remains responsible for enforce-vs-shadow transport behavior.
func (p *SecurityPipeline) ProcessRequest(env *core.InspectionEnvelope, raw []byte) (RequestDecision, error) {
	return p.ProcessRequestContext(context.Background(), env, raw)
}

// ProcessRequestContext is the request-aware entry point used by HTTP
// handlers so semantic evaluation and its bounded queue honor cancellation.
func (p *SecurityPipeline) ProcessRequestContext(ctx context.Context, env *core.InspectionEnvelope, raw []byte) (RequestDecision, error) {
	if p.mode == ModeOff {
		return RequestDecision{Action: core.ActionAllow}, nil
	}
	ins := p.inspectContext(ctx, env)
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
		if ins.dec.Action == core.ActionTokenize {
			p.recorder.ObserveTokens(len(plan), "tokenize")
		} else {
			p.recorder.ObserveTokens(len(plan), "redact")
		}
		if err := p.recordAudit(ctx, p.auditEvent(ins)); err != nil {
			return RequestDecision{}, err
		}
		return RequestDecision{Action: ins.dec.Action, Code: ins.dec.Code, Transformations: plan}, nil
	case core.ActionRestrictTools:
		body, err := stripRestrictedTools(raw, p.current().Engine.RestrictedTools())
		if err != nil {
			return RequestDecision{}, err
		}
		transformed = body
	}
	if err := p.recordAudit(ctx, p.auditEvent(ins)); err != nil {
		return RequestDecision{}, err
	}
	return RequestDecision{Action: ins.dec.Action, Code: ins.dec.Code, TransformedBody: transformed}, nil
}

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
		ct, err := p.crypto.Seal([]byte(text[t.Start:t.End]))
		if err != nil {
			return fmt.Errorf("seal token value: %w", err)
		}
		err = p.vault.Put(ctx, tokenization.VaultRecord{
			Namespace: env.RequestID, Token: tokenization.TokenLabel(t.Replacement), Type: t.Subtype,
			Ciphertext: ct, CreatedAt: now, ExpiresAt: now.Add(p.vaultTTL),
			Application: env.Application, Subject: env.User.Subject,
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
	Transformations []pii.Transformation
}

// StreamTextOutcome is the shared pipeline result for one rolling response
// text window. Predicted is the policy result; Applied reflects deployment
// mode so shadow traffic remains byte-for-byte unchanged.
type StreamTextOutcome struct {
	Predicted core.Action
	Applied   core.Action
	Code      string
	Text      string
}

// ProcessStreamText uses the same detector, policy, semantic, audit, and
// transformation machinery as buffered responses. The transport owns SSE
// framing and rolling holdback; this method owns security meaning.
func (p *SecurityPipeline) ProcessStreamText(reqEnv *core.InspectionEnvelope, text, kind string) (StreamTextOutcome, error) {
	if p.mode == ModeOff {
		return StreamTextOutcome{Predicted: core.ActionAllow, Applied: core.ActionAllow, Text: text}, nil
	}
	env := &core.InspectionEnvelope{
		RequestID: reqEnv.RequestID, Direction: core.DirectionResponse,
		Application: reqEnv.Application, Tenant: reqEnv.Tenant, User: reqEnv.User,
		Target: reqEnv.Target, Metadata: map[string]string{},
		Messages: []core.Message{{Role: core.RoleAssistant, Parts: []core.ContentPart{{Type: core.PartText, Text: text}}}},
	}
	for key, value := range reqEnv.Metadata {
		env.Metadata[key] = value
	}
	env.Metadata["stream"] = "true"
	if kind == "tool_arguments" {
		env.Messages[0].Parts[0].Type = core.PartToolCall
	}
	ins := p.inspect(env)
	out := StreamTextOutcome{Predicted: ins.dec.Action, Applied: ins.dec.Action, Code: ins.dec.Code, Text: text}
	if p.mode != ModeEnforce {
		out.Applied = core.ActionAllow
	} else {
		switch ins.dec.Action {
		case core.ActionBlock, core.ActionReview:
			out.Text = ""
		case core.ActionRedact, core.ActionTokenize:
			namer := pii.RedactNamer
			if ins.dec.Action == core.ActionTokenize {
				namer = pii.TokenNamer
			}
			plan := pii.Plan(ins.findings, namer)
			if ins.dec.Action == core.ActionTokenize && p.vault != nil && p.crypto != nil {
				if err := p.storeTokenMappings(env, plan); err != nil {
					return StreamTextOutcome{}, err
				}
			}
			out.Text = pii.ApplyToText(text, plan)
		}
	}
	if err := p.recordAudit(context.Background(), p.auditEvent(ins)); err != nil {
		return StreamTextOutcome{}, err
	}
	if recorder, ok := p.recorder.(interface {
		ObserveStream(core.Direction, string, core.Action, core.Action, string, int64, int)
	}); ok {
		recorded := out.Applied
		if p.mode == ModeShadow {
			recorded = core.ActionAllow
		}
		recorder.ObserveStream(core.DirectionResponse, reqEnv.Metadata["endpoint_family"], out.Predicted, recorded, p.mode, int64(len(text)), 1)
	}
	return out, nil
}

// AuditPassthrough records a body-free ALLOW event for endpoints such as
// GET /v1/models. It deliberately never runs a content detector over a body.
func (p *SecurityPipeline) AuditPassthrough(env *core.InspectionEnvelope) {
	if env.Metadata == nil {
		env.Metadata = map[string]string{}
	}
	env.Metadata["passthrough"] = "true"
	ins := p.inspect(env)
	_ = p.recordAudit(context.Background(), p.auditEvent(ins))
}

// AuditRoute adds only bounded route metadata to the already-sanitized audit
// stream. It is intentionally separate from policy inspection because routing
// is selected after request transformations are decided.
func (p *SecurityPipeline) AuditRoute(env *core.InspectionEnvelope, action core.Action, id, class, provider, requested, routed string, failover bool) {
	if p.audit == nil {
		return
	}
	p.audit.Record(audit.Event{RequestID: env.RequestID, Timestamp: time.Now().UTC(), Direction: core.DirectionRequest, Component: "gateway",
		Application: env.Application, Tenant: env.Tenant, User: env.User.Subject, Roles: append([]string(nil), env.User.Roles...),
		Provider: env.Target.Provider, Mode: p.mode, Action: action, EndpointFamily: env.Metadata["endpoint_family"],
		RouteID: safeSemanticMetadata(id), RouteClass: safeSemanticMetadata(class), RouteProvider: safeSemanticMetadata(provider),
		RequestedModel: safeSemanticMetadata(requested), RoutedModel: safeSemanticMetadata(routed), RouteReason: routeReason(action), RouteFailover: failover})
}

func routeReason(action core.Action) string {
	if action == core.ActionForceLocalModel {
		return "force_local_policy"
	}
	return "configured_route"
}

// ProcessResponse scans and transforms an upstream response before delivery.
func (p *SecurityPipeline) ProcessResponse(reqEnv *core.InspectionEnvelope, raw []byte) (ResponseOutcome, error) {
	if p.mode == ModeOff {
		return ResponseOutcome{Action: core.ActionAllow}, nil
	}
	normalizer := NormalizerFor(reqEnv.Metadata["endpoint_path"])
	if normalizer == nil {
		normalizer = openAIChatNormalizer{}
	}
	respEnv, err := normalizer.ParseResponse(raw)
	if err != nil {
		return ResponseOutcome{}, err
	}
	deriveResponseEnvelope(respEnv, reqEnv)
	ins := p.inspect(respEnv)
	outcome := ResponseOutcome{Action: ins.dec.Action, Code: ins.dec.Code}
	switch ins.dec.Action {
	case core.ActionBlock, core.ActionReview:
	case core.ActionRedact, core.ActionTokenize:
		plan := pii.Plan(ins.findings, pii.RedactNamer)
		outcome.Transformations = plan
	}
	if ins.dec.Action != core.ActionBlock && ins.dec.Action != core.ActionReview && p.vault != nil && p.crypto != nil {
		reid := tokenization.NewReidentifier(p.vault, p.crypto)
		body, changed, rerr := replacePlaceholdersInNormalizerBody(raw, normalizer, func(label string) (string, bool) {
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
	if err := p.recordAudit(context.Background(), p.auditEvent(ins)); err != nil {
		return ResponseOutcome{}, err
	}
	return outcome, nil
}

func deriveResponseEnvelope(respEnv, reqEnv *core.InspectionEnvelope) {
	respEnv.RequestID = reqEnv.RequestID
	respEnv.Application = reqEnv.Application
	respEnv.Tenant = reqEnv.Tenant
	respEnv.User = reqEnv.User
	respEnv.Target.Provider = reqEnv.Target.Provider
}
