package gateway

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aegisllm/gateway/internal/attachment"
	"github.com/aegisllm/gateway/internal/audit"
	"github.com/aegisllm/gateway/internal/core"
	"github.com/aegisllm/gateway/internal/pii"
	"github.com/aegisllm/gateway/internal/policy"
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
	if p.attachments != nil {
		if err := p.attachments.Inspect(ctx, env); err != nil {
			p.observeAttachment("failed")
			if ae, ok := err.(*attachment.Error); ok {
				dec := RequestDecision{Action: core.ActionBlock, Code: ae.Code}
				ins := &inspection{env: env, start: time.Now(), dec: policy.Decision{Action: core.ActionBlock, PolicyID: p.current().Engine.Policy().ID, PolicyVersion: p.current().Engine.Policy().Version, Code: ae.Code, MatchedRule: "attachment_contract", Reason: "attachment inspection failed"}}
				_ = p.recordAudit(ctx, p.auditEvent(ins))
				return dec, nil
			}
			return RequestDecision{}, err
		}
		p.observeAttachment("allow")
	}
	ins := p.inspectContext(ctx, env)
	var transformed []byte
	switch ins.dec.Action {
	case core.ActionRedact, core.ActionTokenize:
		if hasAttachmentFinding(env, ins.findings) {
			// Binary reconstruction is format-specific and is not claimed by
			// this gateway. A policy transformation must never be reported as
			// successful when the original attachment would still be forwarded.
			ins.dec.Action = core.ActionBlock
			ins.dec.Code = "ATTACHMENT_TRANSFORM_UNSUPPORTED"
			ins.dec.Reason = "attachment transformation is unavailable"
			if err := p.recordAudit(ctx, p.auditEvent(ins)); err != nil {
				return RequestDecision{}, err
			}
			return RequestDecision{Action: core.ActionBlock, Code: ins.dec.Code}, nil
		}
		namer := pii.RedactNamer
		if ins.dec.Action == core.ActionTokenize {
			namer = pii.TokenNamer
		}
		plan := pii.Plan(ins.findings, namer)
		if ins.dec.Action == core.ActionTokenize && ((p.vault != nil && p.crypto != nil) || p.scopedVault != nil) {
			if err := p.storeTokenMappings(env, plan, ins.dec); err != nil {
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

func hasAttachmentFinding(env *core.InspectionEnvelope, findings []core.SecurityFinding) bool {
	for _, finding := range findings {
		if finding.Location.MessageIndex < 0 || finding.Location.MessageIndex >= len(env.Messages) {
			continue
		}
		parts := env.Messages[finding.Location.MessageIndex].Parts
		if finding.Location.PartIndex >= 0 && finding.Location.PartIndex < len(parts) && parts[finding.Location.PartIndex].Attachment != nil {
			return true
		}
	}
	return false
}

func (p *SecurityPipeline) storeTokenMappings(env *core.InspectionEnvelope, plan []pii.Transformation, dec policy.Decision) error {
	if p.scopedVault != nil {
		for i := range plan {
			category := "PII:" + plan[i].Subtype
			scope, err := p.tokenScope(env, dec, category)
			if err != nil {
				return err
			}
			value, ok := valueForTransformation(env, plan[i])
			if !ok {
				continue
			}
			label, err := p.scopedVault.Issue(context.Background(), scope, value)
			if err != nil {
				return err
			}
			plan[i].Replacement = label
		}
		return nil
	}
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

func valueForTransformation(env *core.InspectionEnvelope, t pii.Transformation) (string, bool) {
	for _, lt := range env.TextParts() {
		if lt.MessageIndex != t.MessageIndex || lt.PartIndex != t.PartIndex || t.Start < 0 || t.End > len(lt.Text) || t.Start >= t.End {
			continue
		}
		return lt.Text[t.Start:t.End], true
	}
	return "", false
}

func (p *SecurityPipeline) tokenScope(env *core.InspectionEnvelope, dec policy.Decision, category string) (tokenization.Scope, error) {
	policyID := dec.PolicyID
	policyVersion := dec.PolicyVersion
	if env.Metadata == nil {
		env.Metadata = map[string]string{}
	}
	if env.Metadata["vault_policy_id"] == "" {
		env.Metadata["vault_policy_id"] = policyID
	}
	if env.Metadata["vault_policy_version"] == "" {
		env.Metadata["vault_policy_version"] = strconv.Itoa(policyVersion)
	}
	if env.Metadata != nil {
		if env.Metadata["vault_policy_id"] != "" {
			policyID = env.Metadata["vault_policy_id"]
		}
		if env.Metadata["vault_policy_version"] != "" {
			if parsed, err := strconv.Atoi(env.Metadata["vault_policy_version"]); err == nil {
				policyVersion = parsed
			}
		}
	}
	purpose := tokenization.PurposeResponse
	if env.Metadata != nil && env.Metadata["mcp_server"] != "" {
		purpose = "tool_return:" + env.Metadata["mcp_server"]
	}
	if env.Metadata == nil || env.Metadata["session_binding"] == "" {
		return tokenization.Scope{}, tokenization.ErrScopeRequired
	}
	return tokenization.NewScope(tokenization.ScopeInput{Tenant: env.Tenant, Application: env.Application, Subject: env.User.Subject,
		SessionID: env.Metadata["session_binding"], PolicyID: policyID, PolicyVersion: policyVersion,
		Purpose: purpose, DataCategory: category}, p.scopedVaultMACKey())
}

func (p *SecurityPipeline) scopedVaultMACKey() []byte {
	// ScopedVault owns the key. The pipeline only needs a matching scope
	// derivation; expose a process-local key through the narrow helper below.
	return p.scopedVault.MACKey()
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
			if ins.dec.Action == core.ActionTokenize && ((p.vault != nil && p.crypto != nil) || p.scopedVault != nil) {
				if err := p.storeTokenMappings(env, plan, ins.dec); err != nil {
					return StreamTextOutcome{}, err
				}
			}
			out.Text = pii.ApplyToText(text, plan)
		}
		if p.scopedVault != nil && kind != "tool_arguments" {
			out.Text = p.restoreScopedText(reqEnv, ins.dec, out.Text)
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

var scopedPlaceholderPattern = regexp.MustCompile(`<v1(?:\.[A-Za-z0-9:_-]+){3,4}>`)

func (p *SecurityPipeline) restoreScopedText(env *core.InspectionEnvelope, dec policy.Decision, text string) string {
	return scopedPlaceholderPattern.ReplaceAllStringFunc(text, func(label string) string {
		scope, err := p.tokenScope(env, dec, "unknown")
		if err != nil {
			return label
		}
		value, err := p.scopedVault.Retrieve(context.Background(), scope, label)
		if err != nil {
			return label
		}
		return value
	})
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
	if p.attachments != nil {
		if err := p.attachments.Inspect(context.Background(), respEnv); err != nil {
			p.observeAttachment("failed")
			if ae, ok := err.(*attachment.Error); ok {
				ins := &inspection{env: respEnv, start: time.Now(), dec: policy.Decision{Action: core.ActionBlock, Code: ae.Code, Reason: "attachment inspection failed"}}
				_ = p.recordAudit(context.Background(), p.auditEvent(ins))
				return ResponseOutcome{Action: core.ActionBlock, Code: ae.Code}, nil
			}
			return ResponseOutcome{}, err
		}
		p.observeAttachment("allow")
	}
	ins := p.inspect(respEnv)
	outcome := ResponseOutcome{Action: ins.dec.Action, Code: ins.dec.Code}
	switch ins.dec.Action {
	case core.ActionBlock, core.ActionReview:
	case core.ActionRedact, core.ActionTokenize:
		if hasAttachmentFinding(respEnv, ins.findings) {
			ins.dec.Action = core.ActionBlock
			ins.dec.Code = "ATTACHMENT_TRANSFORM_UNSUPPORTED"
			ins.dec.Reason = "attachment transformation is unavailable"
			outcome.Action, outcome.Code = ins.dec.Action, ins.dec.Code
			break
		}
		plan := pii.Plan(ins.findings, pii.RedactNamer)
		outcome.Transformations = plan
	}
	if ins.dec.Action != core.ActionBlock && ins.dec.Action != core.ActionReview && p.scopedVault != nil && responseRestoreAllowed(raw) {
		body, changed, rerr := replacePlaceholdersInNormalizerBody(raw, normalizer, func(label string) (string, bool) {
			dec := ins.dec
			category := "unknown"
			scope, err := p.tokenScope(reqEnv, dec, category)
			if err != nil {
				return "", false
			}
			value, err := p.scopedVault.Retrieve(context.Background(), scope, label)
			if err != nil {
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
	} else if ins.dec.Action != core.ActionBlock && ins.dec.Action != core.ActionReview && p.vault != nil && p.crypto != nil {
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

func (p *SecurityPipeline) observeAttachment(outcome string) {
	if observer, ok := p.recorder.(interface{ ObserveAttachment(string, string) }); ok && p.attachments != nil {
		observer.ObserveAttachment(outcome, p.attachments.Status().Adapter)
	}
}

func responseRestoreAllowed(raw []byte) bool {
	// Assistant tool calls are an untrusted execution boundary. Leaving an
	// opaque placeholder there is safer than restoring data into a tool call.
	text := string(raw)
	for _, marker := range []string{"\"tool_calls\"", "\"function_call\"", "\"tool_use\"", "\"tool_result\""} {
		if strings.Contains(text, marker) {
			return false
		}
	}
	return true
}

func deriveResponseEnvelope(respEnv, reqEnv *core.InspectionEnvelope) {
	respEnv.RequestID = reqEnv.RequestID
	respEnv.Application = reqEnv.Application
	respEnv.Tenant = reqEnv.Tenant
	respEnv.User = reqEnv.User
	respEnv.Target.Provider = reqEnv.Target.Provider
}
