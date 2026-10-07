package gateway

import (
	"context"
	"fmt"
	"time"

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
	if env.Metadata["skipped_stream"] == "true" {
		ins.dec.Action = core.ActionAllow
		ins.dec.Code = "SKIPPED_STREAM"
		ins.dec.MatchedRule = "skipped_stream"
		p.audit.Record(p.auditEvent(ins))
		return RequestDecision{Action: core.ActionAllow, Code: "SKIPPED_STREAM"}, nil
	}
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
		p.audit.Record(p.auditEvent(ins))
		return RequestDecision{Action: ins.dec.Action, Code: ins.dec.Code, Transformations: plan}, nil
	case core.ActionRestrictTools:
		body, err := stripRestrictedTools(raw, p.engine.RestrictedTools())
		if err != nil {
			return RequestDecision{}, err
		}
		transformed = body
	}
	p.audit.Record(p.auditEvent(ins))
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

// AuditPassthrough records a body-free ALLOW event for endpoints such as
// GET /v1/models. It deliberately never runs a content detector over a body.
func (p *SecurityPipeline) AuditPassthrough(env *core.InspectionEnvelope) {
	if env.Metadata == nil {
		env.Metadata = map[string]string{}
	}
	env.Metadata["passthrough"] = "true"
	ins := p.inspect(env)
	if p.audit != nil {
		p.audit.Record(p.auditEvent(ins))
	}
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
	p.audit.Record(p.auditEvent(ins))
	return outcome, nil
}

func deriveResponseEnvelope(respEnv, reqEnv *core.InspectionEnvelope) {
	respEnv.RequestID = reqEnv.RequestID
	respEnv.Application = reqEnv.Application
	respEnv.Tenant = reqEnv.Tenant
	respEnv.User = reqEnv.User
	respEnv.Target.Provider = reqEnv.Target.Provider
}
