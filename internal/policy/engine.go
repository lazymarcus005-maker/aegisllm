package policy

import (
	"fmt"

	"github.com/aegisllm/gateway/internal/core"
)

// Context carries everything the engine needs to reach a decision. It must be
// sufficient to reproduce the decision later from sanitized evidence.
type Context struct {
	Envelope *core.InspectionEnvelope
	Findings []core.SecurityFinding
}

// Decision is the engine's deterministic output (T-011).
type Decision struct {
	Action        core.Action
	PolicyID      string
	PolicyVersion int
	MatchedRule   string // e.g. "secrets.GITLAB_PAT" or "default"
	Code          string // spec §9 error code for rejections
	Reason        string
}

// Engine evaluates findings and evidence against one policy document.
// It performs no I/O and no model calls (handoff T-011).
type Engine struct {
	policy *Policy
}

func NewEngine(p *Policy) *Engine {
	return &Engine{policy: p}
}

// Evaluate applies the precedence chain. Ticket 02 implements the prefix of
// the chain that exists so far: secret rules > default. Later tickets extend
// this method ticket by ticket, preserving determinism.
func (e *Engine) Evaluate(ctx Context) Decision {
	base := Decision{
		PolicyID:      e.policy.ID,
		PolicyVersion: e.policy.Version,
	}

	// 1. Secret protection rules.
	for _, f := range ctx.Findings {
		if f.Category != core.CategorySecret {
			continue
		}
		if rule, ok := e.policy.Secrets[f.Subtype]; ok {
			base.Action = rule.Action
			base.MatchedRule = "secrets." + f.Subtype
			base.Code = secretCode(f.Subtype)
			base.Reason = fmt.Sprintf("secret finding %s matched secrets.%s", f.Subtype, f.Subtype)
			return base
		}
	}

	// 2. Default action.
	base.Action = e.policy.Default.Action
	base.MatchedRule = "default"
	base.Reason = "no rule matched; default action"
	return base
}

// secretCode maps secret subtypes to the spec §9 error code family.
func secretCode(subtype string) string {
	return "SECRET_DETECTED"
}
