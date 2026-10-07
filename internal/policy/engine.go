package policy

import (
	"fmt"
	"sort"

	"github.com/aegisllm/gateway/internal/core"
)

// SemanticSignal is normalized Laya evidence for one question (INV-002:
// evidence, not permission). The adapter fills Risk from the question schema.
type SemanticSignal struct {
	QuestionID string
	Triggered  bool
	Confidence float64
	Risk       string // "high" | "medium" | "low"
}

// Context carries everything the engine needs to reach a decision. It must be
// sufficient to reproduce the decision later from sanitized evidence.
type Context struct {
	Envelope *core.InspectionEnvelope
	Findings []core.SecurityFinding
	Semantic []SemanticSignal
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

// actionSeverity ranks sibling actions within one precedence level so that
// conflict resolution is order-independent (higher wins). Within one severity,
// the lexicographically smaller rule identifier wins.
var actionSeverity = map[core.Action]int{
	core.ActionBlock:           7,
	core.ActionRestrictTools:   6,
	core.ActionForceLocalModel: 5,
	core.ActionReview:          4,
	core.ActionTokenize:        3,
	core.ActionRedact:          2,
	core.ActionAllow:           1,
}

var highRiskSecretSubtypes = map[string]bool{
	"PEM_PRIVATE_KEY":       true,
	"AWS_SECRET_ACCESS_KEY": true,
	"GITLAB_PAT":            true,
	"GITHUB_TOKEN":          true,
	"OPENAI_KEY":            true, // legacy policy alias
	"OPENAI_API_KEY":        true,
}

// Engine evaluates findings, evidence, and context against one policy
// document. It performs no I/O and no model calls (handoff T-011).
type Engine struct {
	policy *Policy
}

func NewEngine(p *Policy) *Engine {
	return &Engine{policy: p}
}

// RestrictedTools exposes the policy's RESTRICT_TOOLS tool list (T-025).
func (e *Engine) RestrictedTools() []string {
	return e.policy.RestrictedTools()
}

// Evaluate applies the precedence chain from spec §7:
//
//  1. explicit deny                      5. provider-boundary policy
//  2. secret protection                  6. PII transformation policy
//  3. tenant/application restriction     7. semantic risk policy
//  4. identity/role restriction          8. default action
//
// The first level with a match wins; within a level the most severe action
// wins, ties broken lexicographically. Deterministic by construction.
func (e *Engine) Evaluate(ctx Context) Decision {
	base := Decision{PolicyID: e.policy.ID, PolicyVersion: e.policy.Version}
	dec := func(action core.Action, rule, code, reason string) Decision {
		d := base
		d.Action, d.MatchedRule, d.Code, d.Reason = action, rule, code, reason
		return d
	}
	env := ctx.Envelope

	// 1. Explicit deny.
	for i, rule := range e.policy.Deny {
		if rule.matches(env) {
			return dec(rule.Action.Action, fmt.Sprintf("deny[%d]", i), "POLICY_DENIED",
				"explicit deny rule matched")
		}
	}

	// 2. Secret protection.
	if d, ok := e.bestSecret(ctx.Findings); ok {
		d.PolicyID, d.PolicyVersion = base.PolicyID, base.PolicyVersion
		return d
	}

	if env != nil {
		// 3. Tenant, then application restriction.
		if rule, ok := e.policy.Tenants[env.Tenant]; ok {
			return dec(rule.Action, "tenants."+env.Tenant, "TENANT_RESTRICTED",
				"tenant restriction matched")
		}
		if rule, ok := e.policy.Applications[env.Application]; ok {
			return dec(rule.Action, "applications."+env.Application, "APPLICATION_RESTRICTED",
				"application restriction matched")
		}

		// 4. Identity/role restriction.
		if d, ok := e.bestRole(env); ok {
			d.PolicyID, d.PolicyVersion = base.PolicyID, base.PolicyVersion
			return d
		}

		// 5 + 6. Provider boundary, refined by PII subtype transformation.
		if d, ok := e.piiTransformation(env, ctx.Findings); ok {
			d.PolicyID, d.PolicyVersion = base.PolicyID, base.PolicyVersion
			return d
		}
	}

	// 7. Semantic risk.
	if d, ok := e.bestSemantic(ctx.Semantic); ok {
		d.PolicyID, d.PolicyVersion = base.PolicyID, base.PolicyVersion
		return d
	}

	// 8. Default.
	return dec(e.policy.Default.Action, "default", "", "no rule matched; default action")
}

// bestSecret picks the most severe action among secret findings with rules.
func (e *Engine) bestSecret(findings []core.SecurityFinding) (Decision, bool) {
	var bestRule string
	var bestAction core.Action
	found := false
	for _, f := range findings {
		if f.Category != core.CategorySecret {
			continue
		}
		action := core.ActionRedact
		if rule, ok := e.policy.Secrets[f.Subtype]; ok && rule.Action != "" {
			action = rule.Action
			if action == core.ActionAllow {
				action = core.ActionRedact
			}
		}
		if f.Confidence >= 0.9 || highRiskSecretSubtypes[f.Subtype] {
			action = core.ActionBlock
		}
		if !found || better(f.Subtype, action, bestRule, bestAction) {
			bestRule, bestAction, found = "secrets."+f.Subtype, action, true
		}
	}
	if !found {
		return Decision{}, false
	}
	return Decision{
		Action:      bestAction,
		MatchedRule: bestRule,
		Code:        "SECRET_DETECTED",
		Reason:      "secret finding matched " + bestRule,
	}, true
}

// bestRole picks the most severe role restriction covering the caller.
func (e *Engine) bestRole(env *core.InspectionEnvelope) (Decision, bool) {
	var bestRule string
	var bestAction core.Action
	found := false
	for _, role := range env.User.Roles {
		rule, ok := e.policy.Roles[role]
		if !ok {
			continue
		}
		if !found || better("roles."+role, rule.Action, bestRule, bestAction) {
			bestRule, bestAction, found = "roles."+role, rule.Action, true
		}
	}
	if !found {
		return Decision{}, false
	}
	return Decision{
		Action:      bestAction,
		MatchedRule: bestRule,
		Code:        "ROLE_RESTRICTED",
		Reason:      "role restriction matched " + bestRule,
	}, true
}

// piiTransformation implements levels 5 and 6: a provider's confidential-data
// baseline applies only when PII findings exist, and a per-subtype PII rule
// for that provider refines (wins over) the baseline.
func (e *Engine) piiTransformation(env *core.InspectionEnvelope, findings []core.SecurityFinding) (Decision, bool) {
	piiCount := 0
	for _, f := range findings {
		if f.Category == core.CategoryPII {
			piiCount++
		}
	}
	if piiCount == 0 {
		return Decision{}, false
	}
	provider := env.Target.Provider

	// MULTIPLE_PII is an optional policy pseudo-subtype. It keeps the policy
	// schema additive while allowing a tenant to escalate a dense PII payload
	// at the same precedence level as ordinary PII transformations.
	if piiCount >= 3 {
		if rule, ok := e.policy.PII["MULTIPLE_PII"]; ok {
			if ar, ok := rule.Providers[provider]; ok && ar.Action != "" {
				return Decision{
					Action:      ar.Action,
					MatchedRule: "pii.MULTIPLE_PII." + provider,
					Reason:      "multiple PII findings matched for provider " + provider,
				}, true
			}
		}
	}

	// 6. Per-subtype PII transformation policy.
	var bestRule string
	var bestAction core.Action
	found := false
	for _, f := range findings {
		if f.Category != core.CategoryPII {
			continue
		}
		piiRule, ok := e.policy.PII[f.Subtype]
		if !ok {
			continue
		}
		ar, ok := piiRule.Providers[provider]
		if !ok {
			continue
		}
		if !found || better("pii."+f.Subtype+"."+provider, ar.Action, bestRule, bestAction) {
			bestRule, bestAction, found = "pii."+f.Subtype+"."+provider, ar.Action, true
		}
	}
	if found {
		return Decision{
			Action:      bestAction,
			MatchedRule: bestRule,
			Reason:      "PII transformation rule matched for provider " + provider,
		}, true
	}

	// 5. Provider-boundary baseline for confidential data.
	if tr, ok := e.policy.Targets[provider]; ok && tr.ConfidentialData.Action != "" {
		return Decision{
			Action:      tr.ConfidentialData.Action,
			MatchedRule: "targets." + provider,
			Reason:      "provider-boundary confidential-data policy for " + provider,
		}, true
	}
	return Decision{}, false
}

// bestSemantic picks the most severe triggered semantic rule; ties break on
// the lexicographically smaller question id.
func (e *Engine) bestSemantic(signals []SemanticSignal) (Decision, bool) {
	type cand struct {
		question string
		action   core.Action
		risk     string
	}
	var candidates []cand
	for _, sig := range signals {
		if !sig.Triggered {
			continue
		}
		rule, ok := e.policy.Semantic[sig.QuestionID]
		if !ok {
			continue
		}
		ar, ok := rule.ForRisk(sig.Risk)
		if !ok {
			continue
		}
		candidates = append(candidates, cand{question: sig.QuestionID, action: ar.Action, risk: sig.Risk})
	}
	if len(candidates) == 0 {
		return Decision{}, false
	}
	sort.Slice(candidates, func(i, j int) bool {
		si, sj := actionSeverity[candidates[i].action], actionSeverity[candidates[j].action]
		if si != sj {
			return si > sj
		}
		return candidates[i].question < candidates[j].question
	})
	best := candidates[0]
	return Decision{
		Action:      best.action,
		MatchedRule: "semantic." + best.question + "." + best.risk,
		Code:        semanticCode(best.question),
		Reason:      fmt.Sprintf("semantic question %s triggered at %s risk", best.question, best.risk),
	}, true
}

// LayaUnavailableFallback returns the policy-controlled action for a
// high-risk route when the semantic engine is unavailable (architecture §16,
// AS-004, NFR-AVAIL-003): a Laya failure must never silently become ALLOW.
func (e *Engine) LayaUnavailableFallback() (Decision, bool) {
	if e.policy.Fallback == nil {
		return Decision{}, false
	}
	f := e.policy.Fallback.LayaUnavailable
	if f.HighRisk.Action == "" {
		return Decision{}, false
	}
	return Decision{
		Action:        f.HighRisk.Action,
		PolicyID:      e.policy.ID,
		PolicyVersion: e.policy.Version,
		MatchedRule:   "fallback.laya_unavailable.high_risk",
		Code:          "LAYA_UNAVAILABLE",
		Reason:        "semantic engine unavailable on a high-risk route; policy fallback applied",
	}, true
}

// better reports whether candidate (id, action) should replace the current
// best: more severe action wins, ties go to the lexicographically smaller id.
func better(id string, action core.Action, bestID string, bestAction core.Action) bool {
	sa, sb := actionSeverity[action], actionSeverity[bestAction]
	if sa != sb {
		return sa > sb
	}
	return id < bestID
}

// semanticCode derives a stable spec §9-style code from the question id.
func semanticCode(questionID string) string {
	code := ""
	for _, r := range questionID {
		if r == '_' {
			code += "_"
			continue
		}
		if r >= 'a' && r <= 'z' {
			code += string(r - 'a' + 'A')
			continue
		}
		code += string(r)
	}
	return code + "_RISK"
}
