package policy

import (
	"fmt"
	"sort"
	"strings"

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

// PrecedenceStage is the stable, operator-visible stage which selected an
// action. These values are part of the policy/audit contract.
type PrecedenceStage string

const (
	StageExplicitDeny        PrecedenceStage = "explicit_deny"
	StageCanonicalization    PrecedenceStage = "canonicalization"
	StageSecretProtection    PrecedenceStage = "secret_protection"
	StageTenantRestriction   PrecedenceStage = "tenant_restriction"
	StageApplication         PrecedenceStage = "application_restriction"
	StageIdentityRestriction PrecedenceStage = "identity_restriction"
	StageProviderBoundary    PrecedenceStage = "provider_boundary"
	StagePIITransformation   PrecedenceStage = "pii_transformation"
	StageSemanticRisk        PrecedenceStage = "semantic_risk"
	StageDefault             PrecedenceStage = "default"
	StageSafeDefault         PrecedenceStage = "safe_default"
	StageFallback            PrecedenceStage = "fallback"
)

// Decision is the engine's deterministic output (T-011). It contains only
// stable policy metadata; it never contains finding values or hashes.
type Decision struct {
	Action          core.Action     `json:"action"`
	PolicyID        string          `json:"policy_id"`
	PolicyVersion   int             `json:"policy_version"`
	MatchedRule     string          `json:"matched_rule,omitempty"`
	PrecedenceStage PrecedenceStage `json:"precedence_stage,omitempty"`
	Code            string          `json:"code,omitempty"`
	Reason          string          `json:"reason,omitempty"`
}

// FindingSummary is the sanitized projection shared by runtime audit and the
// policy simulator. Confidence is bucketed so exact detector scores are not
// exposed by operator tooling.
type FindingSummary struct {
	Category         core.FindingCategory `json:"category"`
	Subtype          string               `json:"subtype"`
	Count            int                  `json:"count"`
	ConfidenceBucket string               `json:"confidence_bucket"`
}

// Explanation is the single explainability result used by runtime and CLI.
// Evaluate is intentionally implemented in terms of Explain so there is no
// second decision implementation to drift from production behavior.
type Explanation struct {
	Decision Decision         `json:"decision"`
	Findings []FindingSummary `json:"findings,omitempty"`
}

var actionSeverity = map[core.Action]int{
	core.ActionBlock:           7,
	core.ActionRestrictTools:   6,
	core.ActionForceLocalModel: 5,
	core.ActionReview:          4,
	core.ActionTokenize:        3,
	core.ActionRedact:          2,
	core.ActionAllow:           1,
}

// Engine evaluates findings, evidence, and context against one validated
// policy document. It performs no I/O and no model calls (handoff T-011).
type Engine struct {
	policy *Policy
}

func NewEngine(p *Policy) *Engine { return &Engine{policy: p} }

// Policy returns the validated policy used by the engine.
func (e *Engine) Policy() *Policy { return e.policy }

// RestrictedTools exposes the policy's RESTRICT_TOOLS tool list (T-025).
func (e *Engine) RestrictedTools() []string { return e.policy.RestrictedTools() }

// Evaluate returns the same decision embedded in Explain.
func (e *Engine) Evaluate(ctx Context) Decision { return e.Explain(ctx).Decision }

// Explain applies the precedence chain from spec §7 and returns sanitized
// finding summaries plus the selected rule/stage.
func (e *Engine) Explain(ctx Context) Explanation {
	return Explanation{Decision: e.evaluate(ctx), Findings: summarizeFindings(ctx.Findings)}
}

func (e *Engine) evaluate(ctx Context) Decision {
	base := Decision{PolicyID: e.policy.ID, PolicyVersion: e.policy.Version}
	dec := func(action core.Action, rule string, stage PrecedenceStage, code, reason string) Decision {
		base.Action, base.MatchedRule, base.PrecedenceStage, base.Code, base.Reason = action, rule, stage, code, reason
		return base
	}
	env := ctx.Envelope

	for i, rule := range e.policy.Deny {
		if rule.matches(env) {
			return dec(rule.Action.Action, fmt.Sprintf("deny[%d]", i), StageExplicitDeny, "POLICY_DENIED", "explicit deny rule matched")
		}
	}

	if d, ok := e.bestEvasion(ctx); ok {
		return d
	}

	if d, ok := e.bestFinding(core.CategorySecret, ctx); ok {
		return d
	}

	if env != nil {
		if rule, ok := e.policy.Tenants[env.Tenant]; ok {
			return dec(rule.Action, "tenants."+env.Tenant, StageTenantRestriction, "TENANT_RESTRICTED", "tenant restriction matched")
		}
		if rule, ok := e.policy.Applications[env.Application]; ok {
			return dec(rule.Action, "applications."+env.Application, StageApplication, "APPLICATION_RESTRICTED", "application restriction matched")
		}
		if d, ok := e.bestRole(env); ok {
			d.PrecedenceStage = StageIdentityRestriction
			return d
		}
		if d, ok := e.bestPII(ctx); ok {
			return d
		}
	}

	if d, ok := e.bestSemantic(ctx.Semantic); ok {
		return d
	}
	return dec(e.policy.Default.Action, "default", StageDefault, "", "no rule matched; default action")
}

func (e *Engine) bestEvasion(ctx Context) (Decision, bool) {
	var best candidate
	found := false
	for _, f := range ctx.Findings {
		evasionType := ""
		if f.Attributes != nil {
			evasionType = f.Attributes["evasion_type"]
		}
		if evasionType == "" && f.Attributes != nil && f.Attributes["unsafe_span"] == "true" {
			evasionType = "unsafe_span"
		}
		if evasionType == "" {
			continue
		}
		rule, ok := e.policy.Evasion.Actions[evasionType+"/"+string(f.Category)]
		if !ok {
			rule, ok = e.policy.Evasion.Actions[evasionType]
		}
		if !ok {
			switch {
			case f.Category == core.CategorySecret:
				rule = ActionRule{Action: core.ActionBlock}
			case f.Category == core.CategoryPII:
				rule = ActionRule{Action: core.ActionReview}
			case evasionType == "budget_exceeded":
				rule = e.policy.Evasion.BudgetAction
			default:
				continue
			}
		}
		if rule.Action == "" {
			rule = e.policy.SafeDefault
		}
		c := candidate{action: rule.Action, rule: "evasion." + evasionType, stage: StageCanonicalization, priority: 20}
		if !found || betterCandidate(c, best) {
			best, found = c, true
		}
	}
	if !found {
		return Decision{}, false
	}
	return Decision{Action: best.action, PolicyID: e.policy.ID, PolicyVersion: e.policy.Version,
		MatchedRule: best.rule, PrecedenceStage: best.stage, Code: "EVASION_REJECTED",
		Reason: "bounded canonicalization policy rejected an unsafe or over-budget representation"}, true
}

type candidate struct {
	action   core.Action
	rule     string
	stage    PrecedenceStage
	priority int
}

func (e *Engine) bestFinding(category core.FindingCategory, ctx Context) (Decision, bool) {
	env := ctx.Envelope
	provider := ""
	if env != nil {
		provider = env.Target.Provider
	}
	var best candidate
	found := false
	for _, f := range ctx.Findings {
		if f.Category != category {
			continue
		}
		base, ok := e.actionForFinding(f, provider)
		if !ok {
			base = candidate{action: e.policy.SafeDefault.Action, rule: "safe_default", stage: StageSafeDefault, priority: 0}
		}
		if !found || betterCandidate(base, best) {
			best, found = base, true
		}
		for _, rule := range e.policy.ConfidenceEscalation {
			if rule.Category != string(f.Category) || rule.Subtype != "" && rule.Subtype != f.Subtype || rule.Provider != "" && rule.Provider != provider || f.Confidence < rule.MinConfidence {
				continue
			}
			c := candidate{action: rule.Action.Action, rule: "confidence." + rule.ID, stage: stageForCategory(category), priority: 1}
			if !found || betterCandidate(c, best) {
				best, found = c, true
			}
		}
	}
	for _, rule := range e.policy.FindingCountEscalation {
		if rule.Category != string(category) || rule.Provider != "" && rule.Provider != provider {
			continue
		}
		count := 0
		for _, f := range ctx.Findings {
			if f.Category == category && (rule.Subtype == "" || f.Subtype == rule.Subtype) {
				count++
			}
		}
		if count < rule.MinCount {
			continue
		}
		ruleID := "count." + rule.ID
		if rule.displayRule != "" {
			ruleID = rule.displayRule
		}
		c := candidate{action: rule.Action.Action, rule: ruleID, stage: stageForCategory(category), priority: 1}
		if !found || betterCandidate(c, best) {
			best, found = c, true
		}
	}
	if !found {
		return Decision{}, false
	}
	code := "PII_DETECTED"
	if category == core.CategorySecret {
		code = "SECRET_DETECTED"
	}
	return Decision{Action: best.action, PolicyID: e.policy.ID, PolicyVersion: e.policy.Version,
		MatchedRule: best.rule, PrecedenceStage: best.stage, Code: code,
		Reason: "validated policy rule " + best.rule + " matched " + strings.ToLower(string(category)) + " findings"}, true
}

func stageForCategory(category core.FindingCategory) PrecedenceStage {
	if category == core.CategorySecret {
		return StageSecretProtection
	}
	return StagePIITransformation
}

func (e *Engine) actionForFinding(f core.SecurityFinding, provider string) (candidate, bool) {
	category := string(f.Category)
	if f.Category == core.CategorySecret {
		if rule, ok := e.policy.Secrets[f.Subtype]; ok {
			return candidate{action: rule.Action, rule: "secrets." + f.Subtype, stage: StageSecretProtection, priority: 10}, true
		}
	}
	if f.Category == core.CategoryPII {
		if rule, ok := e.policy.PII[f.Subtype]; ok {
			if action, ok := rule.Providers[provider]; ok {
				return candidate{action: action.Action, rule: "pii." + f.Subtype + "." + provider, stage: StagePIITransformation, priority: 10}, true
			}
		}
		if rule, ok := e.policy.Targets[provider]; ok && rule.ConfidentialData.Action != "" {
			return candidate{action: rule.ConfidentialData.Action, rule: "targets." + provider, stage: StageProviderBoundary, priority: 5}, true
		}
	}
	if override, ok := e.policy.ProviderOverrides[provider]; ok {
		if rule, ok := override.Subtypes[f.Subtype]; ok {
			return candidate{rule.Action, "providers." + provider + ".subtypes." + f.Subtype, stageForCategory(f.Category), 9}, true
		}
	}
	if override, ok := e.policy.ProviderOverrides[provider]; ok {
		if rule, ok := override.Categories[category]; ok {
			return candidate{rule.Action, "providers." + provider + ".categories." + category, StageProviderBoundary, 5}, true
		}
	}
	if rule, ok := e.policy.SubtypeActions[category][f.Subtype]; ok {
		return candidate{rule.Action, "subtype_actions." + category + "." + f.Subtype, stageForCategory(f.Category), 8}, true
	}
	if rule, ok := e.policy.CategoryActions[category]; ok {
		return candidate{rule.Action, "category_actions." + category, stageForCategory(f.Category), 4}, true
	}
	return candidate{}, false
}

func (e *Engine) bestRole(env *core.InspectionEnvelope) (Decision, bool) {
	var best candidate
	found := false
	for _, role := range env.User.Roles {
		rule, ok := e.policy.Roles[role]
		if !ok {
			continue
		}
		c := candidate{action: rule.Action, rule: "roles." + role, stage: StageIdentityRestriction, priority: 1}
		if !found || betterCandidate(c, best) {
			best, found = c, true
		}
	}
	if !found {
		return Decision{}, false
	}
	return Decision{Action: best.action, PolicyID: e.policy.ID, PolicyVersion: e.policy.Version,
		MatchedRule: best.rule, PrecedenceStage: best.stage, Code: "ROLE_RESTRICTED", Reason: "role restriction matched " + best.rule}, true
}

func (e *Engine) bestPII(ctx Context) (Decision, bool) {
	return e.bestFinding(core.CategoryPII, ctx)
}

func (e *Engine) bestSemantic(signals []SemanticSignal) (Decision, bool) {
	type semanticCandidate struct {
		question, risk string
		action         core.Action
	}
	var candidates []semanticCandidate
	for _, sig := range signals {
		if !sig.Triggered {
			continue
		}
		rule, ok := e.policy.Semantic[sig.QuestionID]
		if !ok {
			continue
		}
		ar, ok := rule.ForRisk(sig.Risk)
		if ok {
			candidates = append(candidates, semanticCandidate{sig.QuestionID, sig.Risk, ar.Action})
		}
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
	rule := "semantic." + best.question + "." + best.risk
	return Decision{Action: best.action, PolicyID: e.policy.ID, PolicyVersion: e.policy.Version,
		MatchedRule: rule, PrecedenceStage: StageSemanticRisk, Code: semanticCode(best.question),
		Reason: fmt.Sprintf("semantic question %s triggered at %s risk", best.question, best.risk)}, true
}

// LayaUnavailableFallback returns the policy-controlled action for a high-risk
// route. A Laya failure never silently becomes ALLOW.
func (e *Engine) LayaUnavailableFallback() (Decision, bool) {
	if e.policy.Fallback == nil || e.policy.Fallback.LayaUnavailable.HighRisk.Action == "" {
		return Decision{}, false
	}
	f := e.policy.Fallback.LayaUnavailable
	return Decision{Action: f.HighRisk.Action, PolicyID: e.policy.ID, PolicyVersion: e.policy.Version,
		MatchedRule: "fallback.laya_unavailable.high_risk", PrecedenceStage: StageFallback,
		Code: "LAYA_UNAVAILABLE", Reason: "semantic engine unavailable; policy fallback applied"}, true
}

// SemanticFallback resolves the most specific configured fallback for an
// evidence error. A missing rule deliberately returns false so callers can
// retain the deterministic decision; strict policies should configure high
// risk rules explicitly.
func (e *Engine) SemanticFallback(risk, direction, provider, reason string) (Decision, bool) {
	if e.policy.Fallback == nil {
		return Decision{}, false
	}
	best := -1
	bestScore := -1
	for i, rule := range e.policy.Fallback.Semantic {
		if rule.Risk != risk || !fallbackDimensionMatches(rule.Direction, direction) || !fallbackDimensionMatches(rule.Provider, provider) {
			continue
		}
		score := 0
		if rule.Direction != "" && rule.Direction != "*" {
			score++
		}
		if rule.Provider != "" && rule.Provider != "*" {
			score++
		}
		if score > bestScore {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		if risk != "high" {
			return Decision{}, false
		}
		return e.LayaUnavailableFallback()
	}
	rule := e.policy.Fallback.Semantic[best]
	return Decision{Action: rule.OnError.Action, PolicyID: e.policy.ID, PolicyVersion: e.policy.Version,
		MatchedRule: "fallback.semantic." + risk, PrecedenceStage: StageFallback,
		Code: "SEMANTIC_EVIDENCE_REJECTED", Reason: "semantic evidence rejected; " + reason}, true
}

func fallbackDimensionMatches(pattern, value string) bool {
	return pattern == "" || pattern == "*" || strings.EqualFold(pattern, value)
}

func betterCandidate(a, b candidate) bool {
	if actionSeverity[a.action] != actionSeverity[b.action] {
		return actionSeverity[a.action] > actionSeverity[b.action]
	}
	if a.priority != b.priority {
		return a.priority > b.priority
	}
	return a.rule < b.rule
}

func semanticCode(questionID string) string {
	var b strings.Builder
	for _, r := range questionID {
		if r >= 'a' && r <= 'z' {
			b.WriteRune(r - 'a' + 'A')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String() + "_RISK"
}

func summarizeFindings(findings []core.SecurityFinding) []FindingSummary {
	type key struct {
		category core.FindingCategory
		subtype  string
	}
	byKey := map[key]*FindingSummary{}
	for _, f := range findings {
		k := key{f.Category, f.Subtype}
		s, ok := byKey[k]
		if !ok {
			s = &FindingSummary{Category: f.Category, Subtype: f.Subtype, ConfidenceBucket: ConfidenceBucket(f.Confidence)}
			byKey[k] = s
		}
		s.Count++
		if bucketRank(ConfidenceBucket(f.Confidence)) > bucketRank(s.ConfidenceBucket) {
			s.ConfidenceBucket = ConfidenceBucket(f.Confidence)
		}
	}
	out := make([]FindingSummary, 0, len(byKey))
	for _, s := range byKey {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Subtype < out[j].Subtype
	})
	return out
}

// ConfidenceBucket is the only confidence representation exposed by the
// simulator and runtime explanation projection.
func ConfidenceBucket(confidence float64) string {
	switch {
	case confidence >= 0.9:
		return "very_high"
	case confidence >= 0.8:
		return "high"
	case confidence >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

func bucketRank(bucket string) int {
	return map[string]int{"low": 1, "medium": 2, "high": 3, "very_high": 4}[bucket]
}
