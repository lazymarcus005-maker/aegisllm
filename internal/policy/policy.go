// Package policy implements policy-as-code: versioned YAML documents, strict
// validation, and a deterministic engine whose output depends only on its
// inputs (FR-012, SEC-005).
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strings"

	"github.com/aegisllm/gateway/internal/core"
	"gopkg.in/yaml.v3"
)

// ActionRule maps a condition to a policy action. Actions are case-insensitive
// in YAML (spec §8 examples use lowercase) and normalize to the canonical
// uppercase form at parse time.
type ActionRule struct {
	Action core.Action `yaml:"action"`
}

// UnmarshalYAML accepts both shapes used by the spec §8 examples: a bare
// action string (`confidential_data: tokenize`) or a mapping with an action
// key (`action: block`). Values are case-insensitive; unknown actions are
// rejected at load time.
func (r *ActionRule) UnmarshalYAML(value *yaml.Node) error {
	normalize := func(s string) (core.Action, error) {
		a := core.Action(strings.ToUpper(strings.TrimSpace(s)))
		if !isValidAction(a) {
			return "", fmt.Errorf("action %q is not a known action", s)
		}
		return a, nil
	}
	switch value.Kind {
	case yaml.ScalarNode:
		a, err := normalize(value.Value)
		if err != nil {
			return err
		}
		r.Action = a
		return nil
	case yaml.MappingNode:
		var raw map[string]yaml.Node
		if err := value.Decode(&raw); err != nil {
			return err
		}
		for key := range raw {
			if key != "action" {
				return fmt.Errorf("action rule: unknown field %q", key)
			}
		}
		node, ok := raw["action"]
		if !ok || node.Kind != yaml.ScalarNode {
			return errors.New("action rule.action is required")
		}
		a, err := normalize(node.Value)
		if err != nil {
			return err
		}
		r.Action = a
		return nil
	default:
		return fmt.Errorf("action rule must be a string or a mapping with an action key")
	}
}

// DenyRule is an explicit deny condition — the top of the precedence chain.
// At least one matcher must be set.
type DenyRule struct {
	Application string     `yaml:"when_application,omitempty"`
	Tenant      string     `yaml:"when_tenant,omitempty"`
	UserSubject string     `yaml:"when_user,omitempty"`
	Role        string     `yaml:"when_role,omitempty"`
	Action      ActionRule `yaml:"action"`
}

func (d DenyRule) matches(env *core.InspectionEnvelope) bool {
	if env == nil {
		return false
	}
	matched := false
	if d.Application != "" {
		if d.Application != env.Application {
			return false
		}
		matched = true
	}
	if d.Tenant != "" {
		if d.Tenant != env.Tenant {
			return false
		}
		matched = true
	}
	if d.UserSubject != "" {
		if d.UserSubject != env.User.Subject {
			return false
		}
		matched = true
	}
	if d.Role != "" {
		if !slices.Contains(env.User.Roles, d.Role) {
			return false
		}
		matched = true
	}
	return matched
}

// PIIRule assigns transformation actions per target provider class.
type PIIRule struct {
	Providers map[string]ActionRule `yaml:"providers"`
}

// TargetRule is a provider-boundary policy (precedence level 5): the baseline
// treatment of confidential data headed for that provider class.
type TargetRule struct {
	ConfidentialData ActionRule `yaml:"confidential_data"`
}

// SemanticRule maps semantic risk levels to actions for one question
// (precedence level 7). Risk classes come from the question schema.
type SemanticRule struct {
	High   ActionRule `yaml:"high,omitempty"`
	Medium ActionRule `yaml:"medium,omitempty"`
	Low    ActionRule `yaml:"low,omitempty"`
}

// ForRisk returns the configured action for a risk class ("high", "medium",
// "low"), case-insensitive.
func (s SemanticRule) ForRisk(risk string) (ActionRule, bool) {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "high":
		return s.High, s.High.Action != ""
	case "medium":
		return s.Medium, s.Medium.Action != ""
	case "low":
		return s.Low, s.Low.Action != ""
	}
	return ActionRule{}, false
}

const lowRiskDeterministicOnly = "deterministic_only"

// FallbackRule controls behavior when Laya is unavailable (architecture §16).
type FallbackRule struct {
	HighRisk ActionRule `yaml:"high_risk"`
	LowRisk  string     `yaml:"low_risk"` // an action, or "deterministic_only"
}

// Fallback is the failure-behavior section; behavior wiring lands with the
// semantic planner (ticket 09).
type Fallback struct {
	LayaUnavailable FallbackRule `yaml:"laya_unavailable"`
}

// ToolRules governs tool definitions the policy may strip on RESTRICT_TOOLS.
type ToolRules struct {
	Restricted []string `yaml:"restricted"`
}

// ProviderOverride refines category and subtype actions at a provider
// boundary. It is intentionally separate from transport/provider credentials.
type ProviderOverride struct {
	Categories map[string]ActionRule `yaml:"categories,omitempty"`
	Subtypes   map[string]ActionRule `yaml:"subtypes,omitempty"`
}

// ConfidenceEscalation turns detector confidence into a declarative action.
// Subtype and provider are optional matchers.
type ConfidenceEscalation struct {
	ID            string     `yaml:"id"`
	Category      string     `yaml:"category"`
	Subtype       string     `yaml:"subtype,omitempty"`
	Provider      string     `yaml:"provider,omitempty"`
	MinConfidence float64    `yaml:"min_confidence"`
	Action        ActionRule `yaml:"action"`
}

// FindingCountEscalation turns a category/subtype count into an action.
type FindingCountEscalation struct {
	ID          string     `yaml:"id"`
	Category    string     `yaml:"category"`
	Subtype     string     `yaml:"subtype,omitempty"`
	Provider    string     `yaml:"provider,omitempty"`
	MinCount    int        `yaml:"min_count"`
	Action      ActionRule `yaml:"action"`
	displayRule string
}

// Policy is the versioned policy document (FR-012).
type Policy struct {
	ID            string     `yaml:"id"`
	Version       int        `yaml:"version"`
	Owner         string     `yaml:"owner"`
	EffectiveDate string     `yaml:"effective_date"`
	Default       ActionRule `yaml:"default"`
	Deny          []DenyRule `yaml:"deny,omitempty"`

	Tenants      map[string]ActionRule   `yaml:"tenants,omitempty"`
	Applications map[string]ActionRule   `yaml:"applications,omitempty"`
	Roles        map[string]ActionRule   `yaml:"roles,omitempty"`
	Targets      map[string]TargetRule   `yaml:"targets,omitempty"`
	Secrets      map[string]ActionRule   `yaml:"secrets,omitempty"`
	PII          map[string]PIIRule      `yaml:"pii,omitempty"`
	Semantic     map[string]SemanticRule `yaml:"semantic,omitempty"`
	Fallback     *Fallback               `yaml:"fallback,omitempty"`
	Tools        *ToolRules              `yaml:"tools,omitempty"`

	// Declarative effective-policy contract. The legacy sections above remain
	// accepted and are normalized into these maps at load time.
	CategoryActions        map[string]ActionRule            `yaml:"category_actions,omitempty"`
	SubtypeActions         map[string]map[string]ActionRule `yaml:"subtype_actions,omitempty"`
	ProviderOverrides      map[string]ProviderOverride      `yaml:"provider_overrides,omitempty"`
	ConfidenceEscalation   []ConfidenceEscalation           `yaml:"confidence_escalation,omitempty"`
	FindingCountEscalation []FindingCountEscalation         `yaml:"finding_count_escalation,omitempty"`
	SafeDefault            ActionRule                       `yaml:"safe_default,omitempty"`
}

// RestrictedTools lists tool names RESTRICT_TOOLS may strip from requests.
func (p *Policy) RestrictedTools() []string {
	if p.Tools == nil {
		return nil
	}
	return p.Tools.Restricted
}

// RuleSummary is a content-free description suitable for operator tooling.
type RuleSummary struct {
	ID        string      `json:"id"`
	Stage     string      `json:"stage"`
	Category  string      `json:"category,omitempty"`
	Subtype   string      `json:"subtype,omitempty"`
	Provider  string      `json:"provider,omitempty"`
	Action    core.Action `json:"action"`
	Threshold *float64    `json:"threshold,omitempty"`
	MinCount  *int        `json:"min_count,omitempty"`
}

// Summary is a deterministic, sanitized policy projection. It contains rule
// identifiers and actions only, never YAML credentials or content values.
func (p *Policy) Summary() []RuleSummary {
	var out []RuleSummary
	for category, rule := range p.CategoryActions {
		out = append(out, RuleSummary{ID: "category_actions." + category, Stage: "category", Category: category, Action: rule.Action})
	}
	for category, subtypes := range p.SubtypeActions {
		for subtype, rule := range subtypes {
			out = append(out, RuleSummary{ID: "subtype_actions." + category + "." + subtype, Stage: "subtype", Category: category, Subtype: subtype, Action: rule.Action})
		}
	}
	for provider, override := range p.ProviderOverrides {
		for category, rule := range override.Categories {
			out = append(out, RuleSummary{ID: "providers." + provider + ".categories." + category, Stage: "provider_boundary", Category: category, Provider: provider, Action: rule.Action})
		}
		for subtype, rule := range override.Subtypes {
			out = append(out, RuleSummary{ID: "providers." + provider + ".subtypes." + subtype, Stage: "provider_subtype", Subtype: subtype, Provider: provider, Action: rule.Action})
		}
	}
	for _, rule := range p.ConfidenceEscalation {
		threshold := rule.MinConfidence
		out = append(out, RuleSummary{ID: "confidence." + rule.ID, Stage: "confidence_escalation", Category: rule.Category, Subtype: rule.Subtype, Provider: rule.Provider, Action: rule.Action.Action, Threshold: &threshold})
	}
	for _, rule := range p.FindingCountEscalation {
		count := rule.MinCount
		id := "count." + rule.ID
		if rule.displayRule != "" {
			id = rule.displayRule
		}
		out = append(out, RuleSummary{ID: id, Stage: "finding_count_escalation", Category: rule.Category, Subtype: rule.Subtype, Provider: rule.Provider, Action: rule.Action.Action, MinCount: &count})
	}
	out = append(out, RuleSummary{ID: "safe_default", Stage: "safe_default", Action: p.SafeDefault.Action}, RuleSummary{ID: "default", Stage: "default", Action: p.Default.Action})
	slices.SortFunc(out, func(a, b RuleSummary) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Load parses and validates a policy document. Unknown fields and invalid
// values are errors so that policy corruption fails startup/readiness (T-010).
func Load(data []byte) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy parse error: %w", err)
	}
	p.normalizeCompatibility()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadFile reads and validates a policy file from disk.
func LoadFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy load: %w", err)
	}
	return Load(data)
}

// Validate enforces required fields and known actions everywhere.
func (p *Policy) Validate() error {
	if p.ID == "" {
		return errors.New("policy: id is required")
	}
	if p.Version <= 0 {
		return errors.New("policy: version must be a positive integer")
	}
	if p.Default.Action == "" {
		return errors.New("policy: default.action is required")
	}
	if p.SafeDefault.Action == "" {
		return errors.New("policy: safe_default.action is required")
	}
	for category, rule := range p.CategoryActions {
		if strings.TrimSpace(category) == "" || rule.Action == "" {
			return fmt.Errorf("policy: category_actions.%s.action is required", category)
		}
	}
	for category, subtypes := range p.SubtypeActions {
		if strings.TrimSpace(category) == "" {
			return errors.New("policy: subtype_actions has an empty category")
		}
		for subtype, rule := range subtypes {
			if strings.TrimSpace(subtype) == "" || rule.Action == "" {
				return fmt.Errorf("policy: subtype_actions.%s.%s.action is required", category, subtype)
			}
		}
	}
	for provider, override := range p.ProviderOverrides {
		if strings.TrimSpace(provider) == "" {
			return errors.New("policy: provider_overrides has an empty provider")
		}
		for category, rule := range override.Categories {
			if strings.TrimSpace(category) == "" || rule.Action == "" {
				return fmt.Errorf("policy: provider_overrides.%s.categories.%s.action is required", provider, category)
			}
		}
		for subtype, rule := range override.Subtypes {
			if strings.TrimSpace(subtype) == "" || rule.Action == "" {
				return fmt.Errorf("policy: provider_overrides.%s.subtypes.%s.action is required", provider, subtype)
			}
		}
	}
	seenIDs := map[string]bool{}
	for i, rule := range p.ConfidenceEscalation {
		if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.Category) == "" {
			return fmt.Errorf("policy: confidence_escalation[%d] requires id and category", i)
		}
		if seenIDs[rule.ID] {
			return fmt.Errorf("policy: duplicate escalation id %q", rule.ID)
		}
		seenIDs[rule.ID] = true
		if !isValidFindingCategory(rule.Category) {
			return fmt.Errorf("policy: confidence_escalation[%d].category %q is unknown", i, rule.Category)
		}
		if math.IsNaN(rule.MinConfidence) || math.IsInf(rule.MinConfidence, 0) || rule.MinConfidence < 0 || rule.MinConfidence > 1 {
			return fmt.Errorf("policy: confidence_escalation[%d].min_confidence must be within [0,1]", i)
		}
		if rule.Action.Action == "" {
			return fmt.Errorf("policy: confidence_escalation[%d].action is required", i)
		}
	}
	for i, rule := range p.FindingCountEscalation {
		if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.Category) == "" {
			return fmt.Errorf("policy: finding_count_escalation[%d] requires id and category", i)
		}
		if seenIDs[rule.ID] {
			return fmt.Errorf("policy: duplicate escalation id %q", rule.ID)
		}
		seenIDs[rule.ID] = true
		if !isValidFindingCategory(rule.Category) {
			return fmt.Errorf("policy: finding_count_escalation[%d].category %q is unknown", i, rule.Category)
		}
		if rule.MinCount <= 0 {
			return fmt.Errorf("policy: finding_count_escalation[%d].min_count must be positive", i)
		}
		if rule.Action.Action == "" {
			return fmt.Errorf("policy: finding_count_escalation[%d].action is required", i)
		}
	}
	for i, rule := range p.Deny {
		if rule.Application == "" && rule.Tenant == "" && rule.UserSubject == "" && rule.Role == "" {
			return fmt.Errorf("policy: deny[%d] needs at least one matcher", i)
		}
		if rule.Action.Action == "" {
			return fmt.Errorf("policy: deny[%d].action is required", i)
		}
	}
	for name, rule := range p.PII {
		if len(rule.Providers) == 0 {
			return fmt.Errorf("policy: pii.%s needs at least one provider rule", name)
		}
	}
	for name, rule := range p.Semantic {
		if rule.High.Action == "" && rule.Medium.Action == "" && rule.Low.Action == "" {
			return fmt.Errorf("policy: semantic.%s has no configured risk levels", name)
		}
	}
	if p.Fallback != nil {
		f := p.Fallback.LayaUnavailable
		if f.HighRisk.Action == "" && f.LowRisk == "" {
			return errors.New("policy: fallback.laya_unavailable is empty")
		}
		if f.LowRisk != "" && f.LowRisk != lowRiskDeterministicOnly && !isValidAction(core.Action(strings.ToUpper(f.LowRisk))) {
			return fmt.Errorf("policy: fallback.laya_unavailable.low_risk %q is not an action or %q", f.LowRisk, lowRiskDeterministicOnly)
		}
	}
	return nil
}

// normalizeCompatibility makes the v7 policy vocabulary part of the same
// declarative contract consumed by the engine. No detector subtype is
// special-cased by the evaluator.
func (p *Policy) normalizeCompatibility() {
	for i := range p.ConfidenceEscalation {
		p.ConfidenceEscalation[i].Category = strings.ToUpper(strings.TrimSpace(p.ConfidenceEscalation[i].Category))
	}
	for i := range p.FindingCountEscalation {
		p.FindingCountEscalation[i].Category = strings.ToUpper(strings.TrimSpace(p.FindingCountEscalation[i].Category))
	}
	legacy := len(p.CategoryActions) == 0 && len(p.SubtypeActions) == 0 &&
		len(p.ProviderOverrides) == 0 && len(p.ConfidenceEscalation) == 0 &&
		len(p.FindingCountEscalation) == 0 && p.SafeDefault.Action == ""
	if p.CategoryActions == nil {
		p.CategoryActions = map[string]ActionRule{}
	}
	if p.SubtypeActions == nil {
		p.SubtypeActions = map[string]map[string]ActionRule{}
	}
	if p.ProviderOverrides == nil {
		p.ProviderOverrides = map[string]ProviderOverride{}
	}
	if legacy {
		p.CategoryActions[string(core.CategorySecret)] = ActionRule{Action: core.ActionRedact}
		if len(p.PII) > 0 {
			p.CategoryActions[string(core.CategoryPII)] = ActionRule{Action: core.ActionAllow}
		}
		p.SafeDefault = ActionRule{Action: core.ActionBlock}
		p.ConfidenceEscalation = append(p.ConfidenceEscalation, ConfidenceEscalation{
			ID: "compat-high-confidence-finding", Category: string(core.CategorySecret),
			MinConfidence: 0.9, Action: ActionRule{Action: core.ActionBlock},
		})
	}
	if p.SafeDefault.Action == "" {
		p.SafeDefault = ActionRule{Action: core.ActionBlock}
	}
	if _, exists := p.CategoryActions[string(core.CategorySecret)]; !exists && len(p.Secrets) > 0 {
		p.CategoryActions[string(core.CategorySecret)] = ActionRule{Action: core.ActionRedact}
	}
	if _, exists := p.CategoryActions[string(core.CategoryPII)]; !exists && len(p.PII) > 0 {
		p.CategoryActions[string(core.CategoryPII)] = ActionRule{Action: core.ActionAllow}
	}
	for subtype, rule := range p.Secrets {
		p.ensureSubtypeAction(string(core.CategorySecret), subtype, rule)
	}
	for subtype, rule := range p.PII {
		for provider, action := range rule.Providers {
			override := p.ProviderOverrides[provider]
			if override.Subtypes == nil {
				override.Subtypes = map[string]ActionRule{}
			}
			if _, exists := override.Subtypes[subtype]; !exists {
				override.Subtypes[subtype] = action
			}
			p.ProviderOverrides[provider] = override
		}
	}
	for provider, target := range p.Targets {
		override := p.ProviderOverrides[provider]
		if override.Categories == nil {
			override.Categories = map[string]ActionRule{}
		}
		if _, exists := override.Categories[string(core.CategoryPII)]; !exists && target.ConfidentialData.Action != "" {
			override.Categories[string(core.CategoryPII)] = target.ConfidentialData
		}
		p.ProviderOverrides[provider] = override
	}
	if multiple, ok := p.PII["MULTIPLE_PII"]; ok {
		for provider, action := range multiple.Providers {
			p.FindingCountEscalation = append(p.FindingCountEscalation, FindingCountEscalation{
				ID: "compat-multiple-pii-" + provider, Category: string(core.CategoryPII),
				Provider: provider, MinCount: 3, Action: action,
				displayRule: "pii.MULTIPLE_PII." + provider,
			})
		}
	}
}

func (p *Policy) ensureSubtypeAction(category, subtype string, rule ActionRule) {
	if p.SubtypeActions[category] == nil {
		p.SubtypeActions[category] = map[string]ActionRule{}
	}
	if _, exists := p.SubtypeActions[category][subtype]; !exists {
		p.SubtypeActions[category][subtype] = rule
	}
}

func isValidAction(a core.Action) bool {
	switch a {
	case core.ActionAllow, core.ActionBlock, core.ActionRedact, core.ActionTokenize,
		core.ActionReview, core.ActionRestrictTools, core.ActionForceLocalModel:
		return true
	}
	return false
}

func isValidFindingCategory(category string) bool {
	switch core.FindingCategory(strings.ToUpper(strings.TrimSpace(category))) {
	case core.CategoryPII, core.CategorySecret, core.CategoryPromptSecurity,
		core.CategoryToolSecurity, core.CategoryConfidentialData, core.CategoryPolicy:
		return true
	default:
		return false
	}
}
