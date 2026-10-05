// Package policy implements policy-as-code: versioned YAML documents, strict
// validation, and a deterministic engine whose output depends only on its
// inputs (FR-012, SEC-005).
package policy

import (
	"bytes"
	"errors"
	"fmt"
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
		var raw struct {
			Action string `yaml:"action"`
		}
		if err := value.Decode(&raw); err != nil {
			return err
		}
		a, err := normalize(raw.Action)
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
}

// RestrictedTools lists tool names RESTRICT_TOOLS may strip from requests.
func (p *Policy) RestrictedTools() []string {
	if p.Tools == nil {
		return nil
	}
	return p.Tools.Restricted
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

func isValidAction(a core.Action) bool {
	switch a {
	case core.ActionAllow, core.ActionBlock, core.ActionRedact, core.ActionTokenize,
		core.ActionReview, core.ActionRestrictTools, core.ActionForceLocalModel:
		return true
	}
	return false
}
