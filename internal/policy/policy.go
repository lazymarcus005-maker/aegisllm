// Package policy implements policy-as-code: versioned YAML documents, strict
// validation, and a deterministic engine whose output depends only on its
// inputs (FR-012, SEC-005).
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
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

// UnmarshalYAML decodes and normalizes the action value.
func (r *ActionRule) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		Action string `yaml:"action"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	a := core.Action(strings.ToUpper(strings.TrimSpace(raw.Action)))
	if !isValidAction(a) {
		return fmt.Errorf("action %q is not a known action", raw.Action)
	}
	r.Action = a
	return nil
}

// Policy is the versioned policy document (FR-012). Fields here are the
// ticket-02 schema (default + secrets rules); later tickets extend it.
type Policy struct {
	ID            string                `yaml:"id"`
	Version       int                   `yaml:"version"`
	Owner         string                `yaml:"owner"`
	EffectiveDate string                `yaml:"effective_date"`
	Default       ActionRule            `yaml:"default"`
	Secrets       map[string]ActionRule `yaml:"secrets"`
}

// Load parses and validates a policy document. Unknown fields and invalid
// values are errors so that policy corruption fails startup/readiness.
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

// Validate enforces required fields and known actions.
func (p *Policy) Validate() error {
	if p.ID == "" {
		return errors.New("policy: id is required")
	}
	if p.Version <= 0 {
		return errors.New("policy: version must be a positive integer")
	}
	if !isValidAction(p.Default.Action) {
		return fmt.Errorf("policy: default.action %q is not a known action", p.Default.Action)
	}
	for subtype, rule := range p.Secrets {
		if !isValidAction(rule.Action) {
			return fmt.Errorf("policy: secrets.%s.action %q is not a known action", subtype, rule.Action)
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
