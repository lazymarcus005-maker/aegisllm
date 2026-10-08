// Package decision abstracts the semantic decision engine (Laya) behind the
// DecisionProvider interface (architecture §7.5). Laya's raw response
// structures are normalized at the adapter boundary and never leak further
// (T-014). Provider output is evidence only — it can never execute an action
// (FR-010, INV-002).
package decision

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aegisllm/gateway/internal/securetransport"
	"gopkg.in/yaml.v3"
)

// Question is one versioned semantic question.
type Question struct {
	ID         string   `yaml:"id"`
	Version    int      `yaml:"version"`
	Type       string   `yaml:"type"`
	Question   string   `yaml:"question"`
	Directions []string `yaml:"directions"`
	Risk       string   `yaml:"risk"`
}

// QuestionSchema is the versioned question schema document (FR-009).
type QuestionSchema struct {
	Schema    string     `yaml:"schema"`
	Version   int        `yaml:"version"`
	Questions []Question `yaml:"questions"`
}

var validRisks = map[string]bool{"high": true, "medium": true, "low": true}
var validDirections = map[string]bool{
	string(directionRequest): true, string(directionToolCall): true,
	string(directionResponse): true, string(directionToolResult): true,
}

// Direction labels used inside the question schema (lowercase YAML form).
const (
	directionRequest    = "request"
	directionToolCall   = "tool_call"
	directionResponse   = "response"
	directionToolResult = "tool_result"
)

// LoadQuestions parses and validates a question schema file.
func LoadQuestions(data []byte) (*QuestionSchema, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var qs QuestionSchema
	if err := dec.Decode(&qs); err != nil {
		return nil, fmt.Errorf("question schema parse error: %w", err)
	}
	if err := qs.Validate(); err != nil {
		return nil, err
	}
	return &qs, nil
}

// LoadQuestionsFile reads and validates a question schema from disk.
func LoadQuestionsFile(path string) (*QuestionSchema, error) {
	data, err := securetransport.ReadTrustedFile(path)
	if err != nil {
		return nil, fmt.Errorf("question schema load: %w", err)
	}
	return LoadQuestions(data)
}

// Validate enforces complete, well-formed questions.
func (qs *QuestionSchema) Validate() error {
	if qs.Schema == "" {
		return errors.New("question schema: schema name is required")
	}
	if qs.Version <= 0 {
		return errors.New("question schema: version must be positive")
	}
	seen := map[string]bool{}
	for i, q := range qs.Questions {
		if q.ID == "" {
			return fmt.Errorf("question schema: questions[%d].id is required", i)
		}
		if seen[q.ID] {
			return fmt.Errorf("question schema: duplicate question id %q", q.ID)
		}
		seen[q.ID] = true
		if q.Version <= 0 {
			return fmt.Errorf("question schema: %s.version must be positive", q.ID)
		}
		if q.Type == "" {
			return fmt.Errorf("question schema: %s.type is required", q.ID)
		}
		if q.Question == "" {
			return fmt.Errorf("question schema: %s.question is required", q.ID)
		}
		if len(q.Directions) == 0 {
			return fmt.Errorf("question schema: %s.directions is required", q.ID)
		}
		for _, d := range q.Directions {
			if !validDirections[strings.TrimSpace(d)] {
				return fmt.Errorf("question schema: %s has unknown direction %q", q.ID, d)
			}
		}
		if !validRisks[strings.TrimSpace(q.Risk)] {
			return fmt.Errorf("question schema: %s has unknown risk %q (want high|medium|low)", q.ID, q.Risk)
		}
	}
	return nil
}

// ForDirection returns the question ids allowed on one direction.
func (qs *QuestionSchema) ForDirection(direction string) []string {
	var out []string
	for _, q := range qs.Questions {
		if slices.Contains(q.Directions, strings.TrimSpace(direction)) {
			out = append(out, q.ID)
		}
	}
	return out
}

// RiskOf returns the risk class of a question id.
func (qs *QuestionSchema) RiskOf(id string) string {
	for _, q := range qs.Questions {
		if q.ID == id {
			return strings.TrimSpace(q.Risk)
		}
	}
	return ""
}

// DecisionRequest is the normalized semantic evaluation input (spec §4).
type DecisionRequest struct {
	RequestID    string
	Direction    string // lowercase direction label
	Role         string
	Content      string
	Application  string
	ModelID      string
	ModelVersion string
}

// Decision is one normalized answer.
type Decision struct {
	Value      bool
	Confidence float64 // Laya answer_confidence; not calibrated by default
}

// DecisionEvidence is normalized provider output (never Laya's raw shape).
type DecisionEvidence struct {
	Provider      string
	Checkpoint    string
	SchemaVersion string
	Route         string
	Decisions     map[string]Decision
	ModelID       string
	ModelVersion  string
	ModelDigest   string
}

// DecisionProvider asks semantic questions and returns evidence.
type DecisionProvider interface {
	Name() string
	Evaluate(ctx context.Context, req DecisionRequest, questionIDs []string) (DecisionEvidence, error)
}
